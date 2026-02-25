import {
  ActionRowBuilder,
  ButtonBuilder,
  ButtonInteraction,
  ButtonStyle,
  ChannelType,
  ChatInputCommandInteraction,
  Client,
  EmbedBuilder,
  Events,
  GatewayIntentBits,
  Interaction,
  MessageFlags,
  REST,
  Routes,
  SlashCommandBuilder,
  type GuildBasedChannel,
  PermissionFlagsBits,
} from "discord.js";
import * as os from "node:os";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

import { BackendClient } from "./api_client";
import { isAuthorized } from "./authz";
import { ChannelPolicyStore } from "./channel_policy";
import { loadConfig } from "./config";
import { handleButton } from "./interactions/buttons";
import { handleModal } from "./interactions/modals";
import { handlePanelCommand } from "./interactions/panel";
import { handleSelect } from "./interactions/selects";

const cfg = loadConfig();
const backend = new BackendClient(cfg.backendBaseUrl, cfg.sharedSecret);
const channelPolicyStore = new ChannelPolicyStore(cfg.channelPolicyFile);
const execFileAsync = promisify(execFile);

const SERVICE_NAMES = [
  "xray",
  "nginx",
  "wireproxy",
  "xray-expired",
  "xray-quota",
  "xray-limit-ip",
  "xray-speed",
] as const;
const NOTIF_BUTTON_ON = "notifsvc:on";
const NOTIF_BUTTON_OFF = "notifsvc:off";
const NOTIF_BUTTON_TEST = "notifsvc:test";
const NOTIF_MINUTES_MIN = 1;
const NOTIF_MINUTES_MAX = 1_440;
let notifSchedulerBusy = false;
let notifLastWarnAtMs = 0;

const client = new Client({ intents: [GatewayIntentBits.Guilds] });

async function registerSlashCommands(): Promise<void> {
  const commands = [new SlashCommandBuilder().setName("panel").setDescription("Buka panel operasional Xray").toJSON()];
  const rest = new REST({ version: "10" }).setToken(cfg.token);
  await rest.put(Routes.applicationGuildCommands(cfg.applicationId, cfg.guildId), { body: commands });
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function getDiscordErrorCode(err: unknown): number | null {
  if (!err || typeof err !== "object") return null;
  const maybe = (err as { code?: unknown }).code;
  return typeof maybe === "number" ? maybe : null;
}

function isIgnorableInteractionError(err: unknown): boolean {
  const code = getDiscordErrorCode(err);
  return code === 10062 || code === 40060;
}

function formatError(err: unknown): string {
  if (err instanceof Error) {
    return `${err.name}: ${err.message}`;
  }
  return String(err);
}

async function safeReplyEphemeral(interaction: Interaction, content: string): Promise<void> {
  if (!interaction.isRepliable()) return;
  try {
    if (interaction.replied || interaction.deferred) {
      await interaction.followUp({ content, flags: MessageFlags.Ephemeral });
    } else {
      await interaction.reply({ content, flags: MessageFlags.Ephemeral });
    }
  } catch (err) {
    if (isIgnorableInteractionError(err)) {
      console.warn(`[gateway] skip interaction reply (ack/expired): ${formatError(err)}`);
      return;
    }
    throw err;
  }
}

async function registerSlashCommandsWithRetry(maxAttempts = 5): Promise<boolean> {
  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    try {
      await registerSlashCommands();
      if (attempt > 1) {
        console.log(`[gateway] slash command registration succeeded on retry ${attempt}/${maxAttempts}.`);
      }
      return true;
    } catch (err) {
      const errText = err instanceof Error ? `${err.name}: ${err.message}` : String(err);
      console.error(`[gateway] failed to register slash commands (${attempt}/${maxAttempts}): ${errText}`);
      if (attempt >= maxAttempts) {
        return false;
      }
      await sleep(Math.min(2000 * attempt, 10000));
    }
  }
  return false;
}

async function assertAuthorized(interaction: ChatInputCommandInteraction): Promise<boolean> {
  const member = interaction.inGuild() ? interaction.member : null;
  if (!interaction.inGuild() || !isAuthorized(member as any, interaction.user.id, cfg)) {
    await interaction.reply({ content: "Akses ditolak. Hubungi admin.", flags: MessageFlags.Ephemeral });
    return false;
  }
  return true;
}

type PurgeCapableChannel = {
  id: string;
  messages: { fetch: (options: Record<string, unknown>) => Promise<Map<string, { id: string; author?: { id?: string; bot?: boolean }; createdTimestamp?: number }>> };
  bulkDelete: (messages: string[] | number, filterOld?: boolean) => Promise<{ size?: number }>;
};

function isPurgeCapableChannel(channel: unknown): channel is PurgeCapableChannel {
  if (!channel || typeof channel !== "object") return false;
  const maybe = channel as { messages?: unknown; bulkDelete?: unknown; id?: unknown };
  return typeof maybe.id === "string" && typeof maybe.bulkDelete === "function" && typeof maybe.messages === "object";
}

async function buildStatusEmbed(): Promise<EmbedBuilder> {
  const wsPingRaw = client.ws.ping;
  const wsPingText = Number.isFinite(wsPingRaw) && wsPingRaw >= 0 ? `${Math.round(wsPingRaw)} ms` : "n/a";
  const hostUptime = formatDuration(os.uptime());
  const load = os.loadavg().map((n) => n.toFixed(2)).join(" ");
  const totalMem = os.totalmem();
  const freeMem = os.freemem();
  const usedMem = Math.max(0, totalMem - freeMem);

  let healthPass = false;
  let secretPass = false;

  const healthStarted = Date.now();
  let healthLine = "Backend /health: FAIL";
  try {
    const health = await backend.getHealth();
    const elapsed = Date.now() - healthStarted;
    const status = String(health.status ?? "-");
    healthPass = status === "ok";
    healthLine = `Backend /health: ${healthPass ? "PASS" : "FAIL"} (status=${status}, ${elapsed} ms)`;
  } catch (err) {
    const elapsed = Date.now() - healthStarted;
    healthLine = `Backend /health: FAIL (${formatError(err)}, ${elapsed} ms)`;
  }

  const secretStarted = Date.now();
  let secretLine = "Shared secret (/api/main-menu): FAIL";
  try {
    const mainMenu = await backend.getMainMenu();
    const elapsed = Date.now() - secretStarted;
    const menuCount = typeof mainMenu.menu_count === "number" ? String(mainMenu.menu_count) : "-";
    secretPass = true;
    secretLine = `Shared secret (/api/main-menu): PASS (menu_count=${menuCount}, ${elapsed} ms)`;
  } catch (err) {
    const elapsed = Date.now() - secretStarted;
    secretLine = `Shared secret (/api/main-menu): FAIL (${formatError(err)}, ${elapsed} ms)`;
  }

  const overall = healthPass && secretPass ? "STATUS: PASS" : "STATUS: FAIL";
  return new EmbedBuilder()
    .setTitle("System Status")
    .setDescription(overall)
    .setColor(healthPass && secretPass ? 0x2ecc71 : 0xe74c3c)
    .addFields(
      {
        name: "Connectivity",
        value: `Discord WS: ${wsPingText}`,
        inline: false,
      },
      {
        name: "Host Runtime",
        value: `Uptime: ${hostUptime}\nLoad avg (1/5/15): ${load}\nMemory: ${formatGiB(usedMem)} / ${formatGiB(totalMem)}`,
        inline: false,
      },
      {
        name: "Backend",
        value: `${healthLine}\n${secretLine}`,
        inline: false,
      },
    )
    .setTimestamp();
}

async function handleStatusCommand(interaction: ChatInputCommandInteraction): Promise<void> {
  const statusEmbed = await buildStatusEmbed();
  await interaction.reply({
    embeds: [statusEmbed],
    flags: MessageFlags.Ephemeral,
  });
}

async function handlePurgeBotCommand(interaction: ChatInputCommandInteraction): Promise<void> {
  const modeRaw = interaction.options.getString("mode", true);
  const mode = modeRaw === "all_messages" ? "all_messages" : "bot_only";
  const amount = interaction.options.getInteger("jumlah", false) ?? 100;
  const selectedChannel = interaction.options.getChannel("channel", false);
  const target = selectedChannel ?? interaction.channel;

  if (!target || !isPurgeCapableChannel(target)) {
    await interaction.reply({
      content: "Channel target tidak mendukung bulk delete.",
      flags: MessageFlags.Ephemeral,
    });
    return;
  }

  await interaction.deferReply({ flags: MessageFlags.Ephemeral });

  const maxDelete = Math.min(Math.max(amount, 1), 1000);
  const fourteenDaysMs = 14 * 24 * 60 * 60 * 1000;
  const nowMs = Date.now();

  let deleted = 0;
  let scanned = 0;
  let beforeId: string | undefined;
  let loops = 0;

  while (deleted < maxDelete && loops < 40) {
    loops += 1;
    let batch: Map<string, { id: string; author?: { id?: string; bot?: boolean }; createdTimestamp?: number }>;
    try {
      batch = await target.messages.fetch({
        limit: 100,
        ...(beforeId ? { before: beforeId } : {}),
      });
    } catch (err) {
      await interaction.editReply(`Gagal membaca pesan channel: ${formatError(err)}`);
      return;
    }

    if (!batch || batch.size === 0) break;
    scanned += batch.size;

    const candidateIds: string[] = [];
    for (const msg of batch.values()) {
      if (!msg || typeof msg.id !== "string") continue;
      if (typeof msg.createdTimestamp !== "number" || nowMs - msg.createdTimestamp >= fourteenDaysMs) continue;
      const isBotMessage = msg.author?.bot === true;
      if (mode === "bot_only" && !isBotMessage) continue;
      candidateIds.push(msg.id);
      if (deleted + candidateIds.length >= maxDelete) break;
    }

    if (candidateIds.length > 0) {
      try {
        const res = await target.bulkDelete(candidateIds, true);
        const count = typeof res?.size === "number" ? res.size : candidateIds.length;
        deleted += count;
      } catch (err) {
        const code = getDiscordErrorCode(err);
        if (code === 50013) {
          await interaction.editReply("Gagal bulk delete: bot tidak punya izin `Manage Messages` di channel target.");
          return;
        }
        await interaction.editReply(`Gagal bulk delete: ${formatError(err)}`);
        return;
      }
    }

    const keys = Array.from(batch.keys());
    beforeId = keys[keys.length - 1];
    if (!beforeId) break;
  }

  const modeText = mode === "bot_only" ? "pesan bot saja" : "semua pesan (user+bot)";
  await interaction.editReply(
    `Purge selesai.\n- Mode: ${modeText}\n- Channel: <#${target.id}>\n- Dihapus: ${deleted}\n- Scan: ${scanned} pesan`
  );
}

type ServiceState = "active" | "inactive" | "failed" | "activating" | "deactivating" | "unknown";
type ServiceStatus = { service: string; state: ServiceState; raw: string };

type SendCapableChannel = {
  id: string;
  send: (options: Record<string, unknown>) => Promise<unknown>;
};

function normalizeServiceState(raw: string): ServiceState {
  const value = raw.trim().toLowerCase();
  if (value === "active") return "active";
  if (value === "inactive") return "inactive";
  if (value === "failed") return "failed";
  if (value === "activating") return "activating";
  if (value === "deactivating") return "deactivating";
  return "unknown";
}

function toStateLabel(state: ServiceState, raw: string): string {
  if (state === "unknown" && raw.trim()) {
    return `UNKNOWN (${raw.trim()})`;
  }
  return state.toUpperCase();
}

function isSendCapableChannel(channel: unknown): channel is SendCapableChannel {
  if (!channel || typeof channel !== "object") return false;
  const maybe = channel as { id?: unknown; send?: unknown };
  return typeof maybe.id === "string" && typeof maybe.send === "function";
}

function buildNotifButtons(enabled: boolean): ActionRowBuilder<ButtonBuilder> {
  return new ActionRowBuilder<ButtonBuilder>().addComponents(
    new ButtonBuilder()
      .setCustomId(NOTIF_BUTTON_ON)
      .setLabel("ON")
      .setStyle(enabled ? ButtonStyle.Success : ButtonStyle.Secondary)
      .setDisabled(enabled),
    new ButtonBuilder()
      .setCustomId(NOTIF_BUTTON_OFF)
      .setLabel("OFF")
      .setStyle(!enabled ? ButtonStyle.Danger : ButtonStyle.Secondary)
      .setDisabled(!enabled),
    new ButtonBuilder().setCustomId(NOTIF_BUTTON_TEST).setLabel("Test Notifikasi").setStyle(ButtonStyle.Primary)
  );
}

function buildNotifControlEmbed(title = "Set Notif Service"): EmbedBuilder {
  const channelId = channelPolicyStore.getControlChannelId();
  const enabled = channelPolicyStore.getAutoStatusEnabled();
  const interval = channelPolicyStore.getAutoStatusIntervalMinutes();
  const lastSent = channelPolicyStore.getLastAutoStatusAt() ?? "-";

  return new EmbedBuilder()
    .setTitle(title)
    .setDescription("Konfigurasi notifikasi service untuk channel Discord.")
    .setColor(enabled ? 0x2ecc71 : 0xf39c12)
    .addFields(
      { name: "Channel", value: channelId ? `<#${channelId}>` : "Belum diset", inline: true },
      { name: "Interval", value: `${interval} menit`, inline: true },
      { name: "Status", value: enabled ? "ON" : "OFF", inline: true },
      { name: "Last Sent", value: lastSent, inline: false },
      { name: "Services", value: SERVICE_NAMES.join(", "), inline: false }
    )
    .setTimestamp();
}

function buildNotifControlMessage(title?: string) {
  return {
    embeds: [buildNotifControlEmbed(title)],
    components: [buildNotifButtons(channelPolicyStore.getAutoStatusEnabled())],
  };
}

function describeMissingSendPermissions(channel: GuildBasedChannel, interaction: ChatInputCommandInteraction): string | null {
  if (!("permissionsFor" in channel) || typeof channel.permissionsFor !== "function") return null;
  const me = interaction.guild?.members.me;
  if (!me) return null;
  const perms = channel.permissionsFor(me);
  if (!perms) return "Gagal membaca izin bot untuk channel tersebut.";
  const required = [
    { flag: PermissionFlagsBits.ViewChannel, label: "View Channel" },
    { flag: PermissionFlagsBits.SendMessages, label: "Send Messages" },
    { flag: PermissionFlagsBits.EmbedLinks, label: "Embed Links" },
  ];
  const missing = required.filter((item) => !perms.has(item.flag)).map((item) => item.label);
  if (missing.length === 0) return null;
  return `Bot belum punya izin di channel target: ${missing.join(", ")}`;
}

async function readServiceStatus(service: string): Promise<ServiceStatus> {
  try {
    const { stdout } = await execFileAsync("systemctl", ["is-active", service], { timeout: 12_000 });
    const raw = String(stdout ?? "")
      .trim()
      .split(/\s+/)[0] || "unknown";
    return { service, state: normalizeServiceState(raw), raw };
  } catch (err) {
    const maybe = err as { stdout?: unknown; stderr?: unknown };
    const stdout = String(maybe?.stdout ?? "").trim();
    const stderr = String(maybe?.stderr ?? "").trim();
    const raw = (stdout || stderr || "unknown").split(/\s+/)[0];
    return { service, state: normalizeServiceState(raw), raw };
  }
}

async function collectServiceStatuses(): Promise<ServiceStatus[]> {
  return Promise.all(SERVICE_NAMES.map((service) => readServiceStatus(service)));
}

function buildServiceStatusEmbed(statuses: ServiceStatus[], source: "auto" | "test"): EmbedBuilder {
  const healthyCount = statuses.filter((item) => item.state === "active").length;
  const unhealthyCount = statuses.length - healthyCount;
  const allHealthy = unhealthyCount === 0;
  const sourceText = source === "test" ? "manual test" : "scheduler";

  const embed = new EmbedBuilder()
    .setTitle("Service Status Notification")
    .setDescription(`Sumber: ${sourceText}\nHealthy: ${healthyCount}/${statuses.length}`)
    .setColor(allHealthy ? 0x2ecc71 : 0xe67e22)
    .setTimestamp();

  for (const item of statuses) {
    embed.addFields({
      name: item.service,
      value: toStateLabel(item.state, item.raw),
      inline: true,
    });
  }

  return embed;
}

async function sendServiceNotification(source: "auto" | "test"): Promise<{ ok: boolean; message: string }> {
  const channelId = channelPolicyStore.getControlChannelId();
  if (!channelId) {
    return { ok: false, message: "Channel notifikasi belum diset." };
  }

  let channel: Awaited<ReturnType<typeof client.channels.fetch>>;
  try {
    channel = await client.channels.fetch(channelId);
  } catch (err) {
    return { ok: false, message: `Gagal mengakses channel <#${channelId}>: ${formatError(err)}` };
  }

  if (!isSendCapableChannel(channel)) {
    return { ok: false, message: `Channel <#${channelId}> tidak bisa dipakai untuk kirim notifikasi.` };
  }

  let statuses: ServiceStatus[];
  try {
    statuses = await collectServiceStatuses();
  } catch (err) {
    return { ok: false, message: `Gagal membaca status service: ${formatError(err)}` };
  }

  try {
    await channel.send({ embeds: [buildServiceStatusEmbed(statuses, source)] });
    channelPolicyStore.markAutoStatusSent(new Date().toISOString());
    return { ok: true, message: `Notifikasi terkirim ke <#${channelId}>.` };
  } catch (err) {
    const code = getDiscordErrorCode(err);
    if (code === 50013) {
      return {
        ok: false,
        message: "Gagal kirim notifikasi: bot tidak punya izin `View Channel`, `Send Messages`, atau `Embed Links`.",
      };
    }
    return { ok: false, message: `Gagal kirim notifikasi: ${formatError(err)}` };
  }
}

async function handleSetNotifServiceCommand(interaction: ChatInputCommandInteraction): Promise<void> {
  const channel = interaction.options.getChannel("channel", true) as GuildBasedChannel;
  const intervalMinutes = interaction.options.getInteger("durasi_menit", true);
  const permissionError = describeMissingSendPermissions(channel, interaction);
  if (permissionError) {
    await interaction.reply({ content: permissionError, flags: MessageFlags.Ephemeral });
    return;
  }

  channelPolicyStore.update({
    channelId: channel.id,
    intervalMinutes,
  });

  await interaction.reply({
    content: `Konfigurasi disimpan untuk <#${channel.id}> (${intervalMinutes} menit).`,
    ...buildNotifControlMessage(),
    flags: MessageFlags.Ephemeral,
  });
}

async function handleNotifServiceButton(interaction: ButtonInteraction): Promise<boolean> {
  const id = interaction.customId;
  if (!id.startsWith("notifsvc:")) return false;

  if (id === NOTIF_BUTTON_ON) {
    channelPolicyStore.update({ enabled: true });
    await interaction.update({
      content: "Notifikasi service diaktifkan.",
      ...buildNotifControlMessage("Set Notif Service"),
    });
    return true;
  }

  if (id === NOTIF_BUTTON_OFF) {
    channelPolicyStore.update({ enabled: false });
    await interaction.update({
      content: "Notifikasi service dimatikan.",
      ...buildNotifControlMessage("Set Notif Service"),
    });
    return true;
  }

  if (id === NOTIF_BUTTON_TEST) {
    await interaction.deferReply({ flags: MessageFlags.Ephemeral });
    const sent = await sendServiceNotification("test");
    await interaction.editReply(sent.message);
    return true;
  }

  return false;
}

async function runNotifSchedulerTick(): Promise<void> {
  if (notifSchedulerBusy) return;
  notifSchedulerBusy = true;
  try {
    if (!channelPolicyStore.getAutoStatusEnabled()) return;
    if (!channelPolicyStore.getControlChannelId()) return;

    const intervalMinutes = channelPolicyStore.getAutoStatusIntervalMinutes();
    const lastSentAtRaw = channelPolicyStore.getLastAutoStatusAt();
    if (lastSentAtRaw) {
      const lastSentMs = Date.parse(lastSentAtRaw);
      if (Number.isFinite(lastSentMs)) {
        const diff = Date.now() - lastSentMs;
        if (diff < intervalMinutes * 60 * 1_000) return;
      }
    }

    const sent = await sendServiceNotification("auto");
    if (!sent.ok) {
      const now = Date.now();
      if (now - notifLastWarnAtMs >= 10 * 60 * 1_000) {
        notifLastWarnAtMs = now;
        console.warn(`[gateway] auto notifier skipped: ${sent.message}`);
      }
    }
  } finally {
    notifSchedulerBusy = false;
  }
}

function startNotifScheduler(): void {
  setInterval(() => {
    void runNotifSchedulerTick();
  }, 60_000);
  void runNotifSchedulerTick();
}

function formatDuration(secondsRaw: number): string {
  const total = Math.max(0, Math.floor(secondsRaw));
  const days = Math.floor(total / 86_400);
  const hours = Math.floor((total % 86_400) / 3_600);
  const minutes = Math.floor((total % 3_600) / 60);
  return `${days}d ${hours}h ${minutes}m`;
}

function formatGiB(bytes: number): string {
  const gib = bytes / (1024 ** 3);
  return `${gib.toFixed(2)} GiB`;
}

client.once(Events.ClientReady, async (ready) => {
  console.log(`[gateway] logged in as ${ready.user.tag}`);
  const registered = await registerSlashCommandsWithRetry();
  if (registered) {
    console.log("[gateway] slash commands registered: /panel.");
    return;
  }
  console.error("[gateway] slash command registration failed after retries; bot continues running.");
});

client.on(Events.InteractionCreate, async (interaction) => {
  try {
    if (interaction.isChatInputCommand()) {
      if (!(await assertAuthorized(interaction))) return;
      if (interaction.commandName === "panel") {
        await handlePanelCommand(interaction);
        return;
      }
      await interaction.reply({ content: "Command tidak dikenali.", flags: MessageFlags.Ephemeral });
      return;
    }

    if (interaction.isButton()) {
      if (!interaction.inGuild() || !isAuthorized(interaction.member as any, interaction.user.id, cfg)) {
        await interaction.reply({ content: "Akses ditolak.", flags: MessageFlags.Ephemeral });
        return;
      }
      const notifHandled = await handleNotifServiceButton(interaction);
      if (notifHandled) return;
      const handled = await handleButton(interaction, backend);
      if (!handled && !interaction.replied) {
        await interaction.reply({ content: "Aksi tidak dikenali.", flags: MessageFlags.Ephemeral });
      }
      return;
    }

    if (interaction.isModalSubmit()) {
      if (!interaction.inGuild() || !isAuthorized(interaction.member as any, interaction.user.id, cfg)) {
        await interaction.reply({ content: "Akses ditolak.", flags: MessageFlags.Ephemeral });
        return;
      }
      const handled = await handleModal(interaction, backend);
      if (!handled && !interaction.replied) {
        await interaction.reply({ content: "Form tidak dikenali.", flags: MessageFlags.Ephemeral });
      }
      return;
    }

    if (interaction.isStringSelectMenu()) {
      if (!interaction.inGuild() || !isAuthorized(interaction.member as any, interaction.user.id, cfg)) {
        await interaction.reply({ content: "Akses ditolak.", flags: MessageFlags.Ephemeral });
        return;
      }
      const handled = await handleSelect(interaction, backend);
      if (!handled && !interaction.replied) {
        await interaction.reply({ content: "Opsi ini belum tersedia.", flags: MessageFlags.Ephemeral });
      }
    }
  } catch (err) {
    if (isIgnorableInteractionError(err)) {
      console.warn(`[gateway] interaction warning (ack/expired): ${formatError(err)}`);
      return;
    }
    const text = `Terjadi kesalahan: ${formatError(err)}`;
    await safeReplyEphemeral(interaction, text);
  }
});

client.login(cfg.token);
