import {
  ChatInputCommandInteraction,
  Client,
  Events,
  GatewayIntentBits,
  REST,
  Routes,
  SlashCommandBuilder,
} from "discord.js";

import { BackendClient } from "./api_client";
import { isAuthorized } from "./authz";
import { loadConfig } from "./config";
import { handleButton } from "./interactions/buttons";
import { handleModal } from "./interactions/modals";
import { handlePanelCommand } from "./interactions/panel";
import { handleSelect } from "./interactions/selects";

const cfg = loadConfig();
const backend = new BackendClient(cfg.backendBaseUrl, cfg.sharedSecret);

const client = new Client({ intents: [GatewayIntentBits.Guilds] });

async function registerSlashCommands(): Promise<void> {
  const commands = [new SlashCommandBuilder().setName("panel").setDescription("Buka panel bot Xray standalone").toJSON()];
  const rest = new REST({ version: "10" }).setToken(cfg.token);
  await rest.put(Routes.applicationGuildCommands(cfg.applicationId, cfg.guildId), { body: commands });
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function registerSlashCommandsWithRetry(maxAttempts = 5): Promise<boolean> {
  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    try {
      await registerSlashCommands();
      if (attempt > 1) {
        console.log(`[gateway] /panel registration succeeded on retry ${attempt}/${maxAttempts}.`);
      }
      return true;
    } catch (err) {
      const errText = err instanceof Error ? `${err.name}: ${err.message}` : String(err);
      console.error(`[gateway] failed to register /panel (${attempt}/${maxAttempts}): ${errText}`);
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
    await interaction.reply({ content: "Akses ditolak. Hubungi admin.", ephemeral: true });
    return false;
  }
  return true;
}

client.once(Events.ClientReady, async (ready) => {
  console.log(`[gateway] logged in as ${ready.user.tag}`);
  const registered = await registerSlashCommandsWithRetry();
  if (registered) {
    console.log("[gateway] slash command /panel registered.");
    return;
  }
  console.error("[gateway] slash command /panel registration failed after retries; bot continues running.");
});

client.on(Events.InteractionCreate, async (interaction) => {
  try {
    if (interaction.isChatInputCommand() && interaction.commandName === "panel") {
      if (!(await assertAuthorized(interaction))) return;
      await handlePanelCommand(interaction);
      return;
    }

    if (interaction.isButton()) {
      if (!interaction.inGuild() || !isAuthorized(interaction.member as any, interaction.user.id, cfg)) {
        await interaction.reply({ content: "Akses ditolak.", ephemeral: true });
        return;
      }
      const handled = await handleButton(interaction, backend);
      if (!handled && !interaction.replied) {
        await interaction.reply({ content: "Button tidak dikenali.", ephemeral: true });
      }
      return;
    }

    if (interaction.isModalSubmit()) {
      if (!interaction.inGuild() || !isAuthorized(interaction.member as any, interaction.user.id, cfg)) {
        await interaction.reply({ content: "Akses ditolak.", ephemeral: true });
        return;
      }
      const handled = await handleModal(interaction, backend);
      if (!handled && !interaction.replied) {
        await interaction.reply({ content: "Modal tidak dikenali.", ephemeral: true });
      }
      return;
    }

    if (interaction.isStringSelectMenu()) {
      if (!interaction.inGuild() || !isAuthorized(interaction.member as any, interaction.user.id, cfg)) {
        await interaction.reply({ content: "Akses ditolak.", ephemeral: true });
        return;
      }
      const handled = await handleSelect(interaction);
      if (!handled && !interaction.replied) {
        await interaction.reply({ content: "Select interaction belum diaktifkan untuk opsi ini.", ephemeral: true });
      }
    }
  } catch (err) {
    const text = `Terjadi error: ${String(err)}`;
    if (interaction.isRepliable()) {
      if (interaction.replied || interaction.deferred) {
        await interaction.followUp({ content: text, ephemeral: true });
      } else {
        await interaction.reply({ content: text, ephemeral: true });
      }
    }
  }
});

client.login(cfg.token);
