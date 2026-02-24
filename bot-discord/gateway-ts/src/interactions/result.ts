import { AttachmentBuilder, ButtonInteraction, EmbedBuilder, MessageFlags, ModalSubmitInteraction, StringSelectMenuInteraction } from "discord.js";

const MAX_CHUNK = 1800;
const MAX_RESULT_CHUNKS = 2;
const MAX_JSON_DOWNLOAD_BYTES = 2_000_000;

function splitText(input: string): string[] {
  const text = input.trim() || "(kosong)";
  if (text.length <= MAX_CHUNK) return [text];
  const parts: string[] = [];
  for (let i = 0; i < text.length; i += MAX_CHUNK) {
    parts.push(text.slice(i, i + MAX_CHUNK));
  }
  return parts;
}

type Replyable = ButtonInteraction | ModalSubmitInteraction | StringSelectMenuInteraction;

type JsonDownloadPayload = {
  filename: string;
  content_base64: string;
};

type AddUserSummaryPayload = {
  username: string;
  protocol: string;
  active_days: string;
  quota_gb: string;
  ip_limit: string;
  speed_limit: string;
};

function sanitizeFilename(input: string): string {
  const clean = input.replace(/[^A-Za-z0-9@._-]/g, "_").trim();
  if (!clean) return "download.json";
  return clean;
}

function extractAddUserSummary(data?: Record<string, unknown>): AddUserSummaryPayload | null {
  if (!data || typeof data !== "object") return null;
  const raw = data.add_user_summary;
  if (!raw || typeof raw !== "object") return null;
  const payload = raw as Record<string, unknown>;
  const username = String(payload.username || "").trim();
  const protocol = String(payload.protocol || "").trim();
  const activeDays = String(payload.active_days || "").trim();
  const quotaGb = String(payload.quota_gb || "").trim();
  const ipLimit = String(payload.ip_limit || "").trim();
  const speedLimit = String(payload.speed_limit || "").trim();
  if (!username || !protocol) return null;
  return {
    username,
    protocol,
    active_days: activeDays || "-",
    quota_gb: quotaGb || "-",
    ip_limit: ipLimit || "-",
    speed_limit: speedLimit || "-",
  };
}

function buildAddUserSummaryEmbed(summary: AddUserSummaryPayload): EmbedBuilder {
  return new EmbedBuilder()
    .setTitle("Add User Berhasil")
    .setDescription("Ringkasan akun baru")
    .setColor(0x2ea043)
    .addFields(
      { name: "Username", value: summary.username, inline: true },
      { name: "Protokol", value: summary.protocol.toUpperCase(), inline: true },
      { name: "Masa Aktif", value: `${summary.active_days} hari`, inline: true },
      { name: "Quota", value: summary.quota_gb, inline: true },
      { name: "IP Limit", value: summary.ip_limit, inline: true },
      { name: "Speed Limit", value: summary.speed_limit, inline: false },
    );
}

function extractJsonDownload(data?: Record<string, unknown>): JsonDownloadPayload | null {
  if (!data || typeof data !== "object") return null;
  const raw = data.download_file || data.download_json;
  if (!raw || typeof raw !== "object") return null;
  const payload = raw as Record<string, unknown>;
  const filename = sanitizeFilename(String(payload.filename || ""));
  const contentBase64 = String(payload.content_base64 || "").trim();
  if (!contentBase64) return null;
  return { filename, content_base64: contentBase64 };
}

function buildJsonAttachment(payload: JsonDownloadPayload): AttachmentBuilder | null {
  try {
    const bytes = Buffer.from(payload.content_base64, "base64");
    if (!bytes.length || bytes.length > MAX_JSON_DOWNLOAD_BYTES) return null;
    return new AttachmentBuilder(bytes, { name: payload.filename });
  } catch {
    return null;
  }
}

export async function sendActionResult(
  interaction: Replyable,
  title: string,
  message: string,
  ok: boolean,
  data?: Record<string, unknown>,
): Promise<void> {
  const summary = extractAddUserSummary(data);
  if (ok && summary) {
    const embed = buildAddUserSummaryEmbed(summary);
    if (interaction.deferred || interaction.replied) {
      await interaction.followUp({ embeds: [embed], flags: MessageFlags.Ephemeral });
    } else {
      await interaction.reply({ embeds: [embed], flags: MessageFlags.Ephemeral });
    }

    const download = extractJsonDownload(data);
    if (!download) return;
    const attachment = buildJsonAttachment(download);
    if (!attachment) {
      await interaction.followUp({
        content: "File lampiran tidak bisa dikirim (format/ukuran tidak valid).",
        flags: MessageFlags.Ephemeral,
      });
      return;
    }
    await interaction.followUp({
      content: `File: \`${download.filename}\``,
      files: [attachment],
      flags: MessageFlags.Ephemeral,
    });
    return;
  }

  const chunks = splitText(message.replace(/```/g, "'''") );
  const visibleChunks = chunks.slice(0, MAX_RESULT_CHUNKS);
  const droppedChunks = Math.max(chunks.length - visibleChunks.length, 0);
  const prefix = ok ? "OK" : "ERROR";

  if (interaction.deferred || interaction.replied) {
    await interaction.followUp({ content: `**${prefix}** ${title}`, flags: MessageFlags.Ephemeral });
  } else {
    await interaction.reply({ content: `**${prefix}** ${title}`, flags: MessageFlags.Ephemeral });
  }

  for (const chunk of visibleChunks) {
    await interaction.followUp({ content: `\`\`\`text\n${chunk}\n\`\`\``, flags: MessageFlags.Ephemeral });
  }

  if (droppedChunks > 0) {
    await interaction.followUp({
      content: `Output dipotong agar tidak spam. Bagian tersembunyi: ${droppedChunks} chunk.`,
      flags: MessageFlags.Ephemeral,
    });
  }

  const download = extractJsonDownload(data);
  if (!download) return;
  const attachment = buildJsonAttachment(download);
  if (!attachment) {
    await interaction.followUp({
      content: "File lampiran tidak bisa dikirim (format/ukuran tidak valid).",
      flags: MessageFlags.Ephemeral,
    });
    return;
  }
  await interaction.followUp({
    content: `File: \`${download.filename}\``,
    files: [attachment],
    flags: MessageFlags.Ephemeral,
  });
}
