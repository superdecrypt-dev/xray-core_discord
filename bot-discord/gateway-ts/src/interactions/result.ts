import { ButtonInteraction, MessageFlags, ModalSubmitInteraction, StringSelectMenuInteraction } from "discord.js";

const MAX_CHUNK = 1800;
const MAX_RESULT_CHUNKS = 2;

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

export async function sendActionResult(interaction: Replyable, title: string, message: string, ok: boolean): Promise<void> {
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
}
