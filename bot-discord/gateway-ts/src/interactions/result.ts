import { ButtonInteraction, ModalSubmitInteraction } from "discord.js";

const MAX_CHUNK = 1800;

function splitText(input: string): string[] {
  const text = input.trim() || "(kosong)";
  if (text.length <= MAX_CHUNK) return [text];
  const parts: string[] = [];
  for (let i = 0; i < text.length; i += MAX_CHUNK) {
    parts.push(text.slice(i, i + MAX_CHUNK));
  }
  return parts;
}

type Replyable = ButtonInteraction | ModalSubmitInteraction;

export async function sendActionResult(interaction: Replyable, title: string, message: string, ok: boolean): Promise<void> {
  const chunks = splitText(message.replace(/```/g, "'''") );
  const prefix = ok ? "OK" : "ERROR";

  if (interaction.deferred || interaction.replied) {
    await interaction.followUp({ content: `**${prefix}** ${title}`, ephemeral: true });
  } else {
    await interaction.reply({ content: `**${prefix}** ${title}`, ephemeral: true });
  }

  for (const chunk of chunks) {
    await interaction.followUp({ content: `\`\`\`text\n${chunk}\n\`\`\``, ephemeral: true });
  }
}
