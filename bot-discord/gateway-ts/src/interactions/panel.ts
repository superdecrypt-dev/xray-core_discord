import { ChatInputCommandInteraction, MessageFlags } from "discord.js";

import { buildMainMenuView } from "../views/main_menu";

export async function handlePanelCommand(interaction: ChatInputCommandInteraction): Promise<void> {
  await interaction.reply({
    ...buildMainMenuView(),
    flags: MessageFlags.Ephemeral,
  });
}
