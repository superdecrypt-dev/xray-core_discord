import { ActionRowBuilder, ButtonBuilder, ButtonStyle, EmbedBuilder } from "discord.js";

import { MENUS } from "../router";

function chunkButtons<T>(arr: T[], size: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < arr.length; i += size) {
    out.push(arr.slice(i, i + size));
  }
  return out;
}

export function buildMainMenuView() {
  const embed = new EmbedBuilder()
    .setTitle("Xray Discord Panel [BETA]")
    .setDescription("Pilih menu dan tindakan yang akan dijalankan. Mode saat ini: BETA.")
    .setColor(0x2f81f7);

  const buttons = MENUS.map((menu) =>
    new ButtonBuilder().setCustomId(`nav:menu:${menu.id}`).setLabel(`${menu.id}) ${menu.label}`).setStyle(ButtonStyle.Secondary)
  );

  const rows = chunkButtons(buttons, 5).map((items) => new ActionRowBuilder<ButtonBuilder>().addComponents(items));

  return {
    embeds: [embed],
    components: rows,
  };
}
