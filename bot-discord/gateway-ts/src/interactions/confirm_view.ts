import { ActionRowBuilder, ButtonBuilder, ButtonStyle, EmbedBuilder } from "discord.js";

import { findAction, findMenu } from "../router";

export function buildPendingConfirmView(menuId: string, actionId: string, token: string, params: Record<string, string>) {
  const menu = findMenu(menuId);
  const action = findAction(menuId, actionId);
  const actionLabel = action?.label || actionId;
  const menuTitle = menu ? `${menu.id}) ${menu.label}` : "Confirm Action";

  const details: string[] = [];
  const proto = String(params.proto || "").trim();
  const username = String(params.username || "").trim();
  if (proto) details.push(`Protocol: **${proto.toUpperCase()}**`);
  if (username) details.push(`User: **${username}**`);

  const detailBlock = details.length > 0 ? `\n${details.join("\n")}` : "";

  const embed = new EmbedBuilder()
    .setTitle("Konfirmasi Aksi")
    .setDescription(`Aksi **${actionLabel}** akan dijalankan.${detailBlock}\nLanjutkan?`)
    .setColor(0xd29922)
    .setFooter({ text: menuTitle });

  return {
    embeds: [embed],
    components: [
      new ActionRowBuilder<ButtonBuilder>().addComponents(
        new ButtonBuilder().setCustomId(`runconfirm:${token}`).setLabel("Ya, Lanjutkan").setStyle(ButtonStyle.Danger),
        new ButtonBuilder().setCustomId(`nav:menu:${menuId}`).setLabel("Tidak, Batal").setStyle(ButtonStyle.Secondary)
      ),
    ],
  };
}
