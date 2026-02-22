import {
  ActionRowBuilder,
  ButtonBuilder,
  ButtonInteraction,
  ButtonStyle,
  EmbedBuilder,
  ModalBuilder,
  TextInputBuilder,
  TextInputStyle,
} from "discord.js";

import type { BackendClient } from "../api_client";
import { findAction, findMenu } from "../router";
import type { MenuActionDef } from "../views/types";
import { buildMainMenuView } from "../views/main_menu";
import { sendActionResult } from "./result";

function toButtonStyle(style: MenuActionDef["style"]): ButtonStyle {
  switch (style) {
    case "primary":
      return ButtonStyle.Primary;
    case "success":
      return ButtonStyle.Success;
    case "danger":
      return ButtonStyle.Danger;
    default:
      return ButtonStyle.Secondary;
  }
}

function chunkButtons<T>(arr: T[], size: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < arr.length; i += size) {
    out.push(arr.slice(i, i + size));
  }
  return out;
}

function buildMenuView(menuId: string) {
  const menu = findMenu(menuId);
  if (!menu) {
    return buildMainMenuView();
  }

  const embed = new EmbedBuilder().setTitle(`${menu.id}) ${menu.label}`).setDescription(menu.description).setColor(0x238636);

  const actionButtons = menu.actions.map((action) => {
    const customId = action.mode === "modal" ? `modal:${menu.id}:${action.id}` : `run:${menu.id}:${action.id}`;
    return new ButtonBuilder().setCustomId(customId).setLabel(action.label).setStyle(toButtonStyle(action.style));
  });

  const rows = chunkButtons(actionButtons, 5).map((items) => new ActionRowBuilder<ButtonBuilder>().addComponents(items));

  rows.push(
    new ActionRowBuilder<ButtonBuilder>().addComponents(
      new ButtonBuilder().setCustomId("nav:main").setLabel("Back to Main Menu").setStyle(ButtonStyle.Secondary)
    )
  );

  return {
    embeds: [embed],
    components: rows,
  };
}

function buildConfirmView(menuId: string, actionId: string) {
  const menu = findMenu(menuId);
  const action = findAction(menuId, actionId);
  const title = menu ? `${menu.id}) ${menu.label}` : "Confirm Action";
  const label = action?.label || actionId;

  const embed = new EmbedBuilder()
    .setTitle("Konfirmasi Aksi")
    .setDescription(`Aksi **${label}** akan dijalankan. Lanjutkan?`)
    .setColor(0xd29922)
    .setFooter({ text: title });

  return {
    embeds: [embed],
    components: [
      new ActionRowBuilder<ButtonBuilder>().addComponents(
        new ButtonBuilder().setCustomId(`run:${menuId}:${actionId}:confirm`).setLabel("Confirm").setStyle(ButtonStyle.Danger),
        new ButtonBuilder().setCustomId(`nav:menu:${menuId}`).setLabel("Cancel").setStyle(ButtonStyle.Secondary)
      ),
    ],
  };
}

export async function handleButton(interaction: ButtonInteraction, backend: BackendClient): Promise<boolean> {
  const id = interaction.customId;

  if (id === "nav:main") {
    await interaction.update(buildMainMenuView());
    return true;
  }

  if (id.startsWith("nav:menu:")) {
    const menuId = id.split(":")[2] || "";
    await interaction.update(buildMenuView(menuId));
    return true;
  }

  if (id.startsWith("modal:")) {
    const [, menuId, actionId] = id.split(":");
    const action = findAction(menuId, actionId);
    if (!action || action.mode !== "modal" || !action.modal) {
      await interaction.reply({ content: "Action modal tidak valid.", ephemeral: true });
      return true;
    }

    const modal = new ModalBuilder().setCustomId(`form:${menuId}:${actionId}`).setTitle(action.modal.title);
    for (const field of action.modal.fields.slice(0, 5)) {
      const input = new TextInputBuilder()
        .setCustomId(field.id)
        .setLabel(field.label)
        .setRequired(field.required)
        .setPlaceholder(field.placeholder || "")
        .setStyle(field.style === "paragraph" ? TextInputStyle.Paragraph : TextInputStyle.Short);
      modal.addComponents(new ActionRowBuilder<TextInputBuilder>().addComponents(input));
    }

    await interaction.showModal(modal);
    return true;
  }

  if (id.startsWith("run:")) {
    const parts = id.split(":");
    const menuId = parts[1] || "";
    const actionId = parts[2] || "";
    const mode = parts[3] || "";

    const action = findAction(menuId, actionId);
    if (!action) {
      await interaction.reply({ content: "Action tidak ditemukan.", ephemeral: true });
      return true;
    }

    if (action.confirm && mode !== "confirm") {
      await interaction.update(buildConfirmView(menuId, actionId));
      return true;
    }

    await interaction.deferReply({ ephemeral: true });
    try {
      const res = await backend.runAction(menuId, actionId, {});
      await sendActionResult(interaction, res.title, res.message, res.ok);
    } catch (err) {
      await sendActionResult(interaction, "Backend Error", String(err), false);
    }

    return true;
  }

  return false;
}
