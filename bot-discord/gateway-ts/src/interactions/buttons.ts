import {
  ActionRowBuilder,
  ButtonBuilder,
  ButtonInteraction,
  ButtonStyle,
  EmbedBuilder,
  MessageFlags,
  ModalBuilder,
  StringSelectMenuBuilder,
  TextInputBuilder,
  TextInputStyle,
} from "discord.js";

import type { BackendClient } from "../api_client";
import { getSingleFieldSelectConfig } from "../constants/action_selects";
import { isXrayProtocol, shouldUseProtocolSelect, XRAY_PROTOCOLS } from "../constants/protocols";
import { findAction, findMenu } from "../router";
import type { MenuActionDef } from "../views/types";
import { buildMainMenuView } from "../views/main_menu";
import { consumePendingConfirm } from "./confirm_state";
import { sendActionResult } from "./result";

const USER_SELECT_PAGE_SIZE = 25;

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

function buildProtocolSelectView(menuId: string, actionId: string) {
  const menu = findMenu(menuId);
  const action = findAction(menuId, actionId);
  const title = menu ? `${menu.id}) ${menu.label}` : "User Management";
  const actionLabel = action?.label || actionId;

  const embed = new EmbedBuilder()
    .setTitle(`${actionLabel} - Pilih Protocol`)
    .setDescription(`Pilih protocol dulu, lalu isi form ${actionLabel}.`)
    .setColor(0x2f81f7)
    .setFooter({ text: title });

  const select = new StringSelectMenuBuilder()
    .setCustomId(`select:${menuId}:${actionId}:proto`)
    .setPlaceholder("Pilih protocol")
    .addOptions(
      XRAY_PROTOCOLS.map((proto) => ({
        label: proto.toUpperCase(),
        value: proto,
        description: `Gunakan protocol ${proto}`,
      }))
    );

  return {
    embeds: [embed],
    components: [
      new ActionRowBuilder<StringSelectMenuBuilder>().addComponents(select),
      new ActionRowBuilder<ButtonBuilder>().addComponents(
        new ButtonBuilder().setCustomId(`nav:menu:${menuId}`).setLabel("Back").setStyle(ButtonStyle.Secondary)
      ),
    ],
  };
}

function buildSingleFieldSelectView(menuId: string, actionId: string) {
  const menu = findMenu(menuId);
  const action = findAction(menuId, actionId);
  const cfg = getSingleFieldSelectConfig(menuId, actionId);
  const title = menu ? `${menu.id}) ${menu.label}` : "Network Controls";
  const actionLabel = action?.label || actionId;
  if (!cfg) {
    return null;
  }

  const embed = new EmbedBuilder()
    .setTitle(`${actionLabel} - Select`)
    .setDescription(`Pilih nilai untuk **${cfg.title}**.`)
    .setColor(0x2f81f7)
    .setFooter({ text: title });

  const select = new StringSelectMenuBuilder()
    .setCustomId(`select:${menuId}:${actionId}:${cfg.fieldId}`)
    .setPlaceholder(cfg.placeholder)
    .addOptions(
      cfg.options.map((opt) => ({
        label: opt.label,
        value: opt.value,
        description: opt.description || "",
      }))
    );

  return {
    embeds: [embed],
    components: [
      new ActionRowBuilder<StringSelectMenuBuilder>().addComponents(select),
      new ActionRowBuilder<ButtonBuilder>().addComponents(
        new ButtonBuilder().setCustomId(`nav:menu:${menuId}`).setLabel("Back").setStyle(ButtonStyle.Secondary)
      ),
    ],
  };
}

function buildUsernameSelectView(menuId: string, actionId: string, proto: string, usernames: string[], pageRaw = 0) {
  const menu = findMenu(menuId);
  const action = findAction(menuId, actionId);
  const title = menu ? `${menu.id}) ${menu.label}` : "User Management";
  const actionLabel = action?.label || actionId;

  const total = usernames.length;
  const totalPages = Math.max(1, Math.ceil(total / USER_SELECT_PAGE_SIZE));
  const page = Math.min(Math.max(0, pageRaw), totalPages - 1);
  const start = page * USER_SELECT_PAGE_SIZE;
  const end = start + USER_SELECT_PAGE_SIZE;
  const items = usernames.slice(start, end);

  const embed = new EmbedBuilder()
    .setTitle(`${actionLabel} - Pilih User`)
    .setDescription(`Protocol: **${proto.toUpperCase()}**\nTotal user: **${total}**\nHalaman: **${page + 1}/${totalPages}**`)
    .setColor(0x2f81f7)
    .setFooter({ text: title });

  const select = new StringSelectMenuBuilder()
    .setCustomId(`select:${menuId}:${actionId}:username:${proto}:${page}`)
    .setPlaceholder(items.length > 0 ? "Pilih username" : "Tidak ada user")
    .setDisabled(items.length === 0)
    .addOptions(
      items.length > 0
        ? items.map((username) => ({
            label: username.slice(0, 100),
            value: username,
            description: `${proto.toUpperCase()} user`,
          }))
        : [{ label: "(kosong)", value: "__none__", description: "Tidak ada user", default: true }]
    );

  const navButtons: ButtonBuilder[] = [];
  if (totalPages > 1) {
    navButtons.push(
      new ButtonBuilder()
        .setCustomId(`userpage:${menuId}:${actionId}:${proto}:${Math.max(page - 1, 0)}`)
        .setLabel("Prev")
        .setStyle(ButtonStyle.Secondary)
        .setDisabled(page <= 0)
    );
    navButtons.push(
      new ButtonBuilder()
        .setCustomId(`userpage:${menuId}:${actionId}:${proto}:${Math.min(page + 1, totalPages - 1)}`)
        .setLabel("Next")
        .setStyle(ButtonStyle.Secondary)
        .setDisabled(page >= totalPages - 1)
    );
  }
  navButtons.push(new ButtonBuilder().setCustomId(`modal:${menuId}:${actionId}`).setLabel("Ganti Protocol").setStyle(ButtonStyle.Secondary));
  navButtons.push(new ButtonBuilder().setCustomId(`nav:menu:${menuId}`).setLabel("Back").setStyle(ButtonStyle.Secondary));

  return {
    embeds: [embed],
    components: [
      new ActionRowBuilder<StringSelectMenuBuilder>().addComponents(select),
      new ActionRowBuilder<ButtonBuilder>().addComponents(navButtons),
    ],
  };
}

function actionHasProtoField(action: MenuActionDef): boolean {
  if (action.mode !== "modal" || !action.modal) {
    return false;
  }
  return action.modal.fields.some((field) => field.id === "proto");
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

  if (id.startsWith("userpage:")) {
    const [, menuId, actionId, protoRaw, pageRaw = "0"] = id.split(":");
    const proto = String(protoRaw || "").trim().toLowerCase();
    if (!isXrayProtocol(proto)) {
      await interaction.reply({ content: "Protocol tidak valid.", flags: MessageFlags.Ephemeral });
      return true;
    }
    const page = Number.parseInt(pageRaw, 10);
    const users = await backend.listUserOptions(proto);
    const usernames = users
      .filter((item) => item.proto.toLowerCase() === proto)
      .map((item) => item.username)
      .filter((value) => Boolean(value))
      .sort((a, b) => a.localeCompare(b));
    await interaction.update(buildUsernameSelectView(menuId, actionId, proto, usernames, Number.isFinite(page) ? page : 0));
    return true;
  }

  if (id.startsWith("modal:")) {
    const [, menuId, actionId] = id.split(":");
    const action = findAction(menuId, actionId);
    if (!action || action.mode !== "modal" || !action.modal) {
      await interaction.reply({ content: "Action modal tidak valid.", flags: MessageFlags.Ephemeral });
      return true;
    }
    const singleSelectView = buildSingleFieldSelectView(menuId, actionId);
    if (singleSelectView) {
      await interaction.update(singleSelectView);
      return true;
    }
    if (shouldUseProtocolSelect(menuId, actionId, actionHasProtoField(action))) {
      await interaction.update(buildProtocolSelectView(menuId, actionId));
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
      await interaction.reply({ content: "Action tidak ditemukan.", flags: MessageFlags.Ephemeral });
      return true;
    }

    if (action.confirm && mode !== "confirm") {
      await interaction.update(buildConfirmView(menuId, actionId));
      return true;
    }

    await interaction.deferReply({ flags: MessageFlags.Ephemeral });
    try {
      const res = await backend.runAction(menuId, actionId, {});
      await sendActionResult(interaction, res.title, res.message, res.ok, res.data);
    } catch (err) {
      await sendActionResult(interaction, "Backend Error", String(err), false);
    }

    return true;
  }

  if (id.startsWith("runconfirm:")) {
    const token = id.split(":")[1] || "";
    const pending = consumePendingConfirm(token);
    if (!pending) {
      await interaction.reply({ content: "Konfirmasi kadaluarsa. Ulangi aksi dari menu.", flags: MessageFlags.Ephemeral });
      return true;
    }

    await interaction.deferReply({ flags: MessageFlags.Ephemeral });
    try {
      const res = await backend.runAction(pending.menuId, pending.actionId, pending.params);
      await sendActionResult(interaction, res.title, res.message, res.ok, res.data);
    } catch (err) {
      await sendActionResult(interaction, "Backend Error", String(err), false);
    }

    return true;
  }

  return false;
}
