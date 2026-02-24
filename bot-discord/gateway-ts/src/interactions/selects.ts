import {
  ActionRowBuilder,
  ButtonBuilder,
  ButtonStyle,
  EmbedBuilder,
  MessageFlags,
  ModalBuilder,
  StringSelectMenuInteraction,
  StringSelectMenuBuilder,
  TextInputBuilder,
  TextInputStyle,
} from "discord.js";

import type { BackendClient } from "../api_client";
import {
  encodeSingleSelectPreset,
  getSingleFieldSelectConfig,
  shouldSelectContinueToModal,
} from "../constants/action_selects";
import { isXrayProtocol, shouldUseProtocolSelect, shouldUseUsernameSelect } from "../constants/protocols";
import { findAction } from "../router";
import { createPendingConfirm } from "./confirm_state";
import { buildPendingConfirmView } from "./confirm_view";
import { sendActionResult } from "./result";

const USER_SELECT_PAGE_SIZE = 25;

function buildUsernameSelectView(menuId: string, actionId: string, proto: string, usernames: string[], pageRaw = 0) {
  const action = findAction(menuId, actionId);
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
    .setColor(0x2f81f7);

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

export async function handleSelect(interaction: StringSelectMenuInteraction, backend: BackendClient): Promise<boolean> {
  const id = interaction.customId;
  if (!id.startsWith("select:")) {
    return false;
  }

  const parts = id.split(":");
  const menuId = parts[1] || "";
  const actionId = parts[2] || "";
  const fieldId = parts[3] || "";

  const action = findAction(menuId, actionId);
  if (!action || action.mode !== "modal" || !action.modal) {
    return false;
  }

  const hasProtoField = action.modal.fields.some((field) => field.id === "proto");
  const hasUsernameField = action.modal.fields.some((field) => field.id === "username");
  const needsProtocolSelect = shouldUseProtocolSelect(menuId, actionId, hasProtoField);
  const needsUsernameSelect = shouldUseUsernameSelect(actionId, hasUsernameField);
  const singleFieldSelectCfg = getSingleFieldSelectConfig(menuId, actionId);

  if (fieldId === "proto") {
    if (!needsProtocolSelect) {
      return false;
    }

    const protoRaw = String(interaction.values[0] || "").trim().toLowerCase();
    if (!isXrayProtocol(protoRaw)) {
      await interaction.reply({ content: "Protocol tidak valid.", flags: MessageFlags.Ephemeral });
      return true;
    }

    if (needsUsernameSelect) {
      const options = await backend.listUserOptions(protoRaw);
      const seen = new Set<string>();
      const usernames = options
        .filter((item) => item.proto.toLowerCase() === protoRaw)
        .map((item) => String(item.username || "").trim())
        .filter((username) => {
          if (!username || seen.has(username)) return false;
          seen.add(username);
          return true;
        })
        .sort((a, b) => a.localeCompare(b));
      await interaction.update(buildUsernameSelectView(menuId, actionId, protoRaw, usernames, 0));
      return true;
    }

    const modal = new ModalBuilder().setCustomId(`form:${menuId}:${actionId}:${protoRaw}`).setTitle(`${action.modal.title} (${protoRaw})`);
    const fields = action.modal.fields.filter((field) => field.id !== "proto").slice(0, 5);
    for (const field of fields) {
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

  if (singleFieldSelectCfg && fieldId === singleFieldSelectCfg.fieldId) {
    const selectedValue = String(interaction.values[0] || "").trim();
    const isAllowed = singleFieldSelectCfg.options.some((opt) => opt.value === selectedValue);
    if (!isAllowed) {
      await interaction.reply({ content: "Nilai pilihan tidak valid.", flags: MessageFlags.Ephemeral });
      return true;
    }

    if (shouldSelectContinueToModal(menuId, actionId)) {
      const remainingFields = action.modal.fields.filter((field) => field.id !== singleFieldSelectCfg.fieldId).slice(0, 5);
      const presetToken = encodeSingleSelectPreset(singleFieldSelectCfg.fieldId, selectedValue);
      const modal = new ModalBuilder()
        .setCustomId(`form:${menuId}:${actionId}:${presetToken}`)
        .setTitle(`${action.modal.title} (${selectedValue})`);
      for (const field of remainingFields) {
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

    const params: Record<string, string> = { [singleFieldSelectCfg.fieldId]: selectedValue };
    if (action.confirm) {
      const token = createPendingConfirm({ menuId, actionId, params });
      await interaction.update(buildPendingConfirmView(menuId, actionId, token, params));
      return true;
    }

    await interaction.deferReply({ flags: MessageFlags.Ephemeral });
    try {
      const res = await backend.runAction(menuId, actionId, params);
      await sendActionResult(interaction, res.title, res.message, res.ok, res.data);
    } catch (err) {
      await sendActionResult(interaction, "Backend Error", String(err), false);
    }
    return true;
  }

  if (fieldId !== "username") {
    return false;
  }
  if (!needsUsernameSelect) {
    return false;
  }

  const selectedUsername = String(interaction.values[0] || "").trim();
  if (!selectedUsername || selectedUsername === "__none__") {
    await interaction.reply({ content: "Username tidak valid.", flags: MessageFlags.Ephemeral });
    return true;
  }

  const protoFromId = String(parts[4] || "").trim().toLowerCase();
  if (needsProtocolSelect && !isXrayProtocol(protoFromId)) {
    await interaction.reply({ content: "Protocol tidak valid.", flags: MessageFlags.Ephemeral });
    return true;
  }

  const remainingFields = action.modal.fields.filter((field) => field.id !== "proto" && field.id !== "username").slice(0, 5);
  if (remainingFields.length === 0) {
    const params: Record<string, string> = { username: selectedUsername };
    if (needsProtocolSelect) {
      params.proto = protoFromId;
    }

    if (action.confirm) {
      const token = createPendingConfirm({ menuId, actionId, params });
      await interaction.update(buildPendingConfirmView(menuId, actionId, token, params));
      return true;
    }

    await interaction.deferReply({ flags: MessageFlags.Ephemeral });
    try {
      const res = await backend.runAction(menuId, actionId, params);
      await sendActionResult(interaction, res.title, res.message, res.ok, res.data);
    } catch (err) {
      await sendActionResult(interaction, "Backend Error", String(err), false);
    }
    return true;
  }

  const titleSuffix = needsProtocolSelect ? ` (${protoFromId})` : "";
  const modal = new ModalBuilder()
    .setCustomId(`form:${menuId}:${actionId}:${protoFromId}:${selectedUsername}`)
    .setTitle(`${action.modal.title}${titleSuffix}`);
  for (const field of remainingFields) {
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
