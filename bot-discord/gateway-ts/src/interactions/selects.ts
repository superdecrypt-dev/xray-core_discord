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
import { createUserContextToken, isUserContextToken, resolveUserContext } from "./user_context_state";

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
            value: createUserContextToken(proto, username),
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

function buildSingleFieldSelectView(menuId: string, actionId: string, proto = "", username = "") {
  const action = findAction(menuId, actionId);
  const actionLabel = action?.label || actionId;
  const cfg = getSingleFieldSelectConfig(menuId, actionId);
  if (!cfg) {
    return null;
  }

  const contextLines: string[] = [`Pilih nilai untuk **${cfg.title}**.`];
  const protoNormalized = String(proto || "").trim().toLowerCase();
  const usernameNormalized = String(username || "").trim();
  if (protoNormalized) {
    contextLines.push(`Protocol: **${protoNormalized.toUpperCase()}**`);
  }
  if (usernameNormalized) {
    contextLines.push(`User: **${usernameNormalized}**`);
  }

  const selectIdParts = ["select", menuId, actionId, cfg.fieldId];
  if (protoNormalized) {
    selectIdParts.push(protoNormalized);
  }
  if (usernameNormalized) {
    selectIdParts.push(createUserContextToken(protoNormalized, usernameNormalized));
  }

  const embed = new EmbedBuilder()
    .setTitle(`${actionLabel} - Select`)
    .setDescription(contextLines.join("\n"))
    .setColor(0x2f81f7);

  const select = new StringSelectMenuBuilder()
    .setCustomId(selectIdParts.join(":"))
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

    if (singleFieldSelectCfg && singleFieldSelectCfg.fieldId !== "proto") {
      const hasSingleField = action.modal.fields.some((field) => field.id === singleFieldSelectCfg.fieldId);
      if (hasSingleField) {
        const singleSelectView = buildSingleFieldSelectView(menuId, actionId, protoRaw);
        if (singleSelectView) {
          await interaction.update(singleSelectView);
          return true;
        }
      }
    }

    const modalIdParts = ["form", menuId, actionId, protoRaw];
    const modal = new ModalBuilder().setCustomId(modalIdParts.join(":")).setTitle(`${action.modal.title} (${protoRaw})`);
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

    const protoFromContext = String(parts[4] || "").trim().toLowerCase();
    const usernameContextRaw = String(parts[5] || "").trim();
    const params: Record<string, string> = { [singleFieldSelectCfg.fieldId]: selectedValue };
    if (needsProtocolSelect && protoFromContext) {
      if (!isXrayProtocol(protoFromContext)) {
        await interaction.reply({ content: "Protocol tidak valid.", flags: MessageFlags.Ephemeral });
        return true;
      }
      params.proto = protoFromContext;
    }
    if (needsUsernameSelect && usernameContextRaw) {
      const resolvedUser = resolveUserContext(usernameContextRaw, params.proto || protoFromContext);
      if (!resolvedUser || !resolvedUser.username) {
        await interaction.reply({ content: "Context username kadaluarsa. Ulangi dari pilih user.", flags: MessageFlags.Ephemeral });
        return true;
      }
      if (!params.proto && resolvedUser.proto) {
        params.proto = resolvedUser.proto;
      }
      params.username = resolvedUser.username;
    }

    if (shouldSelectContinueToModal(menuId, actionId)) {
      const remainingFields = action.modal.fields
        .filter((field) => field.id !== singleFieldSelectCfg.fieldId)
        .filter((field) => !(field.id === "proto" && Boolean(params.proto)))
        .filter((field) => !(field.id === "username" && Boolean(params.username)))
        .slice(0, 5);

      if (remainingFields.length === 0) {
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

      const presetToken = encodeSingleSelectPreset(singleFieldSelectCfg.fieldId, selectedValue);
      const modalIdParts = ["form", menuId, actionId];
      if (params.proto) {
        modalIdParts.push(params.proto);
      }
      if (params.username) {
        modalIdParts.push(createUserContextToken(params.proto || "", params.username));
      }
      modalIdParts.push(presetToken);
      const modal = new ModalBuilder()
        .setCustomId(modalIdParts.join(":"))
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

    if (needsProtocolSelect && !params.proto) {
      await interaction.reply({ content: "Protocol belum dipilih.", flags: MessageFlags.Ephemeral });
      return true;
    }
    if (needsUsernameSelect && !params.username) {
      await interaction.reply({ content: "Username belum dipilih.", flags: MessageFlags.Ephemeral });
      return true;
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

  if (fieldId !== "username") {
    return false;
  }
  if (!needsUsernameSelect) {
    return false;
  }

  const selectedRaw = String(interaction.values[0] || "").trim();
  if (!selectedRaw || selectedRaw === "__none__") {
    await interaction.reply({ content: "Username tidak valid.", flags: MessageFlags.Ephemeral });
    return true;
  }

  const protoFromId = String(parts[4] || "").trim().toLowerCase();
  if (needsProtocolSelect && !isXrayProtocol(protoFromId)) {
    await interaction.reply({ content: "Protocol tidak valid.", flags: MessageFlags.Ephemeral });
    return true;
  }
  const resolvedUser = resolveUserContext(selectedRaw, needsProtocolSelect ? protoFromId : "");
  if (!resolvedUser || !resolvedUser.username) {
    const content = isUserContextToken(selectedRaw)
      ? "Pilihan user kadaluarsa. Silakan pilih ulang dari daftar user."
      : "Username tidak valid.";
    await interaction.reply({ content, flags: MessageFlags.Ephemeral });
    return true;
  }
  const selectedUsername = resolvedUser.username;

  if (singleFieldSelectCfg && fieldId !== singleFieldSelectCfg.fieldId) {
    const hasSingleField = action.modal.fields.some((field) => field.id === singleFieldSelectCfg.fieldId);
    if (hasSingleField && singleFieldSelectCfg.fieldId !== "proto" && singleFieldSelectCfg.fieldId !== "username") {
      const singleSelectView = buildSingleFieldSelectView(menuId, actionId, needsProtocolSelect ? protoFromId : "", selectedUsername);
      if (singleSelectView) {
        await interaction.update(singleSelectView);
        return true;
      }
    }
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
  const modalIdParts = ["form", menuId, actionId];
  if (needsProtocolSelect) {
    modalIdParts.push(protoFromId);
  }
  modalIdParts.push(createUserContextToken(needsProtocolSelect ? protoFromId : "", selectedUsername));
  const modal = new ModalBuilder()
    .setCustomId(modalIdParts.join(":"))
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
