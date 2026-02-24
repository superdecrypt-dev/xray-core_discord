import { MessageFlags, ModalSubmitInteraction } from "discord.js";

import type { BackendClient } from "../api_client";
import { decodeSingleSelectPreset } from "../constants/action_selects";
import { isXrayProtocol, shouldUseProtocolSelect, shouldUseUsernameSelect } from "../constants/protocols";
import { findAction } from "../router";
import { createPendingConfirm } from "./confirm_state";
import { buildPendingConfirmView } from "./confirm_view";
import { sendActionResult } from "./result";

type SpeedParseResult =
  | { ok: true; enabled: false }
  | { ok: true; enabled: true; down: string; up: string }
  | { ok: false; error: string };

function parseSpeedLimitInput(raw: string): SpeedParseResult {
  const value = String(raw || "").trim().toLowerCase();
  if (!value || value === "0" || value === "-" || value === "off" || value === "disable" || value === "disabled" || value === "none") {
    return { ok: true, enabled: false };
  }

  const cleaned = value.replace(/\s+/g, "");
  const parts = cleaned.split("/");
  if (parts.length > 2) {
    return { ok: false, error: "Format speed limit tidak valid. Gunakan off, 20, atau 20/10." };
  }

  const parsePositive = (input: string): number | null => {
    const n = Number(input);
    if (!Number.isFinite(n) || n <= 0) return null;
    return n;
  };

  if (parts.length === 1) {
    const symmetric = parsePositive(parts[0]);
    if (symmetric === null) {
      return { ok: false, error: "Speed limit harus angka > 0. Contoh: 20 atau 20/10." };
    }
    const normalized = `${symmetric}`;
    return { ok: true, enabled: true, down: normalized, up: normalized };
  }

  const down = parsePositive(parts[0]);
  const up = parsePositive(parts[1]);
  if (down === null || up === null) {
    return { ok: false, error: "Speed limit down/up harus angka > 0. Contoh: 20/10." };
  }

  return { ok: true, enabled: true, down: `${down}`, up: `${up}` };
}

export async function handleModal(interaction: ModalSubmitInteraction, backend: BackendClient): Promise<boolean> {
  const id = interaction.customId;
  if (!id.startsWith("form:")) {
    return false;
  }

  const [, menuId, actionId, presetProto = "", presetUsername = ""] = id.split(":");
  const action = findAction(menuId, actionId);
  if (!action || action.mode !== "modal" || !action.modal) {
    await interaction.reply({ content: "Modal action tidak valid.", flags: MessageFlags.Ephemeral });
    return true;
  }

  const params: Record<string, string> = {};
  for (const field of action.modal.fields) {
    try {
      params[field.id] = interaction.fields.getTextInputValue(field.id) || "";
    } catch {
      // Field bisa tidak ada ketika value protocol dipilih via select.
    }
  }

  const presetSelect = decodeSingleSelectPreset(presetProto);
  if (presetSelect) {
    params[presetSelect.fieldId] = presetSelect.value;
  }

  const hasProtoField = action.modal.fields.some((field) => field.id === "proto");
  const hasUsernameField = action.modal.fields.some((field) => field.id === "username");
  const needsProtocolSelect = shouldUseProtocolSelect(menuId, actionId, hasProtoField);
  const needsUsernameSelect = shouldUseUsernameSelect(actionId, hasUsernameField);

  let selectedProto = (presetProto || "").trim().toLowerCase();
  if (needsProtocolSelect && !selectedProto) {
    selectedProto = String(params.proto || "").trim().toLowerCase();
  }
  if (needsProtocolSelect && !selectedProto) {
    // Fallback kompatibilitas modal lama yang masih punya input "proto".
    try {
      selectedProto = (interaction.fields.getTextInputValue("proto") || "").trim().toLowerCase();
    } catch {
      selectedProto = "";
    }
  }

  if (needsProtocolSelect) {
    if (!isXrayProtocol(selectedProto)) {
      await interaction.reply({ content: "Protocol tidak valid.", flags: MessageFlags.Ephemeral });
      return true;
    }
    params.proto = selectedProto;
  }

  if (needsUsernameSelect) {
    const selectedUsername = String(presetUsername || params.username || "").trim();
    if (!selectedUsername) {
      await interaction.reply({ content: "Username tidak valid.", flags: MessageFlags.Ephemeral });
      return true;
    }
    params.username = selectedUsername;
  }

  if (menuId === "2" && actionId === "add_user") {
    const parsedSpeed = parseSpeedLimitInput(params.speed_limit || "");
    delete params.speed_limit;
    if (!parsedSpeed.ok) {
      await interaction.reply({ content: parsedSpeed.error, flags: MessageFlags.Ephemeral });
      return true;
    }
    if (parsedSpeed.enabled) {
      params.speed_limit_enabled = "true";
      params.speed_down_mbit = parsedSpeed.down;
      params.speed_up_mbit = parsedSpeed.up;
    } else {
      params.speed_limit_enabled = "false";
    }
  }

  if (action.confirm) {
    const token = createPendingConfirm({ menuId, actionId, params });
    await interaction.reply({
      ...buildPendingConfirmView(menuId, actionId, token, params),
      flags: MessageFlags.Ephemeral,
    });
    return true;
  }

  await interaction.deferReply({ flags: MessageFlags.Ephemeral });
  try {
    const res = await backend.runAction(menuId, actionId, params);
    await sendActionResult(interaction, res.title, res.message, res.ok);
  } catch (err) {
    await sendActionResult(interaction, "Backend Error", String(err), false);
  }
  return true;
}
