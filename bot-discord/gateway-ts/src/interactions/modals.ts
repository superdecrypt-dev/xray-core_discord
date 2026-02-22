import { ModalSubmitInteraction } from "discord.js";

import type { BackendClient } from "../api_client";
import { findAction } from "../router";
import { sendActionResult } from "./result";

export async function handleModal(interaction: ModalSubmitInteraction, backend: BackendClient): Promise<boolean> {
  const id = interaction.customId;
  if (!id.startsWith("form:")) {
    return false;
  }

  const [, menuId, actionId] = id.split(":");
  const action = findAction(menuId, actionId);
  if (!action || action.mode !== "modal" || !action.modal) {
    await interaction.reply({ content: "Modal action tidak valid.", ephemeral: true });
    return true;
  }

  const params: Record<string, string> = {};
  for (const field of action.modal.fields) {
    params[field.id] = interaction.fields.getTextInputValue(field.id) || "";
  }

  await interaction.deferReply({ ephemeral: true });
  try {
    const res = await backend.runAction(menuId, actionId, params);
    await sendActionResult(interaction, res.title, res.message, res.ok);
  } catch (err) {
    await sendActionResult(interaction, "Backend Error", String(err), false);
  }
  return true;
}
