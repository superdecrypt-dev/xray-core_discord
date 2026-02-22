import { GuildMember, PermissionsBitField } from "discord.js";

import type { AppConfig } from "./config";

export function isAuthorized(member: GuildMember | null, userId: string, cfg: AppConfig): boolean {
  if (cfg.adminUserIds.size > 0 && cfg.adminUserIds.has(userId)) {
    return true;
  }

  if (member && cfg.adminRoleIds.size > 0) {
    for (const role of member.roles.cache.values()) {
      if (cfg.adminRoleIds.has(role.id)) {
        return true;
      }
    }
  }

  if (cfg.adminRoleIds.size === 0 && cfg.adminUserIds.size === 0) {
    return !!member?.permissions.has(PermissionsBitField.Flags.Administrator);
  }

  return false;
}
