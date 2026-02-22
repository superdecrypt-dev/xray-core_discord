import fs from "node:fs";
import path from "node:path";

export interface AppConfig {
  token: string;
  applicationId: string;
  guildId: string;
  backendBaseUrl: string;
  sharedSecret: string;
  adminRoleIds: Set<string>;
  adminUserIds: Set<string>;
  commandsFile: string;
}

function parseSet(input: string | undefined): Set<string> {
  const out = new Set<string>();
  if (!input) return out;
  for (const part of input.split(",")) {
    const value = part.trim();
    if (value) out.add(value);
  }
  return out;
}

function requireEnv(name: string): string {
  const raw = process.env[name]?.trim();
  if (!raw) {
    throw new Error(`${name} belum diset.`);
  }
  return raw;
}

export function loadConfig(): AppConfig {
  const commandsFile = process.env.COMMANDS_FILE?.trim() || path.resolve(__dirname, "../../shared/commands.json");
  if (!fs.existsSync(commandsFile)) {
    throw new Error(`commands file tidak ditemukan: ${commandsFile}`);
  }

  return {
    token: requireEnv("DISCORD_BOT_TOKEN"),
    applicationId: requireEnv("DISCORD_APPLICATION_ID"),
    guildId: requireEnv("DISCORD_GUILD_ID"),
    backendBaseUrl: process.env.BACKEND_BASE_URL?.trim() || "http://127.0.0.1:8080",
    sharedSecret: requireEnv("INTERNAL_SHARED_SECRET"),
    adminRoleIds: parseSet(process.env.DISCORD_ADMIN_ROLE_IDS),
    adminUserIds: parseSet(process.env.DISCORD_ADMIN_USER_IDS),
    commandsFile,
  };
}
