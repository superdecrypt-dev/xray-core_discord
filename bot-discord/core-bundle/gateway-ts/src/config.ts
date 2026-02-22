export type BotConfig = {
  token: string;
  applicationId: string;
  guildId: string;
  adminRoleId?: string;
  backendBaseUrl: string;
  internalSharedSecret: string;
};

export function loadConfig(): BotConfig {
  return {
    token: process.env.DISCORD_BOT_TOKEN ?? "",
    applicationId: process.env.DISCORD_APPLICATION_ID ?? "",
    guildId: process.env.DISCORD_GUILD_ID ?? "",
    adminRoleId: process.env.DISCORD_ADMIN_ROLE_ID,
    backendBaseUrl: process.env.BACKEND_BASE_URL ?? "http://127.0.0.1:8787",
    internalSharedSecret: process.env.INTERNAL_SHARED_SECRET ?? ""
  };
}
