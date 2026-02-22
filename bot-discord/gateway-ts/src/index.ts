import "dotenv/config";

import {
  ChatInputCommandInteraction,
  Client,
  Events,
  GatewayIntentBits,
  REST,
  Routes,
  SlashCommandBuilder,
} from "discord.js";

import { BackendClient } from "./api_client";
import { isAuthorized } from "./authz";
import { loadConfig } from "./config";
import { handleButton } from "./interactions/buttons";
import { handleModal } from "./interactions/modals";
import { handlePanelCommand } from "./interactions/panel";
import { handleSelect } from "./interactions/selects";

const cfg = loadConfig();
const backend = new BackendClient(cfg.backendBaseUrl, cfg.sharedSecret);

const client = new Client({ intents: [GatewayIntentBits.Guilds] });

async function registerSlashCommands(): Promise<void> {
  const commands = [new SlashCommandBuilder().setName("panel").setDescription("Buka panel bot Xray standalone").toJSON()];
  const rest = new REST({ version: "10" }).setToken(cfg.token);
  await rest.put(Routes.applicationGuildCommands(cfg.applicationId, cfg.guildId), { body: commands });
}

async function assertAuthorized(interaction: ChatInputCommandInteraction): Promise<boolean> {
  const member = interaction.inGuild() ? interaction.member : null;
  if (!interaction.inGuild() || !isAuthorized(member as any, interaction.user.id, cfg)) {
    await interaction.reply({ content: "Akses ditolak. Hubungi admin.", ephemeral: true });
    return false;
  }
  return true;
}

client.once(Events.ClientReady, async (ready) => {
  console.log(`[gateway] logged in as ${ready.user.tag}`);
  await registerSlashCommands();
  console.log("[gateway] slash command /panel registered.");
});

client.on(Events.InteractionCreate, async (interaction) => {
  try {
    if (interaction.isChatInputCommand() && interaction.commandName === "panel") {
      if (!(await assertAuthorized(interaction))) return;
      await handlePanelCommand(interaction);
      return;
    }

    if (interaction.isButton()) {
      if (!interaction.inGuild() || !isAuthorized(interaction.member as any, interaction.user.id, cfg)) {
        await interaction.reply({ content: "Akses ditolak.", ephemeral: true });
        return;
      }
      const handled = await handleButton(interaction, backend);
      if (!handled && !interaction.replied) {
        await interaction.reply({ content: "Button tidak dikenali.", ephemeral: true });
      }
      return;
    }

    if (interaction.isModalSubmit()) {
      if (!interaction.inGuild() || !isAuthorized(interaction.member as any, interaction.user.id, cfg)) {
        await interaction.reply({ content: "Akses ditolak.", ephemeral: true });
        return;
      }
      const handled = await handleModal(interaction, backend);
      if (!handled && !interaction.replied) {
        await interaction.reply({ content: "Modal tidak dikenali.", ephemeral: true });
      }
      return;
    }

    if (interaction.isStringSelectMenu()) {
      if (!interaction.inGuild() || !isAuthorized(interaction.member as any, interaction.user.id, cfg)) {
        await interaction.reply({ content: "Akses ditolak.", ephemeral: true });
        return;
      }
      const handled = await handleSelect(interaction);
      if (!handled && !interaction.replied) {
        await interaction.reply({ content: "Select interaction belum diaktifkan untuk opsi ini.", ephemeral: true });
      }
    }
  } catch (err) {
    const text = `Terjadi error: ${String(err)}`;
    if (interaction.isRepliable()) {
      if (interaction.replied || interaction.deferred) {
        await interaction.followUp({ content: text, ephemeral: true });
      } else {
        await interaction.reply({ content: text, ephemeral: true });
      }
    }
  }
});

client.login(cfg.token);
