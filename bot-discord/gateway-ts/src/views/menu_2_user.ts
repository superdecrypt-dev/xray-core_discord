import type { MenuDefinition } from "./types";

export const menu2: MenuDefinition = {
  id: "2",
  label: "User Management",
  description: "Lihat daftar user, pencarian, dan XRAY ACCOUNT INFO.",
  actions: [
    { id: "list_users", label: "List Users", mode: "direct", style: "primary" },
    {
      id: "search_user",
      label: "Search User",
      mode: "modal",
      style: "secondary",
      modal: {
        title: "Search User",
        fields: [{ id: "query", label: "Username Query", style: "short", required: true, placeholder: "contoh: alice" }],
      },
    },
    {
      id: "account_info",
      label: "Account Info",
      mode: "modal",
      style: "secondary",
      modal: {
        title: "User Account Info",
        fields: [
          { id: "proto", label: "Protocol", style: "short", required: true, placeholder: "vless/vmess/trojan" },
          { id: "username", label: "Username", style: "short", required: true, placeholder: "contoh: alice" },
        ],
      },
    },
  ],
};
