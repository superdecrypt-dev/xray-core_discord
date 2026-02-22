import type { MenuDefinition } from "./types";

export const menu3: MenuDefinition = {
  id: "3",
  label: "Quota & Access Control",
  description: "Ringkasan quota metadata dan detail per user.",
  actions: [
    { id: "summary", label: "Quota Summary", mode: "direct", style: "primary" },
    {
      id: "detail",
      label: "Quota Detail",
      mode: "modal",
      style: "secondary",
      modal: {
        title: "Quota Detail",
        fields: [
          { id: "proto", label: "Protocol", style: "short", required: true, placeholder: "vless/vmess/trojan" },
          { id: "username", label: "Username", style: "short", required: true, placeholder: "contoh: alice" },
        ],
      },
    },
  ],
};
