import type { MenuDefinition } from "./types";

export const menu2: MenuDefinition = {
  id: "2",
  label: "User Management",
  description: "Kelola pengguna, masa aktif, pencarian, dan informasi akun.",
  actions: [
    {
      id: "add_user",
      label: "Add User",
      mode: "modal",
      style: "success",
      modal: {
        title: "Add User",
        fields: [
          { id: "username", label: "Username", style: "short", required: true, placeholder: "contoh: alice" },
          { id: "days", label: "Masa Aktif (hari)", style: "short", required: true, placeholder: "30" },
          { id: "quota_gb", label: "Quota (GB)", style: "short", required: true, placeholder: "100" },
          { id: "ip_limit", label: "IP Limit (opsional)", style: "short", required: false, placeholder: "0 = OFF" },
          {
            id: "speed_limit",
            label: "Speed Limit Mbps (opsional)",
            style: "short",
            required: false,
            placeholder: "off | 20 | 20/10 (down/up)",
          },
        ],
      },
    },
    {
      id: "delete_user",
      label: "Delete User",
      mode: "modal",
      style: "danger",
      confirm: true,
      modal: {
        title: "Delete User",
        fields: [
          { id: "proto", label: "Protocol", style: "short", required: true, placeholder: "vless/vmess/trojan" },
          { id: "username", label: "Username", style: "short", required: true, placeholder: "contoh: alice" },
        ],
      },
    },
    {
      id: "extend_expiry",
      label: "Set User Expiry",
      mode: "modal",
      style: "primary",
      modal: {
        title: "Extend/Set Expiry",
        fields: [
          { id: "username", label: "Username", style: "short", required: true, placeholder: "contoh: alice" },
          { id: "mode", label: "Mode", style: "short", required: true, placeholder: "extend / set" },
          { id: "value", label: "Value", style: "short", required: true, placeholder: "7 atau 2026-12-31" },
        ],
      },
    },
    { id: "list_users", label: "View User List", mode: "direct", style: "primary" },
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
      label: "View Account Info",
      mode: "modal",
      style: "secondary",
      modal: {
        title: "User Account Info",
        fields: [
          { id: "username", label: "Username", style: "short", required: true, placeholder: "contoh: alice" },
        ],
      },
    },
  ],
};
