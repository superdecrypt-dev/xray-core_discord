import type { MenuDefinition } from "./types";

export const menu2: MenuDefinition = {
  id: "2",
  label: "User Management",
  description: "Lihat daftar user dan pencarian user.",
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
  ],
};
