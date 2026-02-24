import type { MenuDefinition } from "./types";

export const menu12: MenuDefinition = {
  id: "12",
  label: "Traffic Analytics",
  description: "Analitik traffic user berdasarkan metadata quota (overview, top users, search, dan export).",
  actions: [
    { id: "overview", label: "View Overview", mode: "direct", style: "primary" },
    {
      id: "top_users",
      label: "View Top Users",
      mode: "modal",
      style: "secondary",
      modal: {
        title: "Top Users by Usage",
        fields: [{ id: "limit", label: "Limit", style: "short", required: true, placeholder: "15 (maks 200)" }],
      },
    },
    {
      id: "search_user",
      label: "Search User",
      mode: "modal",
      style: "secondary",
      modal: {
        title: "Search User Traffic",
        fields: [{ id: "query", label: "Keyword", style: "short", required: true, placeholder: "alice atau vless" }],
      },
    },
    { id: "export_json", label: "Export JSON", mode: "direct", style: "secondary" },
  ],
};
