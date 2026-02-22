import type { MenuDefinition } from "./types";

export const menu5: MenuDefinition = {
  id: "5",
  label: "Domain Control",
  description: "Info domain aktif dan server_name nginx.",
  actions: [
    { id: "domain_info", label: "Domain Info", mode: "direct", style: "primary" },
    { id: "nginx_server_name", label: "Nginx Server Name", mode: "direct", style: "secondary" },
  ],
};
