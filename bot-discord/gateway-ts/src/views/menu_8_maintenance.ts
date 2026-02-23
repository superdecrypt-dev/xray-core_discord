import type { MenuDefinition } from "./types";

export const menu8: MenuDefinition = {
  id: "8",
  label: "Maintenance",
  description: "Status layanan dan restart layanan.",
  actions: [
    { id: "service_status", label: "Service Status", mode: "direct", style: "primary" },
    { id: "restart_xray", label: "Restart Xray", mode: "direct", style: "danger", confirm: true },
    { id: "restart_nginx", label: "Restart Nginx", mode: "direct", style: "danger", confirm: true },
  ],
};
