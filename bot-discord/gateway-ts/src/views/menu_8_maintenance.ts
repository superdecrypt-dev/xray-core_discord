import type { MenuDefinition } from "./types";

export const menu8: MenuDefinition = {
  id: "8",
  label: "Maintenance",
  description: "Status service, restart service, dan tail logs.",
  actions: [
    { id: "service_status", label: "Service Status", mode: "direct", style: "primary" },
    { id: "restart_xray", label: "Restart Xray", mode: "direct", style: "danger", confirm: true },
    { id: "restart_nginx", label: "Restart Nginx", mode: "direct", style: "danger", confirm: true },
    {
      id: "tail_log",
      label: "Tail Logs",
      mode: "modal",
      style: "secondary",
      modal: {
        title: "Tail Service Logs",
        fields: [
          { id: "service", label: "Service Name", style: "short", required: true, placeholder: "xray/nginx/wireproxy" },
          { id: "lines", label: "Lines", style: "short", required: false, placeholder: "80" },
        ],
      },
    },
  ],
};
