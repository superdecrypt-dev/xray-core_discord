import type { MenuDefinition } from "./types";

export const menu1: MenuDefinition = {
  id: "1",
  label: "Status & Diagnostics",
  description: "Status server, validasi konfigurasi Xray, dan informasi TLS.",
  actions: [
    { id: "overview", label: "View Status", mode: "direct", style: "primary" },
    { id: "xray_test", label: "Run Xray Test", mode: "direct", style: "secondary" },
    { id: "tls_info", label: "View TLS Info", mode: "direct", style: "secondary" },
    { id: "observe_snapshot", label: "Run Observe Snap", mode: "direct", style: "secondary" },
    { id: "observe_status", label: "View Observe Stat", mode: "direct", style: "secondary" },
    { id: "observe_alert_log", label: "View Alert Log", mode: "direct", style: "secondary" },
  ],
};
