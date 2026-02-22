import type { MenuDefinition } from "./types";

export const menu1: MenuDefinition = {
  id: "1",
  label: "Status & Diagnostics",
  description: "Cek status server, tes config Xray, dan info TLS.",
  actions: [
    { id: "overview", label: "Ringkasan Status", mode: "direct", style: "primary" },
    { id: "xray_test", label: "Test Config Xray", mode: "direct", style: "secondary" },
    { id: "tls_info", label: "TLS Info", mode: "direct", style: "secondary" },
  ],
};
