import type { MenuDefinition } from "./types";

export const menu7: MenuDefinition = {
  id: "7",
  label: "Security",
  description: "Status fail2ban dan parameter hardening kernel.",
  actions: [
    { id: "fail2ban_status", label: "Fail2ban Status", mode: "direct", style: "primary" },
    { id: "sysctl_summary", label: "Sysctl Summary View", mode: "direct", style: "secondary" },
  ],
};
