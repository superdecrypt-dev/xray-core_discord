import type { MenuDefinition } from "./types";

export const menu7: MenuDefinition = {
  id: "7",
  label: "Security",
  description: "Status fail2ban dan parameter hardening kernel.",
  actions: [
    { id: "fail2ban_status", label: "View Fail2ban", mode: "direct", style: "primary" },
    { id: "sysctl_summary", label: "View Sysctl", mode: "direct", style: "secondary" },
  ],
};
