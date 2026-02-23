import type { MenuDefinition } from "./types";

export const menu4: MenuDefinition = {
  id: "4",
  label: "Network Controls",
  description: "Ringkasan outbound, routing, DNS, dan status network.",
  actions: [
    { id: "egress_summary", label: "Egress Summary", mode: "direct", style: "primary" },
    { id: "dns_summary", label: "DNS Summary", mode: "direct", style: "secondary" },
    { id: "state_file", label: "State File", mode: "direct", style: "secondary" },
  ],
};
