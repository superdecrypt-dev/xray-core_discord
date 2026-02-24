import type { MenuDefinition } from "./types";

export const menu4: MenuDefinition = {
  id: "4",
  label: "Network Controls",
  description: "Ringkasan outbound, routing, DNS, dan status network.",
  actions: [
    { id: "egress_summary", label: "Egress Summary View", mode: "direct", style: "primary" },
    {
      id: "set_egress_mode",
      label: "Egress Mode Setup",
      mode: "modal",
      style: "secondary",
      modal: {
        title: "Set Egress Mode",
        fields: [{ id: "mode", label: "Mode", style: "short", required: true, placeholder: "direct / warp / balancer" }],
      },
    },
    {
      id: "set_balancer_strategy",
      label: "Balancer Strategy",
      mode: "modal",
      style: "secondary",
      modal: {
        title: "Set Balancer Strategy",
        fields: [
          {
            id: "strategy",
            label: "Strategy",
            style: "short",
            required: true,
            placeholder: "random / roundRobin / leastPing / leastLoad",
          },
        ],
      },
    },
    { id: "set_balancer_selector_auto", label: "Balancer Auto Sel", mode: "direct", style: "secondary" },
    {
      id: "set_balancer_selector",
      label: "Balancer Selector",
      mode: "modal",
      style: "secondary",
      modal: {
        title: "Set Balancer Selector",
        fields: [
          {
            id: "selector",
            label: "Selector",
            style: "short",
            required: true,
            placeholder: "auto atau direct,warp",
          },
        ],
      },
    },
    { id: "dns_summary", label: "DNS Summary View", mode: "direct", style: "secondary" },
    {
      id: "set_dns_primary",
      label: "Primary DNS Setup",
      mode: "modal",
      style: "secondary",
      modal: {
        title: "Set Primary DNS",
        fields: [{ id: "dns", label: "Primary DNS", style: "short", required: true, placeholder: "contoh: 1.1.1.1" }],
      },
    },
    {
      id: "set_dns_secondary",
      label: "Secondary DNS Set",
      mode: "modal",
      style: "secondary",
      modal: {
        title: "Set Secondary DNS",
        fields: [{ id: "dns", label: "Secondary DNS", style: "short", required: true, placeholder: "contoh: 8.8.8.8" }],
      },
    },
    {
      id: "set_dns_query_strategy",
      label: "DNS Query Strategy",
      mode: "modal",
      style: "secondary",
      modal: {
        title: "Set DNS Query Strategy",
        fields: [
          {
            id: "strategy",
            label: "Query Strategy",
            style: "short",
            required: true,
            placeholder: "UseIP/UseIPv4/UseIPv6/PreferIPv4/PreferIPv6",
          },
        ],
      },
    },
    { id: "toggle_dns_cache", label: "DNS Cache Toggle", mode: "direct", style: "secondary" },
    { id: "state_file", label: "State File View", mode: "direct", style: "secondary" },
  ],
};
