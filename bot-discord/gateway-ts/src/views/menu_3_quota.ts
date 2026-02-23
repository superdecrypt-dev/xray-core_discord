import type { MenuDefinition } from "./types";

export const menu3: MenuDefinition = {
  id: "3",
  label: "Quota & Access Control",
  description: "Ringkasan, detail, dan kontrol quota/manual block/IP limit/speed limit per user.",
  actions: [
    { id: "summary", label: "Quota Summary", mode: "direct", style: "primary" },
    {
      id: "detail",
      label: "Quota Detail",
      mode: "modal",
      style: "secondary",
      modal: {
        title: "Quota Detail",
        fields: [
          { id: "proto", label: "Protocol", style: "short", required: true, placeholder: "vless/vmess/trojan" },
          { id: "username", label: "Username", style: "short", required: true, placeholder: "contoh: alice" },
        ],
      },
    },
    {
      id: "set_quota_limit",
      label: "Set Quota Limit",
      mode: "modal",
      style: "secondary",
      modal: {
        title: "Set Quota Limit",
        fields: [
          { id: "proto", label: "Protocol", style: "short", required: true, placeholder: "vless/vmess/trojan" },
          { id: "username", label: "Username", style: "short", required: true, placeholder: "alice" },
          { id: "quota_gb", label: "Quota GB", style: "short", required: true, placeholder: "100" },
        ],
      },
    },
    {
      id: "reset_quota_used",
      label: "Reset Quota Used",
      mode: "modal",
      style: "danger",
      confirm: true,
      modal: {
        title: "Reset Quota Used",
        fields: [
          { id: "proto", label: "Protocol", style: "short", required: true, placeholder: "vless/vmess/trojan" },
          { id: "username", label: "Username", style: "short", required: true, placeholder: "alice" },
        ],
      },
    },
    {
      id: "manual_block",
      label: "Manual Block ON/OFF",
      mode: "modal",
      style: "danger",
      modal: {
        title: "Manual Block",
        fields: [
          { id: "proto", label: "Protocol", style: "short", required: true, placeholder: "vless/vmess/trojan" },
          { id: "username", label: "Username", style: "short", required: true, placeholder: "alice" },
          { id: "enabled", label: "Enabled", style: "short", required: true, placeholder: "on / off" },
        ],
      },
    },
    {
      id: "ip_limit_enable",
      label: "IP Limit ON/OFF",
      mode: "modal",
      style: "secondary",
      modal: {
        title: "IP Limit Enable/Disable",
        fields: [
          { id: "proto", label: "Protocol", style: "short", required: true, placeholder: "vless/vmess/trojan" },
          { id: "username", label: "Username", style: "short", required: true, placeholder: "alice" },
          { id: "enabled", label: "Enabled", style: "short", required: true, placeholder: "on / off" },
        ],
      },
    },
    {
      id: "set_ip_limit",
      label: "Set IP Limit",
      mode: "modal",
      style: "secondary",
      modal: {
        title: "Set IP Limit",
        fields: [
          { id: "proto", label: "Protocol", style: "short", required: true, placeholder: "vless/vmess/trojan" },
          { id: "username", label: "Username", style: "short", required: true, placeholder: "alice" },
          { id: "ip_limit", label: "IP Limit", style: "short", required: true, placeholder: "2" },
        ],
      },
    },
    {
      id: "unlock_ip_lock",
      label: "Unlock IP Lock",
      mode: "modal",
      style: "secondary",
      modal: {
        title: "Unlock IP Lock",
        fields: [
          { id: "proto", label: "Protocol", style: "short", required: true, placeholder: "vless/vmess/trojan" },
          { id: "username", label: "Username", style: "short", required: true, placeholder: "alice" },
        ],
      },
    },
    {
      id: "set_speed_download",
      label: "Set Speed Download",
      mode: "modal",
      style: "secondary",
      modal: {
        title: "Set Speed Download",
        fields: [
          { id: "proto", label: "Protocol", style: "short", required: true, placeholder: "vless/vmess/trojan" },
          { id: "username", label: "Username", style: "short", required: true, placeholder: "alice" },
          { id: "speed_down_mbit", label: "Speed Down Mbps", style: "short", required: true, placeholder: "20" },
        ],
      },
    },
    {
      id: "set_speed_upload",
      label: "Set Speed Upload",
      mode: "modal",
      style: "secondary",
      modal: {
        title: "Set Speed Upload",
        fields: [
          { id: "proto", label: "Protocol", style: "short", required: true, placeholder: "vless/vmess/trojan" },
          { id: "username", label: "Username", style: "short", required: true, placeholder: "alice" },
          { id: "speed_up_mbit", label: "Speed Up Mbps", style: "short", required: true, placeholder: "10" },
        ],
      },
    },
    {
      id: "speed_limit",
      label: "Speed Limit ON/OFF",
      mode: "modal",
      style: "secondary",
      modal: {
        title: "Speed Limit Enable/Disable",
        fields: [
          { id: "proto", label: "Protocol", style: "short", required: true, placeholder: "vless/vmess/trojan" },
          { id: "username", label: "Username", style: "short", required: true, placeholder: "alice" },
          { id: "enabled", label: "Enabled", style: "short", required: true, placeholder: "on / off" },
        ],
      },
    },
  ],
};
