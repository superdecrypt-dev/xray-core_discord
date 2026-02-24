import type { MenuDefinition } from "./types";

export const menu5: MenuDefinition = {
  id: "5",
  label: "Domain Control",
  description:
    "Atur domain aktif + sertifikat.\n" +
    "Manual: pakai domain sendiri yang sudah pointing ke IP VPS.\n" +
    "Auto: pakai root domain bawaan sistem (subdomain dibuat otomatis via API Cloudflare).",
  actions: [
    {
      id: "setup_domain_custom",
      label: "Set Domain Manual",
      mode: "modal",
      style: "danger",
      confirm: true,
      modal: {
        title: "Set Domain Manual",
        fields: [
          { id: "domain", label: "Domain (FQDN)", style: "short", required: true, placeholder: "vpn.example.com" },
        ],
      },
    },
    {
      id: "setup_domain_cloudflare",
      label: "Set Domain Auto",
      mode: "modal",
      style: "danger",
      confirm: true,
      modal: {
        title: "Set Domain Auto (API Cloudflare)",
        fields: [
          { id: "root_domain", label: "Root Domain", style: "short", required: true, placeholder: "1 atau vyxara1.web.id" },
          { id: "subdomain_mode", label: "Subdomain Mode", style: "short", required: false, placeholder: "auto / manual (default: auto)" },
          { id: "subdomain", label: "Subdomain", style: "short", required: false, placeholder: "Isi jika mode manual, contoh: vpn01" },
          { id: "proxied", label: "Cloudflare Proxy", style: "short", required: false, placeholder: "on / off (default: off)" },
          {
            id: "allow_existing_same_ip",
            label: "Lanjut jika ada A record dengan IP sama?",
            style: "short",
            required: false,
            placeholder: "on / off (default: off)",
          },
        ],
      },
    },
    { id: "domain_info", label: "View Domain Info", mode: "direct", style: "primary" },
    { id: "domain_guard_check", label: "Run Guard Check", mode: "direct", style: "secondary" },
    { id: "domain_guard_status", label: "View Guard Stat", mode: "direct", style: "secondary" },
    { id: "domain_guard_renew", label: "Run Guard Renew", mode: "direct", style: "danger", confirm: true },
    { id: "nginx_server_name", label: "View Nginx Name", mode: "direct", style: "secondary" },
    { id: "refresh_account_info", label: "Refresh Accounts", mode: "direct", style: "secondary" },
  ],
};
