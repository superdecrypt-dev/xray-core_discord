import type { MenuDefinition } from "./types";

export const menu5: MenuDefinition = {
  id: "5",
  label: "Domain Control",
  description: "Konfigurasi domain custom/Cloudflare dan informasi domain aktif.",
  actions: [
    { id: "cloudflare_root_list", label: "Cloudflare Root List", mode: "direct", style: "secondary" },
    {
      id: "setup_domain_custom",
      label: "Set Domain Custom",
      mode: "modal",
      style: "danger",
      confirm: true,
      modal: {
        title: "Set Domain Custom",
        fields: [
          { id: "domain", label: "Domain", style: "short", required: true, placeholder: "vpn.example.com" },
        ],
      },
    },
    {
      id: "setup_domain_cloudflare",
      label: "Set Domain Cloudflare",
      mode: "modal",
      style: "danger",
      confirm: true,
      modal: {
        title: "Cloudflare Domain Wizard",
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
    {
      id: "set_domain",
      label: "Set Domain Legacy",
      mode: "modal",
      style: "danger",
      confirm: true,
      modal: {
        title: "Set Domain Legacy",
        fields: [
          { id: "domain", label: "Domain", style: "short", required: true, placeholder: "vpn.example.com" },
          { id: "issue_cert", label: "Issue Cert", style: "short", required: false, placeholder: "on / off (default off)" },
        ],
      },
    },
    { id: "domain_info", label: "Domain Info", mode: "direct", style: "primary" },
    { id: "nginx_server_name", label: "Nginx Server Name", mode: "direct", style: "secondary" },
    { id: "refresh_account_info", label: "Refresh Account Info", mode: "direct", style: "secondary" },
  ],
};
