import type { MenuDefinition } from "./types";

export const menu6: MenuDefinition = {
  id: "6",
  label: "Speedtest",
  description: "Pengujian kecepatan jaringan dan versi binary.",
  actions: [
    { id: "run", label: "Run Speedtest Now", mode: "direct", style: "primary" },
    { id: "version", label: "Speedtest Version", mode: "direct", style: "secondary" },
  ],
};
