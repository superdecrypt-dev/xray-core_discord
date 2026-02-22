import type { MenuDefinition } from "./types";

export const menu6: MenuDefinition = {
  id: "6",
  label: "Speedtest",
  description: "Speedtest Ookla dan versi binary.",
  actions: [
    { id: "run", label: "Run Speedtest", mode: "direct", style: "primary" },
    { id: "version", label: "Speedtest Version", mode: "direct", style: "secondary" },
  ],
};
