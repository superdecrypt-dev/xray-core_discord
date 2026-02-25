import fs from "node:fs";
import path from "node:path";

interface ChannelPolicySnapshot {
  control_channel_id?: string;
  auto_status_enabled?: boolean;
  auto_status_interval_minutes?: number;
  last_auto_status_at?: string;
  updated_at?: string;
}

const DEFAULT_AUTO_STATUS_ENABLED = false;
const DEFAULT_AUTO_STATUS_INTERVAL_MINUTES = 10;
const MIN_INTERVAL_MINUTES = 1;
const MAX_INTERVAL_MINUTES = 1_440;

function sanitizeChannelId(value: unknown): string | null {
  const raw = String(value ?? "").trim();
  if (!raw) return null;
  return /^[0-9]{5,30}$/.test(raw) ? raw : null;
}

function sanitizeIntervalMinutes(value: unknown): number {
  const raw = Number(value);
  if (!Number.isFinite(raw)) return DEFAULT_AUTO_STATUS_INTERVAL_MINUTES;
  const rounded = Math.floor(raw);
  if (rounded < MIN_INTERVAL_MINUTES) return MIN_INTERVAL_MINUTES;
  if (rounded > MAX_INTERVAL_MINUTES) return MAX_INTERVAL_MINUTES;
  return rounded;
}

function sanitizeBoolean(value: unknown, fallback: boolean): boolean {
  if (typeof value === "boolean") return value;
  return fallback;
}

export class ChannelPolicyStore {
  private controlChannelId: string | null = null;
  private autoStatusEnabled = DEFAULT_AUTO_STATUS_ENABLED;
  private autoStatusIntervalMinutes = DEFAULT_AUTO_STATUS_INTERVAL_MINUTES;
  private lastAutoStatusAt: string | null = null;
  private readonly filePath: string;

  constructor(filePath: string) {
    this.filePath = path.resolve(filePath);
    this.load();
  }

  getControlChannelId(): string | null {
    return this.controlChannelId;
  }

  getAutoStatusEnabled(): boolean {
    return this.autoStatusEnabled;
  }

  getAutoStatusIntervalMinutes(): number {
    return this.autoStatusIntervalMinutes;
  }

  getLastAutoStatusAt(): string | null {
    return this.lastAutoStatusAt;
  }

  update(params: { channelId?: string | null; enabled?: boolean; intervalMinutes?: number }): void {
    if (params.channelId !== undefined) {
      if (params.channelId === null) {
        this.controlChannelId = null;
      } else {
        const normalized = sanitizeChannelId(params.channelId);
        if (!normalized) {
          throw new Error("channel id tidak valid");
        }
        this.controlChannelId = normalized;
      }
    }
    if (params.enabled !== undefined) {
      this.autoStatusEnabled = sanitizeBoolean(params.enabled, this.autoStatusEnabled);
    }
    if (params.intervalMinutes !== undefined) {
      this.autoStatusIntervalMinutes = sanitizeIntervalMinutes(params.intervalMinutes);
    }
    this.persist();
  }

  markAutoStatusSent(isoTime: string): void {
    this.lastAutoStatusAt = String(isoTime || "").trim() || null;
    this.persist();
  }

  private load(): void {
    try {
      if (!fs.existsSync(this.filePath)) {
        this.controlChannelId = null;
        this.autoStatusEnabled = DEFAULT_AUTO_STATUS_ENABLED;
        this.autoStatusIntervalMinutes = DEFAULT_AUTO_STATUS_INTERVAL_MINUTES;
        this.lastAutoStatusAt = null;
        return;
      }
      const raw = fs.readFileSync(this.filePath, "utf-8");
      const obj = JSON.parse(raw) as ChannelPolicySnapshot;
      this.controlChannelId = sanitizeChannelId(obj?.control_channel_id);
      this.autoStatusEnabled = sanitizeBoolean(obj?.auto_status_enabled, DEFAULT_AUTO_STATUS_ENABLED);
      this.autoStatusIntervalMinutes = sanitizeIntervalMinutes(obj?.auto_status_interval_minutes);
      this.lastAutoStatusAt = String(obj?.last_auto_status_at ?? "").trim() || null;
    } catch {
      this.controlChannelId = null;
      this.autoStatusEnabled = DEFAULT_AUTO_STATUS_ENABLED;
      this.autoStatusIntervalMinutes = DEFAULT_AUTO_STATUS_INTERVAL_MINUTES;
      this.lastAutoStatusAt = null;
    }
  }

  private persist(): void {
    const dir = path.dirname(this.filePath);
    fs.mkdirSync(dir, { recursive: true });
    const tmpPath = `${this.filePath}.tmp`;
    const payload: ChannelPolicySnapshot = {
      control_channel_id: this.controlChannelId ?? undefined,
      auto_status_enabled: this.autoStatusEnabled,
      auto_status_interval_minutes: this.autoStatusIntervalMinutes,
      last_auto_status_at: this.lastAutoStatusAt ?? undefined,
      updated_at: new Date().toISOString(),
    };
    fs.writeFileSync(tmpPath, JSON.stringify(payload, null, 2), "utf-8");
    fs.renameSync(tmpPath, this.filePath);
  }
}
