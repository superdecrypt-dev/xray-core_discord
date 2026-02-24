import { randomBytes } from "crypto";

interface UserContextEntry {
  proto: string;
  username: string;
  expiresAt: number;
}

const EXPIRE_MS = 10 * 60 * 1000;
const MAX_ENTRIES = 4096;
const store = new Map<string, UserContextEntry>();

function nowMs(): number {
  return Date.now();
}

function cleanup(): void {
  const now = nowMs();
  for (const [token, entry] of store.entries()) {
    if (entry.expiresAt <= now) {
      store.delete(token);
    }
  }
  if (store.size <= MAX_ENTRIES) {
    return;
  }
  const overflow = store.size - MAX_ENTRIES;
  let removed = 0;
  for (const token of store.keys()) {
    store.delete(token);
    removed += 1;
    if (removed >= overflow) {
      break;
    }
  }
}

export function createUserContextToken(proto: string, username: string): string {
  cleanup();
  const token = `uctx_${randomBytes(8).toString("hex")}`;
  store.set(token, {
    proto: String(proto || "").trim().toLowerCase(),
    username: String(username || "").trim(),
    expiresAt: nowMs() + EXPIRE_MS,
  });
  return token;
}

export function isUserContextToken(raw: string): boolean {
  return String(raw || "").trim().startsWith("uctx_");
}

export function resolveUserContext(raw: string, protoHint = ""): { proto: string; username: string } | null {
  cleanup();
  const source = String(raw || "").trim();
  if (!source) {
    return null;
  }
  const protoNormalized = String(protoHint || "").trim().toLowerCase();
  if (!isUserContextToken(source)) {
    return { proto: protoNormalized, username: source };
  }

  const entry = store.get(source);
  if (!entry || entry.expiresAt <= nowMs()) {
    store.delete(source);
    return null;
  }
  if (protoNormalized && entry.proto && entry.proto !== protoNormalized) {
    return null;
  }
  return { proto: entry.proto || protoNormalized, username: entry.username };
}
