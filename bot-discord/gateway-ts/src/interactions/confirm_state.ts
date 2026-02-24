import { randomBytes } from "crypto";

export interface PendingConfirmPayload {
  menuId: string;
  actionId: string;
  params: Record<string, string>;
}

interface PendingConfirmEntry extends PendingConfirmPayload {
  createdAtMs: number;
}

const EXPIRE_MS = 5 * 60 * 1000;
const MAX_ENTRIES = 512;
const store = new Map<string, PendingConfirmEntry>();

function nowMs(): number {
  return Date.now();
}

function cleanup(): void {
  const cutoff = nowMs() - EXPIRE_MS;
  for (const [token, entry] of store.entries()) {
    if (entry.createdAtMs < cutoff) {
      store.delete(token);
    }
  }

  if (store.size <= MAX_ENTRIES) {
    return;
  }

  const ordered = [...store.entries()].sort((a, b) => a[1].createdAtMs - b[1].createdAtMs);
  const toRemove = store.size - MAX_ENTRIES;
  for (let i = 0; i < toRemove; i += 1) {
    store.delete(ordered[i][0]);
  }
}

export function createPendingConfirm(payload: PendingConfirmPayload): string {
  cleanup();
  let token = "";
  do {
    token = randomBytes(9).toString("base64url");
  } while (store.has(token));

  store.set(token, {
    ...payload,
    createdAtMs: nowMs(),
  });
  return token;
}

export function consumePendingConfirm(token: string): PendingConfirmPayload | null {
  cleanup();
  const entry = store.get(token);
  if (!entry) {
    return null;
  }
  store.delete(token);

  if (entry.createdAtMs + EXPIRE_MS < nowMs()) {
    return null;
  }
  return {
    menuId: entry.menuId,
    actionId: entry.actionId,
    params: entry.params,
  };
}
