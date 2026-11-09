// Same-origin JSON client for the console API. The browser credential is
// the HttpOnly session cookie the server set at pairing; nothing here reads
// or stores a credential. A 401 with console_session_required means the
// session ended (expired, logged out elsewhere, console restarted): the app
// returns to pairing and keeps the page the operator was on.

export class ApiError extends Error {
  readonly status: number;
  readonly reason: string;

  constructor(status: number, reason: string, message: string) {
    super(message);
    this.status = status;
    this.reason = reason;
  }

  get sessionEnded(): boolean {
    return this.status === 401 && this.reason === "console_session_required";
  }
}

type Listener = () => void;
const sessionEndedListeners = new Set<Listener>();

export function onSessionEnded(fn: Listener): () => void {
  sessionEndedListeners.add(fn);
  return () => sessionEndedListeners.delete(fn);
}

async function parse<T>(res: Response): Promise<T> {
  const text = await res.text();
  let body: unknown = null;
  if (text) {
    try {
      body = JSON.parse(text);
    } catch {
      body = null;
    }
  }
  if (!res.ok) {
    const env = (body ?? {}) as { error?: string; message?: string };
    const err = new ApiError(res.status, env.error ?? `http_${res.status}`, env.message ?? `HTTP ${res.status}`);
    if (err.sessionEnded) sessionEndedListeners.forEach((fn) => fn());
    throw err;
  }
  return body as T;
}

export type Query = Record<string, string | number | undefined | null>;

export function withQuery(path: string, query?: Query): string {
  if (!query) return path;
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries(query)) {
    if (v !== undefined && v !== null && v !== "") params.set(k, String(v));
  }
  const qs = params.toString();
  return qs ? `${path}?${qs}` : path;
}

export async function getJSON<T>(path: string, query?: Query, signal?: AbortSignal): Promise<T> {
  const res = await fetch(withQuery(path, query), {
    method: "GET",
    credentials: "same-origin",
    headers: { Accept: "application/json" },
    signal,
  });
  return parse<T>(res);
}

export async function postJSON<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(path, {
    method: "POST",
    credentials: "same-origin",
    headers: { Accept: "application/json", "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return parse<T>(res);
}

export const api = (path: string) => `/console/v1${path}`;
