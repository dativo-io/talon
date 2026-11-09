import { useCallback, useEffect, useState } from "react";
import { getJSON, type Query } from "./client";

export interface ApiState<T> {
  data: T | null;
  error: Error | null;
  loading: boolean;
  reload: () => void;
}

interface Settled<T> {
  key: string;
  data: T | null;
  error: Error | null;
}

// requestKey identifies one request exactly: path plus every query value.
export function requestKey(path: string, query?: Query): string {
  const q = Object.entries(query ?? {})
    .filter(([, v]) => v !== undefined && v !== null && v !== "")
    .sort(([a], [b]) => a.localeCompare(b));
  return JSON.stringify([path, q]);
}

// useApi fetches path+query. A response is rendered only while its request
// key is the current one: when the scope, route or record changes, the page
// shows loading until the matching response arrives, so tenant A's rows or
// record X's detail never sit under tenant B's or record Y's heading. Stale
// requests are aborted, and a late answer for an old key is discarded. It
// does not poll.
export function useApi<T>(path: string | null, query?: Query): ApiState<T> {
  const key = path === null ? null : requestKey(path, query);
  const [settled, setSettled] = useState<Settled<T> | null>(null);
  const [tick, setTick] = useState(0);

  useEffect(() => {
    if (path === null || key === null) return;
    const ctrl = new AbortController();
    getJSON<T>(path, query, ctrl.signal)
      .then((d) => {
        if (!ctrl.signal.aborted) setSettled({ key, data: d, error: null });
      })
      .catch((e: unknown) => {
        if (!ctrl.signal.aborted) setSettled({ key, data: null, error: e instanceof Error ? e : new Error(String(e)) });
      });
    return () => ctrl.abort();
    // key captures path and query
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key, tick]);

  const reload = useCallback(() => setTick((t) => t + 1), []);
  const current = settled !== null && settled.key === key;
  return {
    data: current ? settled.data : null,
    error: current ? settled.error : null,
    loading: key !== null && !current,
    reload,
  };
}
