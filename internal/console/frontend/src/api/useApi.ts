import { useCallback, useEffect, useRef, useState } from "react";
import { getJSON, type Query } from "./client";

export interface ApiState<T> {
  data: T | null;
  error: Error | null;
  loading: boolean;
  reload: () => void;
}

// useApi fetches path+query, aborting the previous request whenever the
// inputs change so a slow answer for an old scope never replaces the
// current view. It does not poll.
export function useApi<T>(path: string | null, query?: Query): ApiState<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<Error | null>(null);
  const [loading, setLoading] = useState<boolean>(path !== null);
  const [tick, setTick] = useState(0);
  const key = path === null ? null : JSON.stringify([path, query ?? {}]);
  const current = useRef<string | null>(null);

  useEffect(() => {
    if (path === null || key === null) return;
    const ctrl = new AbortController();
    current.current = key;
    setLoading(true);
    setError(null);
    getJSON<T>(path, query, ctrl.signal)
      .then((d) => {
        if (current.current === key) setData(d);
      })
      .catch((e: unknown) => {
        if (ctrl.signal.aborted) return;
        if (current.current === key) {
          setError(e instanceof Error ? e : new Error(String(e)));
          setData(null);
        }
      })
      .finally(() => {
        if (!ctrl.signal.aborted && current.current === key) setLoading(false);
      });
    return () => ctrl.abort();
    // key captures path and query
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key, tick]);

  const reload = useCallback(() => setTick((t) => t + 1), []);
  return { data, error, loading, reload };
}
