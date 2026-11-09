import { useSearchParams } from "react-router-dom";

// Shareable, non-sensitive scope lives in the URL: tenant and use case.
// Nothing secret is ever placed in a query string.
export function useScope() {
  const [params, setParams] = useSearchParams();
  const tenant = params.get("tenant") ?? "";
  const set = (key: string, value: string) => {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    setParams(next, { replace: true });
  };
  return { tenant, params, set };
}

// scoped appends the current tenant to an in-app link.
export function scoped(path: string, tenant: string, extra?: Record<string, string | undefined>): string {
  const p = new URLSearchParams();
  if (tenant) p.set("tenant", tenant);
  for (const [k, v] of Object.entries(extra ?? {})) if (v) p.set(k, v);
  const qs = p.toString();
  return qs ? `${path}?${qs}` : path;
}
