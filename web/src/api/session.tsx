import { createContext, useContext, type ReactNode } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError, setCsrf, type SessionInfo } from "./client";

interface SessionCtx {
  session: SessionInfo | null;
  loading: boolean;
  /** Holds the permission organization-wide. Use for pages and actions that need an org-wide role. */
  canOrg: (perm: string) => boolean;
  /** Holds the permission organization-wide or for some sites (device pages). */
  can: (perm: string) => boolean;
  refresh: () => Promise<unknown>;
}

const Ctx = createContext<SessionCtx>({ session: null, loading: true, can: () => false, canOrg: () => false, refresh: async () => undefined });

export function SessionProvider({ children }: { children: ReactNode }) {
  const qc = useQueryClient();
  const q = useQuery({
    queryKey: ["session"],
    queryFn: async () => {
      try {
        const s = await api<SessionInfo>("GET", "/auth/session");
        setCsrf(s.csrf_token);
        return s;
      } catch (e) {
        if (e instanceof ApiError && e.status === 401) return null;
        throw e;
      }
    },
    retry: false,
    staleTime: 60_000,
  });
  const session = q.data ?? null;
  return (
    <Ctx.Provider
      value={{
        session,
        loading: q.isLoading,
        canOrg: (p) => !!session?.permissions.includes(p),
        can: (p) => !!session?.permissions.includes(p) || !!session?.scoped_permissions?.includes(p),
        refresh: () => qc.invalidateQueries({ queryKey: ["session"] }),
      }}
    >
      {children}
    </Ctx.Provider>
  );
}

export const useSession = () => useContext(Ctx);
