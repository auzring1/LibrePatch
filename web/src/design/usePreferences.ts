import { useCallback } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, type Preferences } from "../api/client";
import { useSession } from "../api/session";

/** The signed-in person's saved preferences (kept on the account, shared with the appearance provider's cache entry). */
export function usePreferences() {
  const { session } = useSession();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["preferences"], queryFn: () => api<Preferences>("GET", "/me/preferences"), enabled: !!session, staleTime: 5 * 60_000 });
  const save = useMutation({
    mutationFn: (next: Preferences) => api<Preferences>("PUT", "/me/preferences", next),
    onMutate: async (next) => {
      await qc.cancelQueries({ queryKey: ["preferences"] });
      const prev = qc.getQueryData<Preferences>(["preferences"]);
      qc.setQueryData(["preferences"], next);
      return { prev };
    },
    onError: (_e, _n, ctx) => ctx?.prev && qc.setQueryData(["preferences"], ctx.prev),
    onSuccess: (saved) => qc.setQueryData(["preferences"], saved),
  });
  const prefs = q.data;
  /** Saves a change on top of what is cached now. Nothing is sent before the stored copy has arrived. */
  const update = useCallback(
    (patch: Partial<Preferences>) => {
      const cur = qc.getQueryData<Preferences>(["preferences"]);
      if (!cur) return;
      save.mutate({ ...cur, ...patch });
    },
    [qc, save],
  );
  return { prefs, ready: !!prefs, update };
}
