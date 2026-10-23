import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Popover } from "@mantine/core";
import { api, type Notification } from "../api/client";
import { toast } from "./notify";
import { ago } from "../api/format";
import { useSession } from "../api/session";
import * as I from "./icons";

const ICON: Record<string, typeof I.Warning> = { failed_job: I.Danger, held_update: I.NavHeld };

type Bell = { items: Notification[]; total: number };

/** The bell: failed jobs (24 h), and held updates that the signed-in person may act on. Each item can be dismissed (for this person only). */
export function NotificationsBell() {
  const { session } = useSession();
  const qc = useQueryClient();
  const [open, setOpen] = useState(false);
  const q = useQuery({
    queryKey: ["notifications"],
    queryFn: () => api<{ items: Notification[]; total: number }>("GET", "/notifications"),
    enabled: !!session,
    refetchInterval: 60_000,
    refetchOnWindowFocus: true,
  });
  // Dismissing is instant on screen; the server remembers it for this person.
  const dismiss = useMutation({
    mutationFn: (body: { ids: string[] } | { all: true }) => api("POST", "/notifications/dismiss", body),
    onMutate: async (body) => {
      await qc.cancelQueries({ queryKey: ["notifications"] });
      const before = qc.getQueryData<Bell>(["notifications"]);
      if (before) {
        const keep = "all" in body ? [] : before.items.filter((i) => !body.ids.includes(i.id ?? ""));
        qc.setQueryData<Bell>(["notifications"], { items: keep, total: keep.length });
      }
      return { before };
    },
    onError: (e, _body, ctx) => {
      if (ctx?.before) qc.setQueryData(["notifications"], ctx.before);
      toast.error(e instanceof Error ? e.message : "Could not dismiss.");
    },
    onSettled: () => void qc.invalidateQueries({ queryKey: ["notifications"] }),
  });
  const items = q.data?.items ?? [];
  const n = items.length;
  const worst = items.some((i) => i.severity === "critical") ? "critical" : items.some((i) => i.severity === "warning") ? "warning" : "info";
  return (
    <Popover opened={open} onChange={setOpen} position="bottom-end" width={380} shadow="md" withinPortal trapFocus={false}>
      <Popover.Target>
        <button type="button" className="lp-bell" aria-expanded={open} aria-haspopup="dialog" onClick={() => setOpen((o) => !o)} aria-label={n ? `Notifications, ${n} need attention` : "Notifications, none"} data-testid="notifications">
          {n ? <I.BellRinging size={20} aria-hidden /> : <I.Bell size={20} aria-hidden />}
          {n > 0 && (
            <span className="lp-bell__count" data-severity={worst} aria-hidden="true">
              {n > 9 ? "9+" : n}
            </span>
          )}
        </button>
      </Popover.Target>
      <Popover.Dropdown p={0} aria-label="Notifications">
        <div className="lp-note__head">
          <div className="lp-note__heading">Needs attention</div>
          {n > 1 && (
            <button type="button" className="lp-note__all" onClick={() => dismiss.mutate({ all: true })}>
              Dismiss all
            </button>
          )}
        </div>
        {q.isError && <div className="lp-search__none">Could not load notifications.</div>}
        {!q.isError && n === 0 && <div className="lp-search__none">{q.isLoading ? "Loading…" : "You are all caught up."}</div>}
        {items.map((i) => {
          const Icon = (i.kind && ICON[i.kind]) || I.Info;
          return (
            <div className="lp-note" key={i.id ?? i.title}>
              <Link to={i.to ?? "/"} className="lp-note__link" onClick={() => setOpen(false)}>
                <Icon size={16} aria-hidden />
                <span>
                  <span className="lp-note__title">{i.title}</span>
                  <span className="lp-note__meta">
                    {i.severity === "critical" ? "Critical · " : i.severity === "warning" ? "Warning · " : ""}
                    {i.detail ? `${i.detail} · ` : ""}
                    {ago(i.at ?? null)}
                  </span>
                </span>
              </Link>
              {i.id && (
                <button type="button" className="lp-note__dismiss" aria-label={`Dismiss: ${i.title}`} title="Dismiss" onClick={() => dismiss.mutate({ ids: [i.id!] })}>
                  <I.Close size={14} aria-hidden />
                </button>
              )}
            </div>
          );
        })}
      </Popover.Dropdown>
    </Popover>
  );
}
