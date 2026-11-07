import { useEffect } from "react";
import { useQueryClient } from "@tanstack/react-query";

/** Subscribes to server-sent device events and refreshes affected queries. */
export function useLiveEvents(enabled: boolean) {
  const qc = useQueryClient();
  useEffect(() => {
    if (!enabled) return;
    const es = new EventSource("/api/v1/events");
    const onEvent = (ev: MessageEvent<string>) => {
      try {
        const e = JSON.parse(ev.data) as { type: string; device_id?: string; job_id?: string; deployment_id?: string };
        if (e.type === "updates.updated") {
          void qc.invalidateQueries({ queryKey: ["updates"] });
          void qc.invalidateQueries({ queryKey: ["update-policy"] });
          if (e.device_id) void qc.invalidateQueries({ queryKey: ["device", e.device_id, "wu"] });
          return;
        }
        if (e.type === "job.updated" || e.type === "deployment.updated") {
          void qc.invalidateQueries({ queryKey: ["deployments"] });
          if (e.deployment_id) void qc.invalidateQueries({ queryKey: ["deployment", e.deployment_id] });
          if (e.job_id) void qc.invalidateQueries({ queryKey: ["job", e.job_id] });
          if (e.device_id) void qc.invalidateQueries({ queryKey: ["device-jobs", e.device_id] });
          void qc.invalidateQueries({ queryKey: ["software"] });
          return;
        }
        void qc.invalidateQueries({ queryKey: ["devices"] });
        void qc.invalidateQueries({ queryKey: ["device", e.device_id] });
        void qc.invalidateQueries({ queryKey: ["software"] });
      } catch {
        /* ignore malformed events */
      }
    };
    for (const t of ["device.online", "device.offline", "device.enrolled", "device.updated", "job.updated", "deployment.updated", "updates.updated"]) {
      es.addEventListener(t, onEvent as EventListener);
    }
    return () => es.close();
  }, [enabled, qc]);
}
