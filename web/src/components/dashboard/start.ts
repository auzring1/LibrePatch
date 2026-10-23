import type { Dashboard } from "../../api/client";

export interface StartStep {
  id: string;
  title: string;
  text: string;
  to: string;
  cta: string;
  done: boolean;
}

/**
 * The first things worth doing, as a checklist on the dashboard. A step is offered only to someone who may do it and only
 * when the dashboard has the numbers to tell whether it is done.
 */
export function startSteps(d: Dashboard, canOrg: (perm: string) => boolean): StartStep[] {
  const steps: StartStep[] = [];
  if (d.devices && canOrg("enrollment:read")) {
    steps.push({
      id: "device",
      title: "Add your first computer",
      text: "Make an enrollment token and install the agent on a Windows PC. It then appears under Devices.",
      to: "/enrollment",
      cta: "Add devices",
      done: (d.devices.total ?? 0) + (d.devices.pending ?? 0) > 0,
    });
  }
  if (d.setup && canOrg("policies:write")) {
    steps.push({
      id: "policy",
      title: "Let your apps update themselves",
      text: "One policy can keep every app current, with a delay, stages through your rings and your approval if you want them.",
      to: "/automations",
      cta: "Open Automations",
      done: d.setup.policies > 0,
    });
  }
  if (d.setup && canOrg("deployments:write")) {
    steps.push({
      id: "deploy",
      title: "Install or update something once",
      text: "Software updates lists the apps that have a newer version. Pick some and deploy them to see how a deployment goes.",
      to: "/software-updates",
      cta: "Open Software updates",
      done: d.setup.deployments > 0,
    });
  }
  return steps;
}

/** Whether the checklist is worth showing: there is a step left to do and the person has not put it away. */
export const startVisible = (steps: StartStep[], dismissed: boolean) => !dismissed && steps.some((s) => !s.done);

const KEY = "lp-start-dismissed";

/** The checklist is put away per browser (a convenience, not a setting). */
export function readStartDismissed(): boolean {
  try {
    return window.localStorage.getItem(KEY) === "1";
  } catch {
    return false;
  }
}

export function writeStartDismissed(v: boolean): void {
  try {
    if (v) window.localStorage.setItem(KEY, "1");
    else window.localStorage.removeItem(KEY);
  } catch {
    /* private mode: it comes back next time */
  }
}
