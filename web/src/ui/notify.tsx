import { notifications } from "@mantine/notifications";
import { Danger, Info, Success, Warning } from "./icons";

type Kind = "success" | "error" | "info" | "warning";

const look = {
  success: { color: "green", icon: <Success size={18} aria-hidden /> },
  error: { color: "red", icon: <Danger size={18} aria-hidden /> },
  warning: { color: "yellow", icon: <Warning size={18} aria-hidden /> },
  info: { color: "blue", icon: <Info size={18} aria-hidden /> },
} as const;

function show(kind: Kind, message: string, title?: string) {
  const l = look[kind];
  notifications.show({ color: l.color, icon: l.icon, title, message, autoClose: kind === "error" ? 8000 : 4500, withCloseButton: true, closeButtonProps: { "aria-label": "Dismiss notification" } });
}

/** Toasts: icon, color and text together, so status never relies on color alone. */
export const toast = {
  success: (message: string, title?: string) => show("success", message, title),
  error: (message: string, title?: string) => show("error", message, title),
  warning: (message: string, title?: string) => show("warning", message, title),
  info: (message: string, title?: string) => show("info", message, title),
};
