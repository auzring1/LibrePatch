import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { useNavigate } from "react-router-dom";
import { useConfirm } from "../ui";

interface Ctx {
  /** Registers whether the page being edited has unsaved changes. */
  setDirty: (d: boolean) => void;
  dirty: boolean;
}
const C = createContext<Ctx>({ setDirty: () => undefined, dirty: false });
export const useUnsaved = () => useContext(C);

/**
 * Guards against losing edits: closing the tab asks the browser to confirm, and while the page has unsaved changes a
 * click on any in-app link asks first. (The router here is not a data router, so there is no navigation blocker to use.)
 */
export function UnsavedProvider({ children }: { children: ReactNode }) {
  const [dirty, setDirtyState] = useState(false);
  const ref = useRef(false);
  const nav = useNavigate();
  const confirm = useConfirm();
  const setDirty = useCallback((d: boolean) => {
    ref.current = d;
    setDirtyState(d);
  }, []);
  useEffect(() => {
    const onBefore = (e: BeforeUnloadEvent) => {
      if (ref.current) {
        e.preventDefault();
        e.returnValue = "";
      }
    };
    const onClick = (e: MouseEvent) => {
      if (!ref.current || e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
      const a = (e.target as HTMLElement).closest?.("a[href]") as HTMLAnchorElement | null;
      if (!a || a.target === "_blank" || a.hasAttribute("download")) return;
      const url = new URL(a.href, window.location.href);
      if (url.origin !== window.location.origin) return;
      const to = url.pathname + url.search + url.hash;
      if (to === window.location.pathname + window.location.search) return;
      e.preventDefault();
      e.stopPropagation();
      void confirm({ title: "Leave without saving?", message: "You changed settings on this page and have not saved them. If you leave now, those changes are lost.", confirmLabel: "Leave and discard", danger: true }).then((ok) => {
        if (ok) {
          ref.current = false;
          setDirtyState(false);
          nav(to);
        }
      });
    };
    window.addEventListener("beforeunload", onBefore);
    document.addEventListener("click", onClick, true);
    return () => {
      window.removeEventListener("beforeunload", onBefore);
      document.removeEventListener("click", onClick, true);
    };
  }, [confirm, nav]);
  const value = useMemo(() => ({ dirty, setDirty }), [dirty, setDirty]);
  return <C.Provider value={value}>{children}</C.Provider>;
}
