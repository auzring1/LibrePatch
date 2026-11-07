import { createContext, useContext, useEffect, useId, useMemo, useRef, useState, type KeyboardEvent, type ReactNode } from "react";
import { useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { Modal } from "@mantine/core";
import { useDebouncedValue } from "@mantine/hooks";
import { api, type Device, type WindowsUpdate } from "../api/client";
import { useSession } from "../api/session";
import { useFeatures } from "../settings/features";
import * as I from "./icons";
import { allowed, flatNav, visibleNav } from "./nav";

type Group = "Pages" | "Devices" | "Updates";
interface Result {
  key: string;
  group: Group;
  label: string;
  hint?: string;
  to: string;
  icon: ReactNode;
}

const Ctx = createContext<{ open: () => void }>({ open: () => undefined });
export const useCommandPalette = () => useContext(Ctx);

const isTyping = (t: EventTarget | null) => {
  const el = t as HTMLElement | null;
  return !!el && (/^(input|textarea|select)$/i.test(el.tagName) || el.isContentEditable);
};

/** Matches every word of the query somewhere in the haystack. */
export const matches = (hay: string, needle: string) => {
  const h = hay.toLowerCase();
  return needle
    .toLowerCase()
    .split(/\s+/)
    .filter(Boolean)
    .every((w) => h.includes(w));
};

/**
 * The command palette: Ctrl+K (or Cmd+K, or "/" outside a text field) opens a dialog that jumps to a page, a device or
 * a Windows update. Devices come from the cached device list; updates are searched on the server as you type.
 */
export function CommandPaletteProvider({ children }: { children: ReactNode }) {
  const [opened, setOpened] = useState(false);
  useEffect(() => {
    const onKey = (e: globalThis.KeyboardEvent) => {
      if ((e.key.toLowerCase() === "k" && (e.ctrlKey || e.metaKey)) || (e.key === "/" && !e.ctrlKey && !e.metaKey && !e.altKey && !isTyping(e.target))) {
        e.preventDefault();
        setOpened(true);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);
  const value = useMemo(() => ({ open: () => setOpened(true) }), []);
  return (
    <Ctx.Provider value={value}>
      {children}
      <Palette opened={opened} onClose={() => setOpened(false)} />
    </Ctx.Provider>
  );
}

/** The top bar's search field: looks like an input, opens the palette. */
export function SearchButton() {
  const { open } = useCommandPalette();
  return (
    <button type="button" className="lp-search__field lp-search__trigger" onClick={open} aria-haspopup="dialog" aria-keyshortcuts="Control+K" data-testid="open-search">
      <I.Search size={16} aria-hidden />
      <span className="lp-search__placeholder">Search pages, devices and updates</span>
      <kbd className="lp-kbd" aria-hidden="true">
        Ctrl K
      </kbd>
    </button>
  );
}

function Palette({ opened, onClose }: { opened: boolean; onClose: () => void }) {
  const nav = useNavigate();
  const { can, canOrg } = useSession();
  const features = useFeatures();
  const [q, setQ] = useState("");
  const [active, setActive] = useState(0);
  const listId = useId();
  const input = useRef<HTMLInputElement>(null);
  const [dq] = useDebouncedValue(q.trim(), 250);

  useEffect(() => {
    if (opened) {
      setQ("");
      setActive(0);
    }
  }, [opened]);

  const devices = useQuery({
    queryKey: ["devices", "search"],
    queryFn: () => api<{ items: Device[] }>("GET", "/devices?limit=500"),
    enabled: opened && can("devices:read"),
    staleTime: 60_000,
  });
  const updates = useQuery({
    queryKey: ["updates", "search", dq],
    queryFn: () => api<{ items: WindowsUpdate[] }>("GET", `/updates?limit=6&q=${encodeURIComponent(dq)}`),
    enabled: opened && dq.length >= 2 && can("updates:read") && features.windowsUpdates,
    staleTime: 30_000,
  });

  const results = useMemo<Result[]>(() => {
    const needle = q.trim();
    const groups = visibleNav({ can, canOrg, features });
    const pages = flatNav(groups)
      .filter(({ item }) => allowed(item, { can, canOrg, features }))
      .filter(({ item, group, parent }) => !needle || matches([item.label, parent?.label, group.label, ...(item.keywords ?? [])].filter(Boolean).join(" "), needle))
      .slice(0, needle ? 8 : 7)
      .map<Result>(({ item, group, parent }) => ({
        key: `p${item.id}`,
        group: "Pages",
        label: item.label,
        hint: parent ? `${parent.label}` : group.label || undefined,
        to: item.to,
        icon: <item.icon size={16} aria-hidden />,
      }));
    const devs = needle
      ? (devices.data?.items ?? [])
          .filter((d) => matches([d.hostname, d.logged_on_user, d.serial, d.model, d.manufacturer, d.os_caption].filter(Boolean).join(" "), needle))
          .slice(0, 8)
          .map<Result>((d) => ({ key: `d${d.id}`, group: "Devices", label: d.hostname, hint: d.logged_on_user || d.os_caption || d.status, to: `/devices/${d.id}`, icon: <I.Laptop size={16} aria-hidden /> }))
      : [];
    const ups =
      needle.length >= 2 && dq === needle
        ? (updates.data?.items ?? []).map<Result>((u) => {
            const kb = (u.kb ?? [])[0];
            const term = kb ? `KB${kb.replace(/^KB/i, "")}` : u.title;
            return { key: `u${u.update_id}`, group: "Updates", label: u.title, hint: kb ? term : (u.severity ?? undefined), to: `/updates?q=${encodeURIComponent(term)}&missing=0`, icon: <I.NavUpdates size={16} aria-hidden /> };
          })
        : [];
    return [...pages, ...devs, ...ups];
  }, [q, dq, devices.data, updates.data, can, canOrg, features]);

  useEffect(() => setActive(0), [q]);

  const go = (r: Result) => {
    onClose();
    nav(r.to);
  };
  const onKeyDown = (e: KeyboardEvent) => {
    if (e.key === "ArrowDown") (e.preventDefault(), setActive((a) => Math.min(a + 1, results.length - 1)));
    else if (e.key === "ArrowUp") (e.preventDefault(), setActive((a) => Math.max(a - 1, 0)));
    else if (e.key === "Home") (e.preventDefault(), setActive(0));
    else if (e.key === "End") (e.preventDefault(), setActive(Math.max(results.length - 1, 0)));
    else if (e.key === "Enter" && results[active]) (e.preventDefault(), go(results[active]!));
  };
  useEffect(() => {
    document.getElementById(`${listId}-${active}`)?.scrollIntoView?.({ block: "nearest" });
  }, [active, listId]);

  const busy = devices.isFetching || updates.isFetching || (q.trim().length >= 2 && dq !== q.trim());
  let last = "";
  return (
    <Modal opened={opened} onClose={onClose} withCloseButton={false} padding={0} size={560} yOffset="12vh" title="Search" trapFocus returnFocus classNames={{ content: "lp-palette", header: "lp-visually-hidden" }}>
      <div className="lp-palette__field">
        <I.Search size={18} aria-hidden />
        <input
          ref={input}
          className="lp-search__input"
          type="text"
          role="combobox"
          aria-label="Search pages, devices and updates"
          aria-expanded="true"
          aria-controls={listId}
          aria-autocomplete="list"
          aria-activedescendant={results[active] ? `${listId}-${active}` : undefined}
          placeholder="Type to search…"
          autoComplete="off"
          value={q}
          onChange={(e) => setQ(e.currentTarget.value)}
          onKeyDown={onKeyDown}
          data-autofocus
        />
        <kbd className="lp-kbd" aria-hidden="true">
          Esc
        </kbd>
      </div>
      <div className="lp-palette__list" id={listId} role="listbox" aria-label="Results">
        {results.length === 0 && (
          <div className="lp-search__none" role="presentation">
            {busy ? "Searching…" : "No matches"}
          </div>
        )}
        {results.map((r, i) => {
          const head = r.group !== last ? ((last = r.group), (
            <div className="lp-search__group" role="presentation">
              {r.group}
            </div>
          )) : null;
          return (
            <div key={r.key} role="presentation">
              {head}
              <button type="button" id={`${listId}-${i}`} role="option" aria-selected={i === active} className="lp-search__item" tabIndex={-1} onMouseMove={() => active !== i && setActive(i)} onClick={() => go(r)}>
                {r.icon}
                <span className="lp-search__label">{r.label}</span>
                {r.hint && <small>{r.hint}</small>}
              </button>
            </div>
          );
        })}
      </div>
      <div className="lp-palette__foot" aria-hidden="true">
        <span>
          <kbd className="lp-kbd">↑</kbd> <kbd className="lp-kbd">↓</kbd> to move
        </span>
        <span>
          <kbd className="lp-kbd">Enter</kbd> to open
        </span>
      </div>
      <div className="lp-visually-hidden" role="status" aria-live="polite">
        {results.length} result{results.length === 1 ? "" : "s"}
      </div>
    </Modal>
  );
}
