import { useCallback, useRef, useState, type KeyboardEvent, type PointerEvent as ReactPointerEvent, type ReactNode } from "react";
import { Icons, IconButton } from "../../ui";
import { COLS, place, readingOrder, type Placed, type Rect } from "./grid";

interface Props {
  /** Where each widget sits (only the ones to show). */
  items: Placed[];
  /** Smallest size of each widget, by id. */
  minSize: (id: string) => { w: number; h: number };
  /** The name used in button labels. */
  nameOf: (id: string) => string;
  editing: boolean;
  /** Renders the widget's content. */
  children: (id: string) => ReactNode;
  /** Called with the finished position of a widget after a drag, a resize or a key press. */
  onPlace: (id: string, to: Rect) => void;
  onSettings: (id: string) => void;
  onDuplicate: (id: string) => void;
  onRemove: (id: string) => void;
}

type Drag = { id: string; mode: "move" | "resize"; startX: number; startY: number; from: Rect; to: Rect };

const px = (v: string) => Number.parseFloat(v) || 0;

/**
 * The dashboard canvas: a 12-column CSS grid. In edit mode each widget has a handle to drag it, a corner to resize it,
 * and the same from the keyboard (arrow keys move, Shift plus arrows resize); the others settle around it while it moves.
 * On a narrow screen the widgets stack in reading order and dragging is off.
 */
export function DashboardGrid({ items, minSize, nameOf, editing, children, onPlace, onSettings, onDuplicate, onRemove }: Props) {
  const ref = useRef<HTMLDivElement>(null);
  const [drag, setDrag] = useState<Drag | null>(null);

  // What is drawn: while dragging, the others have settled around the moving one.
  const shown = drag ? place(items, drag.id, drag.to, minSize(drag.id)) : items;
  const ordered = readingOrder(shown);

  const step = useCallback(() => {
    const el = ref.current;
    if (!el) return { x: 80, y: 80 };
    const cs = getComputedStyle(el);
    const gap = px(cs.columnGap);
    const rowH = px(cs.gridAutoRows);
    return { x: (el.clientWidth - gap * (COLS - 1)) / COLS + gap, y: rowH + px(cs.rowGap) };
  }, []);

  const begin = (e: ReactPointerEvent<HTMLElement>, id: string, mode: Drag["mode"]) => {
    if (!editing || e.button !== 0) return;
    const it = items.find((i) => i.id === id);
    if (!it) return;
    e.currentTarget.setPointerCapture(e.pointerId);
    e.preventDefault();
    const from = { x: it.x, y: it.y, w: it.w, h: it.h };
    setDrag({ id, mode, startX: e.clientX, startY: e.clientY, from, to: from });
  };
  const move = (e: ReactPointerEvent<HTMLElement>) => {
    if (!drag) return;
    const s = step();
    const dx = Math.round((e.clientX - drag.startX) / s.x);
    const dy = Math.round((e.clientY - drag.startY) / s.y);
    const f = drag.from;
    const to = drag.mode === "move" ? { ...f, x: f.x + dx, y: f.y + dy } : { ...f, w: f.w + dx, h: f.h + dy };
    if (to.x !== drag.to.x || to.y !== drag.to.y || to.w !== drag.to.w || to.h !== drag.to.h) setDrag({ ...drag, to });
  };
  const end = () => {
    if (!drag) return;
    const { id, from, to } = drag;
    setDrag(null);
    if (from.x !== to.x || from.y !== to.y || from.w !== to.w || from.h !== to.h) onPlace(id, to);
  };

  const key = (e: KeyboardEvent<HTMLElement>, id: string) => {
    const it = items.find((i) => i.id === id);
    const d = { ArrowLeft: [-1, 0], ArrowRight: [1, 0], ArrowUp: [0, -1], ArrowDown: [0, 1] }[e.key];
    if (!it || !d) return;
    e.preventDefault();
    onPlace(id, e.shiftKey ? { ...it, w: it.w + d[0]!, h: it.h + d[1]! } : { ...it, x: it.x + d[0]!, y: it.y + d[1]! });
  };

  return (
    <div ref={ref} className="lp-grid" data-editing={editing ? "true" : "false"} data-dragging={drag ? "true" : "false"}>
      {ordered.map((it) => {
        const name = nameOf(it.id);
        return (
          <div
            key={it.id}
            className="lp-grid__cell"
            data-widget={it.id}
            data-active={drag?.id === it.id ? "true" : "false"}
            style={{ "--x": it.x + 1, "--y": it.y + 1, "--w": it.w, "--h": it.h } as React.CSSProperties}
          >
            {/* While editing, the content is inert so links and buttons inside widgets do not fire. */}
            <div className="lp-grid__content" inert={editing}>
              {children(it.id)}
            </div>
            {editing && (
              <>
                <div className="lp-grid__bar" role="group" aria-label={`${name} controls`}>
                  <button
                    type="button"
                    className="lp-grid__grip"
                    aria-label={`Move ${name}. Arrow keys move it, Shift plus arrow keys resize it.`}
                    onPointerDown={(e) => begin(e, it.id, "move")}
                    onPointerMove={move}
                    onPointerUp={end}
                    onPointerCancel={() => setDrag(null)}
                    onKeyDown={(e) => key(e, it.id)}
                  >
                    <Icons.Grip size={16} aria-hidden="true" />
                  </button>
                  <IconButton label={`Settings of ${name}`} icon={<Icons.NavSettings size={16} aria-hidden="true" />} onClick={() => onSettings(it.id)} />
                  <IconButton label={`Duplicate ${name}`} icon={<Icons.Copy size={16} aria-hidden="true" />} onClick={() => onDuplicate(it.id)} />
                  <IconButton label={`Remove ${name}`} icon={<Icons.Trash size={16} aria-hidden="true" />} onClick={() => onRemove(it.id)} />
                </div>
                <span
                  className="lp-grid__resize"
                  role="presentation"
                  onPointerDown={(e) => begin(e, it.id, "resize")}
                  onPointerMove={move}
                  onPointerUp={end}
                  onPointerCancel={() => setDrag(null)}
                />
              </>
            )}
          </div>
        );
      })}
    </div>
  );
}
