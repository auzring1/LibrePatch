# Console design system

Everything visual comes from **semantic tokens** (`var(--lp-*)`), defined per theme in `src/design/themes/*.css` and
shared in `src/design/tokens.css`. Components never use raw colors (a test fails if they do).

* **Themes**: one CSS file each (`light`, `dark`, `slate`, `midnight`, `contrast`). Add a file, get a theme. Every pair of
  tokens is checked against WCAG AA by `src/design/themes.test.ts`. The branding accent is layered on top of every theme by
  `src/design/accent.ts` (it adapts the accent per theme so it stays readable).
* **Mantine** supplies behaviour and accessibility (modal, menu, tabs, inputs...). Its color variables are bridged to the
  tokens in `src/design/mantine-bridge.css`, so `color="red"`, `c="dimmed"` etc. follow the theme. Prefer the components
  below for status, layout and data.
* **Icons**: only from `src/ui/icons.ts` (Tabler, bundled). Decorative icons get `aria-hidden`.
* **Fonts**: Inter, bundled (no CDN). No runtime network requests.

## Page recipe

```tsx
import { Page, PageHeader, DataTable, StatGrid, StatTile, Status, StatusPill, SeverityBadge, EmptyState, Card, Icons, toast, useConfirm, type Column } from "../ui";

<Page>
  <PageHeader title="Devices" description="…" actions={<Button>…</Button>} />
  <StatGrid label="Fleet summary"><StatTile label="Online" value={211} kind="success" icon={<Icons.Online size={16} aria-hidden />} /></StatGrid>
  <DataTable id="devices" label="Devices" data={rows} columns={cols} rowId={(r) => r.id} … />
</Page>
```

* One `h1` per page (from `PageHeader`); sections inside cards use `Card title=…` (h2).
* **Status is icon + color + text**: `<Status value="active" />` maps API words to pills; `<StatusPill kind="warning">Text</StatusPill>`
  for anything else; `<SeverityBadge severity="critical" />` for update severity (Critical/Important/Moderate/Low).
* **Lists are `DataTable`s**: columns declare `value` (sort/search/filter/CSV), `cell` (rendering), `filter` (chips), `defaultHidden`,
  `required`, `primary` (+ `rowHref`), `width`. Give each table a stable `id` (saved views and layout are keyed by it).
  Bulk actions go in `bulkActions`, hover actions in `rowActions`, extra toolbar controls in `toolbar`.
* **Feedback**: `toast.success/error/warning/info(message)` instead of `notifications.show`; `const confirm = useConfirm();
  if (await confirm({ title, message, confirmLabel, danger: true })) …` for destructive actions.
* **Loading / empty**: `TableSkeleton`, `TileSkeleton`, `Skel`; `EmptyState` with an action.
* **Charts**: `StackedBar`, `Donut` with `token` = a status/severity family (`success`, `critical`…) or `chart-1..6`.
* `/styleguide` (administrators) shows every component in the active theme.

## Dashboard widgets: how to add one

The landing page (`src/pages/DashboardPage.tsx`) is a list of widgets. Each person's order and hidden widgets are saved on
their account (`prefs.dashboard = { order, hidden }`, via `usePreferences()`), and `GET /api/v1/dashboard` supplies the data.

1. **Data**: add the numbers to the `Dashboard` schema in `api/openapi.yaml` and `internal/server/api/dashboard.go`. Leave a
   section `null` (or empty) when the person lacks the permission or only has site-limited rights, and never send zeros for it.
2. **Id**: add a stable kebab-case id (`^[a-z][a-z0-9-]{0,39}$`) to `WIDGET_IDS` and a title to `WIDGET_TITLES` in
   `src/components/dashboard/layout.ts`. Ids are stored in preferences, so never rename one. Widgets that are not in a saved
   order are appended at the end (`resolveLayout`), and unknown ids are dropped.
3. **Component**: write it in `src/components/dashboard/widgets.tsx` as `({ d }: { d: Dashboard })`. Use `Card title=…` (the
   h2), `StatTile to=…` / `Link`s for drill-downs into a pre-filtered list, and `StatusPill`/`SeverityBadge` for status (icon + text,
   never color alone). Charts are plain SVG with tokens; give them an `aria-label` summary and a table alternative
   (see `ComplianceChart.tsx`).
4. **Wire it up**: return its id from `availableWidgets()` only when its data is present, and add a `case` in `render()` in
   `DashboardPage.tsx`. The customizer (show/hide switch, Move up/down buttons, Reset to default) picks it up automatically.
5. Put pure logic (links, labels, geometry) in `format.ts` and cover it in `dashboard.test.ts`.

Drill-down links use query parameters understood by the target list: `/devices?state=online|offline`, `?restart=1`,
`?status=pending`, `?agent=<version>`; `/updates?severity=Critical&missing=1`, `?q=<KB or title>&missing=1`;
`/deployments?failed=1`; `/reports?state=compliant|non_compliant|unknown`.

## Navigation, palette, bell, site switcher

* **`nav.ts` is the one list of pages.** The sidebar, the command palette, breadcrumbs and the document title all read it. Each entry has a stable `id` (saved in the person's layout, so never rename one), a `to`, the permission that shows it (`perm`, `any` for site-scoped pages) and `keywords` for the palette. A parent can have `children` (the Settings sections). Add a page = add a line there and a route in `App.tsx`.
* **Breadcrumbs are automatic.** `PageHeader` builds them from the nav tree; pass `crumb="Name"` for the last, dynamic part (a device's host name) and never write the trail by hand.
* **Sidebar layout** (`useNavLayout`): folded groups and the icon rail are saved on the account (`/me/preferences` -> `nav`) and mirrored in local storage for the first paint.
* **Command palette** (`CommandPalette.tsx`): Ctrl+K or "/" anywhere. Pages come from `nav.ts` (filtered by permission), devices from the cached list, Windows updates from `/updates?q=` as you type.
* **Links that open a filtered list** use URL parameters the list pages read: `/devices?state=online|offline&restart=1&status=pending&agent=<v>`, `/updates?severity=Critical&q=<text>&missing=0|1`, `/deployments?failed=1`, `/reports?state=non_compliant|unknown`. `DataTable` takes a `preset` for column filters (it does not remember the layout while one is set).
* **Site switcher** (`SiteScope.tsx`): narrows the dashboard and the device list to one site; a convenience, never a permission boundary (the server decides what a caller sees).
* **Bell** (`NotificationsBell.tsx`): `GET /notifications`, computed from current state; an item disappears when its cause is fixed.
