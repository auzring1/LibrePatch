package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/auzring1/librepatch/gen/dbq"
	"github.com/auzring1/librepatch/internal/server/branding"
	"github.com/auzring1/librepatch/internal/server/store"
)

// Limits on what one account may store. The document is small by design: it holds a theme, a density and the
// table views people save, and is capped so it cannot be used as storage.
const (
	maxViewTables   = 32
	maxViewsPerTbl  = 20
	maxViewStateLen = 4096
)

var (
	tableIDRe = regexp.MustCompile(`^[a-z][a-z0-9-]{0,39}$`)
	viewIDRe  = regexp.MustCompile(`^[a-z0-9-]{1,40}$`)
)

// savedView is one named table view (visible columns, order, widths, sort, filters), opaque to the server apart
// from being a small JSON object.
type savedView struct {
	ID    string          `json:"id"`
	Name  string          `json:"name"`
	State json.RawMessage `json:"state"`
}

// preferences is a person's console appearance, kept on the account so it follows them to any device.
type preferences struct {
	Theme   string                 `json:"theme"`   // "" = the organization's default
	Density string                 `json:"density"` // "" | comfortable | compact
	Views   map[string][]savedView `json:"views"`   // table id -> saved views
	// Nav and Dashboard are optional: a request that leaves them out keeps what is stored, so an older client that
	// only knows the theme and the views cannot wipe a person's layout.
	Nav       *navPrefs  `json:"nav,omitempty"`
	Dashboard *dashPrefs `json:"dashboard,omitempty"`
}

// navPrefs is how a person arranged the sidebar: whether it is narrowed to icons, and which groups and submenus they
// folded away (by id).
type navPrefs struct {
	Collapsed bool     `json:"collapsed"`
	Closed    []string `json:"closed"`
}

// dashPrefs is a person's dashboard layout. Order and Hidden are the original single layout (widget ids); Boards,
// Active and Refresh are the customizable dashboards (D167). All of it is optional on the wire, so an older client that
// only knows Order and Hidden saves without wiping the boards (the server keeps them).
type dashPrefs struct {
	Order  []string `json:"order"`
	Hidden []string `json:"hidden"`
	// Boards are the person's saved dashboards, each a grid of widget instances.
	Boards []dashBoard `json:"boards,omitempty"`
	// Active is the id of the board shown first.
	Active string `json:"active,omitempty"`
}

// dashBoard is one saved dashboard: a name, how often it refreshes and the placed widgets.
type dashBoard struct {
	ID      string       `json:"id"`
	Name    string       `json:"name"`
	Refresh int          `json:"refresh"` // seconds; 0 = never, else 30, 60 or 300
	Widgets []dashWidget `json:"widgets"`
}

// dashWidget is one widget placed on the 12-column grid, with its own settings. What a type means is the console's
// business; the server only checks shapes and sizes so the document stays small and harmless.
type dashWidget struct {
	ID       string         `json:"id"`
	Type     string         `json:"type"`
	X        int            `json:"x"`
	Y        int            `json:"y"`
	W        int            `json:"w"`
	H        int            `json:"h"`
	Settings dashWidgetOpts `json:"settings"`
}

// dashWidgetOpts are the per-widget settings. Every field is optional.
type dashWidgetOpts struct {
	Title  string `json:"title,omitempty"`  // overrides the widget's own title
	Site   string `json:"site,omitempty"`   // a site id: show this site instead of the site switcher's choice
	Range  string `json:"range,omitempty"`  // a time range such as "7d"
	Count  int    `json:"count,omitempty"`  // how many rows a list shows
	Metric string `json:"metric,omitempty"` // which number a stat tile shows
	Dest   string `json:"dest,omitempty"`   // where a shortcut tile leads
	Text   string `json:"text,omitempty"`   // the body of a text widget
}

const (
	maxBoards         = 10
	maxBoardWidgets   = 40
	dashGridCols      = 12
	dashMaxRows       = 400
	maxWidgetTitle    = 60
	maxWidgetText     = 500
	maxBoardNameRunes = 40
)

var rangeRe = regexp.MustCompile(`^[0-9]{1,3}[dh]$`)

// validBoards checks the saved dashboards' shape. It returns a message for the first problem, or "".
func validBoards(boards []dashBoard, active string) string {
	if len(boards) > maxBoards {
		return "Too many dashboards."
	}
	boardIDs := map[string]bool{}
	for _, b := range boards {
		name := strings.TrimSpace(b.Name)
		if !layoutIDRe.MatchString(b.ID) || boardIDs[b.ID] {
			return "A dashboard has an invalid or repeated id."
		}
		boardIDs[b.ID] = true
		if name == "" || utf8.RuneCountInString(name) > maxBoardNameRunes || hasControl(name) {
			return "A dashboard needs a name of up to 40 characters."
		}
		if b.Refresh != 0 && b.Refresh != 30 && b.Refresh != 60 && b.Refresh != 300 {
			return "A dashboard refreshes never, or every 30, 60 or 300 seconds."
		}
		if len(b.Widgets) > maxBoardWidgets {
			return "A dashboard has too many widgets."
		}
		ids := map[string]bool{}
		for _, w := range b.Widgets {
			if !layoutIDRe.MatchString(w.ID) || ids[w.ID] || !layoutIDRe.MatchString(w.Type) {
				return "A widget has an invalid or repeated id or type."
			}
			ids[w.ID] = true
			if w.X < 0 || w.W < 1 || w.X+w.W > dashGridCols || w.Y < 0 || w.H < 1 || w.Y+w.H > dashMaxRows {
				return "A widget is outside the grid."
			}
			o := w.Settings
			if utf8.RuneCountInString(o.Title) > maxWidgetTitle || hasControl(o.Title) ||
				utf8.RuneCountInString(o.Text) > maxWidgetText || o.Count < 0 || o.Count > 50 ||
				(o.Site != "" && !isUUID(o.Site)) || (o.Range != "" && !rangeRe.MatchString(o.Range)) ||
				(o.Metric != "" && !layoutIDRe.MatchString(o.Metric)) || (o.Dest != "" && !layoutIDRe.MatchString(o.Dest)) {
				return "A widget has settings that are not valid."
			}
		}
	}
	if active != "" && !boardIDs[active] {
		return "The active dashboard does not exist."
	}
	return ""
}

func hasControl(s string) bool {
	for _, c := range s {
		if unicode.IsControl(c) {
			return true
		}
	}
	return false
}

func isUUID(s string) bool {
	_, err := uuid.Parse(s)
	return err == nil
}

const maxLayoutIDs = 32

var layoutIDRe = regexp.MustCompile(`^[a-z][a-z0-9-]{0,39}$`)

// validLayoutIDs reports whether ids is a short list of distinct, well-formed identifiers.
func validLayoutIDs(ids []string) bool {
	if len(ids) > maxLayoutIDs {
		return false
	}
	seen := map[string]bool{}
	for _, id := range ids {
		if !layoutIDRe.MatchString(id) || seen[id] {
			return false
		}
		seen[id] = true
	}
	return true
}

func (p *preferences) normalize() {
	if p.Views == nil {
		p.Views = map[string][]savedView{}
	}
	if p.Nav != nil && p.Nav.Closed == nil {
		p.Nav.Closed = []string{}
	}
	if p.Dashboard != nil {
		if p.Dashboard.Order == nil {
			p.Dashboard.Order = []string{}
		}
		if p.Dashboard.Hidden == nil {
			p.Dashboard.Hidden = []string{}
		}
		for i := range p.Dashboard.Boards {
			if p.Dashboard.Boards[i].Widgets == nil {
				p.Dashboard.Boards[i].Widgets = []dashWidget{}
			}
		}
	}
}

// GET /me/preferences: the signed-in person's preferences (empty values until they choose).
func (s *server) getPreferences(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r)
	var out preferences
	raw, err := s.q().GetUserPreferences(r.Context(), p.UserID)
	switch {
	case store.IsNoRows(err):
	case err != nil:
		s.Log.Error("preferences", "err", err)
		internalError(w)
		return
	default:
		_ = json.Unmarshal(raw, &out)
	}
	out.normalize()
	writeJSON(w, http.StatusOK, out)
}

// PUT /me/preferences: replaces the signed-in person's preferences.
func (s *server) putPreferences(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r)
	if p.TokenID != "" {
		writeError(w, http.StatusForbidden, "forbidden", "An API token cannot change console preferences.")
		return
	}
	var in preferences
	if !decode(w, r, &in) {
		return
	}
	in.normalize()
	fields := map[string]string{}
	in.Theme = strings.TrimSpace(in.Theme)
	if in.Theme != "" && !branding.ValidThemeID(in.Theme) {
		fields["theme"] = "That theme is not valid."
	}
	if in.Density != "" && in.Density != "comfortable" && in.Density != "compact" {
		fields["density"] = "Density is comfortable or compact."
	}
	if in.Theme != "" && fields["theme"] == "" && s.Branding != nil {
		if pub, err := s.Branding.Public(r.Context()); err == nil && len(pub.AllowedThemes) > 0 && !slices.Contains(pub.AllowedThemes, in.Theme) {
			fields["theme"] = "Your administrator does not offer that theme."
		}
	}
	if in.Nav != nil && !validLayoutIDs(in.Nav.Closed) {
		fields["nav"] = "The navigation layout is not valid."
	}
	if in.Dashboard != nil {
		if !validLayoutIDs(in.Dashboard.Order) || !validLayoutIDs(in.Dashboard.Hidden) {
			fields["dashboard"] = "The dashboard layout is not valid."
		} else if msg := validBoards(in.Dashboard.Boards, in.Dashboard.Active); msg != "" {
			fields["dashboard"] = msg
		}
	}
	if len(in.Views) > maxViewTables {
		fields["views"] = "Too many tables have saved views."
	}
	for tbl, views := range in.Views {
		if !tableIDRe.MatchString(tbl) || len(views) > maxViewsPerTbl {
			fields["views"] = "A table has an invalid id or too many saved views."
			break
		}
		ids := map[string]bool{}
		for _, v := range views {
			name := strings.TrimSpace(v.Name)
			bad := !viewIDRe.MatchString(v.ID) || ids[v.ID] || name == "" || utf8.RuneCountInString(name) > 60 || len(v.State) > maxViewStateLen
			for _, c := range name {
				bad = bad || unicode.IsControl(c)
			}
			var obj map[string]json.RawMessage
			bad = bad || json.Unmarshal(v.State, &obj) != nil || obj == nil || !bytes.HasPrefix(bytes.TrimSpace(v.State), []byte("{"))
			if bad {
				fields["views"] = "A saved view is not valid (id, name up to 60 characters, small JSON state)."
			}
			ids[v.ID] = true
		}
	}
	if len(fields) > 0 {
		writeJSON(w, http.StatusUnprocessableEntity, apiError{Error: errorBody{Code: "invalid_preferences", Message: "Some preferences are not valid.", Fields: fields}})
		return
	}
	if in.Nav == nil || in.Dashboard == nil || in.Dashboard.Boards == nil {
		var old preferences
		if raw, err := s.q().GetUserPreferences(r.Context(), p.UserID); err == nil {
			_ = json.Unmarshal(raw, &old)
		}
		if in.Nav == nil {
			in.Nav = old.Nav
		}
		if in.Dashboard == nil {
			in.Dashboard = old.Dashboard
		} else if in.Dashboard.Boards == nil && old.Dashboard != nil {
			// A client that does not know the dashboards (it sends order and hidden only) keeps them.
			in.Dashboard.Boards, in.Dashboard.Active = old.Dashboard.Boards, old.Dashboard.Active
		}
	}
	raw, err := json.Marshal(in)
	if err != nil || len(raw) > 60<<10 {
		writeError(w, http.StatusUnprocessableEntity, "invalid_preferences", "The preferences are too large.")
		return
	}
	if err := s.q().UpsertUserPreferences(r.Context(), dbq.UpsertUserPreferencesParams{UserID: p.UserID, Data: raw, UpdatedAt: s.now()}); err != nil {
		s.Log.Error("save preferences", "err", err)
		internalError(w)
		return
	}
	writeJSON(w, http.StatusOK, in)
}
