package api

import (
	"net/http"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"github.com/auzring1/librepatch/gen/dbq"
	"github.com/auzring1/librepatch/internal/server/audit"
	"github.com/auzring1/librepatch/internal/server/settings"
	"github.com/auzring1/librepatch/internal/server/store"
)

// GET /devices/{id}/fields: the values of the organization's custom device fields for one device.
func (s *server) getDeviceFields(w http.ResponseWriter, r *http.Request) {
	d, ok := s.deviceFromURL(w, r)
	if !ok {
		return
	}
	rows, err := s.q().ListDeviceCustomValues(r.Context(), d.ID)
	if err != nil {
		internalError(w)
		return
	}
	vals := map[string]string{}
	for _, v := range rows {
		vals[v.FieldKey] = v.Value
	}
	writeJSON(w, http.StatusOK, map[string]any{"values": vals})
}

// PUT /devices/{id}/fields {"values": {"asset_tag": "HQ-0142", "owner": null}}: sets or clears values. A key must be a
// field the administrator defined; a choice field takes one of its choices; a date is YYYY-MM-DD. Audited.
func (s *server) putDeviceFields(w http.ResponseWriter, r *http.Request) {
	d, ok := s.deviceFromURL(w, r)
	if !ok {
		return
	}
	var in struct {
		Values map[string]*string `json:"values"`
	}
	if !decode(w, r, &in) {
		return
	}
	p := principalFrom(r)
	defs := map[string]settings.V{}
	if s.Settings != nil {
		for _, f := range s.Settings.Values(r.Context(), p.OrgID, "devices").Items("custom_fields") {
			defs[f.Str("key")] = f
		}
	}
	fields := map[string]string{}
	clean := map[string]string{} // "" = clear
	for k, v := range in.Values {
		def, known := defs[k]
		if !known {
			fields[k] = "There is no such field. Fields are defined under Settings > Device defaults."
			continue
		}
		if v == nil || *v == "" {
			clean[k] = ""
			continue
		}
		val := *v
		bad := !utf8.ValidString(val) || utf8.RuneCountInString(val) > 200
		for _, c := range val {
			bad = bad || unicode.IsControl(c)
		}
		switch def.Str("type") {
		case "select":
			found := false
			for _, o := range def.Strings("options") {
				found = found || o == val
			}
			bad = bad || !found
		case "date":
			_, err := time.Parse("2006-01-02", val)
			bad = bad || err != nil
		}
		if bad {
			fields[k] = "That value is not allowed for this field."
			continue
		}
		clean[k] = val
	}
	if len(fields) > 0 {
		writeJSON(w, http.StatusUnprocessableEntity, apiError{Error: errorBody{Code: "invalid_fields", Message: "Some values are not valid.", Fields: fields}})
		return
	}
	now := s.now()
	err := store.Tx(r.Context(), s.Pool, func(tx pgx.Tx, q *dbq.Queries) error {
		before := map[string]string{}
		rows, err := q.ListDeviceCustomValues(r.Context(), d.ID)
		if err != nil {
			return err
		}
		for _, v := range rows {
			before[v.FieldKey] = v.Value
		}
		changes := map[string]any{}
		for k, v := range clean {
			if before[k] == v {
				continue
			}
			if v == "" {
				err = q.DeleteDeviceCustomValue(r.Context(), dbq.DeleteDeviceCustomValueParams{DeviceID: d.ID, FieldKey: k})
			} else {
				err = q.UpsertDeviceCustomValue(r.Context(), dbq.UpsertDeviceCustomValueParams{DeviceID: d.ID, FieldKey: k, Value: v, UpdatedAt: now, UpdatedBy: &p.UserID})
			}
			if err != nil {
				return err
			}
			changes[k] = map[string]any{"before": before[k], "after": v}
		}
		if len(changes) == 0 {
			return nil
		}
		org := p.OrgID
		_, err = audit.Write(r.Context(), tx, audit.Entry{OrgID: &org, ActorType: audit.ActorUser, ActorID: p.UserID.String(), ActorIP: clientIP(r), Action: "device.fields_update",
			TargetType: "device", TargetIDs: []string{d.ID.String()}, Outcome: audit.Success, Details: map[string]any{"hostname": d.Hostname, "changes": changes}}, now)
		return err
	})
	if err != nil {
		s.Log.Error("device fields", "err", err)
		internalError(w)
		return
	}
	s.getDeviceFields(w, r)
}
