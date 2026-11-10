package reportbuilder

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Saved is a custom report: a name and a Spec.
type Saved struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Spec        Spec      `json:"spec"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// ErrNotFound is returned when a saved report does not exist in the organization.
var ErrNotFound = errors.New("report not found")

// ErrNameTaken is returned when another saved report already has the name.
var ErrNameTaken = errors.New("a report with this name already exists")

// Store keeps the saved reports.
type Store struct{ Pool *pgxpool.Pool }

func scanSaved(row pgx.Row) (Saved, error) {
	var s Saved
	var raw []byte
	if err := row.Scan(&s.ID, &s.Name, &s.Description, &raw, &s.CreatedAt, &s.UpdatedAt); err != nil {
		return s, err
	}
	if err := json.Unmarshal(raw, &s.Spec); err != nil {
		return s, err
	}
	return s, nil
}

// List returns the organization's saved reports by name.
func (st *Store) List(ctx context.Context, org uuid.UUID) ([]Saved, error) {
	rows, err := st.Pool.Query(ctx, `SELECT id, name, description, spec, created_at, updated_at FROM saved_reports WHERE org_id = $1 ORDER BY lower(name) LIMIT 500`, org)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Saved{}
	for rows.Next() {
		s, err := scanSaved(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// Get returns one saved report.
func (st *Store) Get(ctx context.Context, org, id uuid.UUID) (Saved, error) {
	s, err := scanSaved(st.Pool.QueryRow(ctx, `SELECT id, name, description, spec, created_at, updated_at FROM saved_reports WHERE org_id = $1 AND id = $2`, org, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return s, ErrNotFound
	}
	return s, err
}

func nameTaken(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == "23505"
}

// Create saves a new report. The spec must already be validated.
func (st *Store) Create(ctx context.Context, org uuid.UUID, by *uuid.UUID, name, desc string, sp Spec) (Saved, error) {
	raw, _ := json.Marshal(sp)
	s, err := scanSaved(st.Pool.QueryRow(ctx, `INSERT INTO saved_reports (id, org_id, name, description, spec, created_by)
		VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, name, description, spec, created_at, updated_at`, uuid.New(), org, strings.TrimSpace(name), strings.TrimSpace(desc), raw, by))
	if nameTaken(err) {
		return s, ErrNameTaken
	}
	return s, err
}

// Update replaces a saved report's name, description and spec.
func (st *Store) Update(ctx context.Context, org, id uuid.UUID, name, desc string, sp Spec) (Saved, error) {
	raw, _ := json.Marshal(sp)
	s, err := scanSaved(st.Pool.QueryRow(ctx, `UPDATE saved_reports SET name = $3, description = $4, spec = $5, updated_at = now()
		WHERE org_id = $1 AND id = $2 RETURNING id, name, description, spec, created_at, updated_at`, org, id, strings.TrimSpace(name), strings.TrimSpace(desc), raw))
	if errors.Is(err, pgx.ErrNoRows) {
		return s, ErrNotFound
	}
	if nameTaken(err) {
		return s, ErrNameTaken
	}
	return s, err
}

// Delete removes a saved report.
func (st *Store) Delete(ctx context.Context, org, id uuid.UUID) error {
	tag, err := st.Pool.Exec(ctx, `DELETE FROM saved_reports WHERE org_id = $1 AND id = $2`, org, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
