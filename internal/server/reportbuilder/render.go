package reportbuilder

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/auzring1/librepatch/internal/server/pdf"
	"github.com/auzring1/librepatch/internal/shared/text"
)

// MaxPDFRows keeps a PDF readable; the CSV holds everything.
const MaxPDFRows = 5000

// CSV writes the result with the byte-order mark Excel needs to read UTF-8.
func CSV(r *Result) ([]byte, error) {
	var b bytes.Buffer
	b.WriteString("\xef\xbb\xbf")
	w := csv.NewWriter(&b)
	heads := make([]string, len(r.Columns))
	for i, c := range r.Columns {
		heads[i] = c.Label
	}
	if err := w.Write(heads); err != nil {
		return nil, err
	}
	out := make([]string, len(r.Columns))
	for _, row := range r.Rows {
		for i, c := range row {
			out[i] = text.CSVSafe(c)
		}
		if err := w.Write(out); err != nil {
			return nil, err
		}
	}
	w.Flush()
	return b.Bytes(), w.Error()
}

// PDF writes the result as a table. Column widths follow the longest value (within each column's usual width).
func PDF(doc pdf.Doc, r *Result) []byte {
	rows := r.Rows
	note := doc.Note
	if len(rows) > MaxPDFRows {
		rows = rows[:MaxPDFRows]
		more := fmt.Sprintf("First %d of %d rows. Export CSV for all of them.", MaxPDFRows, r.Total)
		note = strings.TrimSpace(note + "   " + more)
	} else if r.Truncated {
		note = strings.TrimSpace(note + fmt.Sprintf("   First %d of %d rows. Export CSV for all of them.", len(rows), r.Total))
	}
	doc.Note = note
	cols := make([]pdf.Column, len(r.Columns))
	for i, c := range r.Columns {
		label := utf8.RuneCountInString(c.Label)
		longest := 0
		for _, row := range rows {
			if n := utf8.RuneCountInString(row[i]); n > longest {
				longest = n
			}
		}
		if c.Width > 0 && longest > c.Width {
			longest = c.Width // long values are cut with "..."; the heading is never cut
		}
		w := max(label, longest, 4)
		cols[i] = pdf.Column{Header: c.Label, Width: w}
	}
	return doc.Table(cols, rows)
}
