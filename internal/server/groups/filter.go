// Package groups compiles dynamic-group filters into parameterized SQL.
//
// A filter is a small JSON tree (docs/DATA_MODEL.md "Filters"). It is parsed
// strictly, validated against allow-lists of fields, comparators and value
// types, and compiled so that user-supplied text only ever appears as a bound
// parameter. Identifiers and operators in the generated SQL come exclusively
// from the tables below, never from the filter.
package groups

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/auzring1/librepatch/internal/shared/vercmp"
)

// Limits keep a filter cheap to evaluate and to reason about.
const (
	MaxDepth     = 6
	MaxNodes     = 50
	MaxInValues  = 100
	MaxValueLen  = 200
	MaxFilterLen = 32 << 10
)

// Node is one filter node. Which fields apply depends on Op:
//
//	and, or   Children (1..)
//	not       Children (exactly 1)
//	device    Field, Cmp, Value
//	software  Title (+Match), optional Publisher, optional Version, optional Scope
type Node struct {
	Op       string  `json:"op"`
	Children []*Node `json:"children,omitempty"`

	Field string          `json:"field,omitempty"`
	Cmp   string          `json:"cmp,omitempty"`
	Value json.RawMessage `json:"value,omitempty"`

	Title     string       `json:"title,omitempty"`
	Match     string       `json:"match,omitempty"` // exact | prefix | contains (default contains)
	Publisher string       `json:"publisher,omitempty"`
	Version   *VersionCond `json:"version,omitempty"`
	Scope     string       `json:"scope,omitempty"` // machine | user
}

// VersionCond compares an install's version with Value using vercmp ordering.
type VersionCond struct {
	Cmp   string `json:"cmp"`
	Value string `json:"value"`
}

// ErrInvalid is returned (wrapped) for every filter that fails validation.
var ErrInvalid = errors.New("invalid filter")

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
}

// Parse strictly decodes a filter document.
func Parse(raw []byte) (*Node, error) {
	if len(raw) > MaxFilterLen {
		return nil, invalid("filter too large")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var n Node
	if err := dec.Decode(&n); err != nil {
		return nil, invalid("malformed filter JSON")
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, invalid("trailing data after filter")
	}
	return &n, nil
}

type valKind int

const (
	kText valKind = iota
	kInt
	kBool
	kUUID
	kEnum
)

type fieldSpec struct {
	col  string // SQL expression over alias d (allow-listed constant)
	kind valKind
	cmps []string
}

var (
	textCmps = []string{"eq", "ne", "contains", "prefix", "in"}
	eqCmps   = []string{"eq", "ne", "in"}
	numCmps  = []string{"eq", "ne", "lt", "le", "gt", "ge"}
	boolCmps = []string{"eq"}
)

// deviceFields is the complete set of filterable device attributes.
var deviceFields = map[string]fieldSpec{
	"hostname":       {col: "d.hostname", kind: kText, cmps: textCmps},
	"os_caption":     {col: "d.os_caption", kind: kText, cmps: textCmps},
	"arch":           {col: "d.arch", kind: kText, cmps: eqCmps},
	"agent_version":  {col: "d.agent_version", kind: kText, cmps: textCmps},
	"manufacturer":   {col: "d.manufacturer", kind: kText, cmps: textCmps},
	"model":          {col: "d.model", kind: kText, cmps: textCmps},
	"chassis":        {col: "d.chassis", kind: kText, cmps: eqCmps},
	"os_build":       {col: "d.os_build_num", kind: kInt, cmps: numCmps},
	"ram_bytes":      {col: "d.ram_bytes", kind: kInt, cmps: numCmps},
	"online":         {col: "d.online", kind: kBool, cmps: boolCmps},
	"pending_reboot": {col: "d.pending_reboot", kind: kBool, cmps: boolCmps},
	"site_id":        {col: "d.site_id", kind: kUUID, cmps: eqCmps},
}

// bitlockerStates are the values the agent reports per disk.
var bitlockerStates = []string{"protected", "unprotected", "encrypting", "decrypting", "unknown", "unsupported"}

// Compiled is a SQL boolean expression over devices aliased d, with its
// positional arguments. Placeholders start at the first index passed to Compile.
type Compiled struct {
	SQL  string
	Args []any
}

type compiler struct {
	args  []any
	first int
	nodes int
	org   string // org placeholder for software title scoping
}

// Compile validates the filter and returns its SQL. orgPlaceholder is the
// placeholder (e.g. "$1") already bound to the organization id; argStart is
// the index of the first placeholder this call may allocate.
func Compile(n *Node, orgPlaceholder string, argStart int) (*Compiled, error) {
	if n == nil {
		return nil, invalid("empty filter")
	}
	c := &compiler{first: argStart, org: orgPlaceholder}
	sql, err := c.node(n, 1)
	if err != nil {
		return nil, err
	}
	return &Compiled{SQL: sql, Args: c.args}, nil
}

func (c *compiler) bind(v any) string {
	c.args = append(c.args, v)
	return fmt.Sprintf("$%d", c.first+len(c.args)-1)
}

func oneOf(s string, set []string) bool {
	for _, x := range set {
		if x == s {
			return true
		}
	}
	return false
}

func (c *compiler) node(n *Node, depth int) (string, error) {
	if n == nil {
		return "", invalid("missing node")
	}
	if depth > MaxDepth {
		return "", invalid("filter nested deeper than %d", MaxDepth)
	}
	if c.nodes++; c.nodes > MaxNodes {
		return "", invalid("filter has more than %d nodes", MaxNodes)
	}
	switch n.Op {
	case "and", "or":
		if len(n.Children) == 0 {
			return "", invalid("%q needs at least one child", n.Op)
		}
		if err := noLeafFields(n); err != nil {
			return "", err
		}
		parts := make([]string, 0, len(n.Children))
		for _, ch := range n.Children {
			s, err := c.node(ch, depth+1)
			if err != nil {
				return "", err
			}
			parts = append(parts, s)
		}
		return "(" + strings.Join(parts, " "+strings.ToUpper(n.Op)+" ") + ")", nil
	case "not":
		if len(n.Children) != 1 {
			return "", invalid("\"not\" needs exactly one child")
		}
		if err := noLeafFields(n); err != nil {
			return "", err
		}
		s, err := c.node(n.Children[0], depth+1)
		if err != nil {
			return "", err
		}
		return "(NOT " + s + ")", nil
	case "device":
		return c.device(n)
	case "software":
		return c.software(n)
	default:
		return "", invalid("unknown op %q", n.Op)
	}
}

func noLeafFields(n *Node) error {
	if n.Field != "" || n.Cmp != "" || len(n.Value) > 0 || n.Title != "" || n.Match != "" || n.Publisher != "" ||
		n.Version != nil || n.Scope != "" {
		return invalid("%q takes only children", n.Op)
	}
	return nil
}

func checkText(s string) error {
	if !utf8.ValidString(s) || strings.ContainsRune(s, 0) {
		return invalid("value is not valid text")
	}
	if len(s) > MaxValueLen {
		return invalid("value longer than %d bytes", MaxValueLen)
	}
	return nil
}

func decodeValue(raw json.RawMessage, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return invalid("value has the wrong type")
	}
	return nil
}

func (c *compiler) device(n *Node) (string, error) {
	if len(n.Children) > 0 || n.Title != "" || n.Match != "" || n.Publisher != "" || n.Version != nil || n.Scope != "" {
		return "", invalid("\"device\" takes field, cmp and value only")
	}
	if n.Field == "disk_bitlocker" { // any disk with the given BitLocker state
		return c.bitlocker(n)
	}
	if key, ok := strings.CutPrefix(n.Field, CustomPrefix); ok {
		return c.custom(n, key)
	}
	spec, ok := deviceFields[n.Field]
	if !ok {
		return "", invalid("unknown device field %q", n.Field)
	}
	return c.compare(spec, n)
}

// CustomPrefix starts the name of a custom device field in a filter ("custom.asset_tag", Settings > Device defaults).
const CustomPrefix = "custom."

var customKeyRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,29}$`)

// custom compiles a comparison on an administrator-defined device field. The key is checked for shape only (a key
// nobody defined matches no device); the value is bound like any other. "ne" means "does not have this value",
// which includes devices where the field is empty.
func (c *compiler) custom(n *Node, key string) (string, error) {
	if !customKeyRe.MatchString(key) {
		return "", invalid("unknown device field %q", n.Field)
	}
	spec := fieldSpec{col: "v.value", kind: kText, cmps: textCmps}
	cmp := n.Cmp
	neg := cmp == "ne"
	if neg {
		cmp = "eq"
	}
	inner := *n
	inner.Cmp = cmp
	cond, err := c.compare(spec, &inner)
	if err != nil {
		return "", err
	}
	exists := fmt.Sprintf("EXISTS (SELECT 1 FROM device_custom_values v WHERE v.device_id = d.id AND v.field_key = %s AND %s)", c.bind(key), cond)
	if neg {
		return "(NOT " + exists + ")", nil
	}
	return "(" + exists + ")", nil
}

// compare compiles one comparison of a field with a value.
func (c *compiler) compare(spec fieldSpec, n *Node) (string, error) {
	if !oneOf(n.Cmp, spec.cmps) {
		return "", invalid("comparator %q not allowed for %q", n.Cmp, n.Field)
	}
	if len(n.Value) == 0 {
		return "", invalid("missing value for %q", n.Field)
	}
	if n.Cmp == "in" {
		return c.in(spec, n)
	}
	arg, err := c.scalar(spec, n.Value)
	if err != nil {
		return "", err
	}
	switch n.Cmp {
	case "eq":
		return fmt.Sprintf("(%s = %s)", spec.col, c.bind(arg)), nil
	case "ne":
		return fmt.Sprintf("(%s <> %s)", spec.col, c.bind(arg)), nil
	case "lt":
		return fmt.Sprintf("(%s < %s)", spec.col, c.bind(arg)), nil
	case "le":
		return fmt.Sprintf("(%s <= %s)", spec.col, c.bind(arg)), nil
	case "gt":
		return fmt.Sprintf("(%s > %s)", spec.col, c.bind(arg)), nil
	case "ge":
		return fmt.Sprintf("(%s >= %s)", spec.col, c.bind(arg)), nil
	case "contains": // strpos avoids LIKE metacharacter escaping altogether
		return fmt.Sprintf("(strpos(lower(%s), %s) > 0)", spec.col, c.bind(strings.ToLower(arg.(string)))), nil
	case "prefix":
		return fmt.Sprintf("starts_with(lower(%s), %s)", spec.col, c.bind(strings.ToLower(arg.(string)))), nil
	}
	return "", invalid("unsupported comparator %q", n.Cmp)
}

// scalar decodes one value of the field's kind.
func (c *compiler) scalar(spec fieldSpec, raw json.RawMessage) (any, error) {
	switch spec.kind {
	case kText, kEnum:
		var s string
		if err := decodeValue(raw, &s); err != nil {
			return nil, err
		}
		if err := checkText(s); err != nil {
			return nil, err
		}
		return s, nil
	case kInt:
		var v int64
		if err := decodeValue(raw, &v); err != nil {
			return nil, err
		}
		if v < 0 || v > 1<<50 {
			return nil, invalid("number out of range")
		}
		return v, nil
	case kBool:
		var b bool
		if err := decodeValue(raw, &b); err != nil {
			return nil, err
		}
		return b, nil
	case kUUID:
		var s string
		if err := decodeValue(raw, &s); err != nil {
			return nil, err
		}
		u, err := uuid.Parse(s)
		if err != nil {
			return nil, invalid("not a UUID")
		}
		return u, nil
	}
	return nil, invalid("unsupported value type")
}

func (c *compiler) in(spec fieldSpec, n *Node) (string, error) {
	var raws []json.RawMessage
	if err := decodeValue(n.Value, &raws); err != nil {
		return "", invalid("\"in\" needs a list")
	}
	if len(raws) == 0 || len(raws) > MaxInValues {
		return "", invalid("\"in\" needs 1..%d values", MaxInValues)
	}
	switch spec.kind {
	case kUUID:
		vals := make([]uuid.UUID, 0, len(raws))
		for _, r := range raws {
			v, err := c.scalar(spec, r)
			if err != nil {
				return "", err
			}
			vals = append(vals, v.(uuid.UUID))
		}
		return fmt.Sprintf("(%s = ANY(%s))", spec.col, c.bind(vals)), nil
	default:
		vals := make([]string, 0, len(raws))
		for _, r := range raws {
			v, err := c.scalar(spec, r)
			if err != nil {
				return "", err
			}
			s, ok := v.(string)
			if !ok {
				return "", invalid("\"in\" is only for text fields")
			}
			vals = append(vals, s)
		}
		return fmt.Sprintf("(%s = ANY(%s))", spec.col, c.bind(vals)), nil
	}
}

func (c *compiler) bitlocker(n *Node) (string, error) {
	if n.Cmp != "any" {
		return "", invalid("\"disk_bitlocker\" supports only cmp \"any\"")
	}
	var s string
	if err := decodeValue(n.Value, &s); err != nil || !oneOf(s, bitlockerStates) {
		return "", invalid("BitLocker state must be one of %s", strings.Join(bitlockerStates, ", "))
	}
	return fmt.Sprintf("EXISTS (SELECT 1 FROM jsonb_array_elements(COALESCE(d.hardware->'disks', '[]'::jsonb)) AS k WHERE k->>'bitlocker' = %s)", c.bind(s)), nil
}

var versionCmps = map[string]string{"lt": "<", "le": "<=", "gt": ">", "ge": ">=", "eq": "=", "ne": "<>"}

// software matches devices with an install whose title (and optionally
// publisher, version and scope) satisfy ALL given conditions on the same row.
func (c *compiler) software(n *Node) (string, error) {
	if len(n.Children) > 0 || n.Field != "" || n.Cmp != "" || len(n.Value) > 0 {
		return "", invalid("\"software\" takes title, match, publisher, version and scope only")
	}
	title := strings.ToLower(strings.TrimSpace(n.Title))
	if title == "" {
		return "", invalid("software filter needs a title")
	}
	if err := checkText(title); err != nil {
		return "", err
	}
	conds := []string{"si.device_id = d.id", "st.org_id = " + c.org, "NOT si.system_component"}
	switch n.Match {
	case "exact":
		conds = append(conds, "st.normalized_name = "+c.bind(title))
	case "prefix":
		conds = append(conds, "starts_with(st.normalized_name, "+c.bind(title)+")")
	case "contains", "":
		conds = append(conds, "strpos(st.normalized_name, "+c.bind(title)+") > 0")
	default:
		return "", invalid("match must be exact, prefix or contains")
	}
	if p := strings.ToLower(strings.TrimSpace(n.Publisher)); p != "" {
		if err := checkText(p); err != nil {
			return "", err
		}
		conds = append(conds, "strpos(st.normalized_publisher, "+c.bind(p)+") > 0")
	}
	switch n.Scope {
	case "":
	case "machine", "user":
		conds = append(conds, "si.scope = "+c.bind(n.Scope))
	default:
		return "", invalid("scope must be machine or user")
	}
	if v := n.Version; v != nil {
		op, ok := versionCmps[v.Cmp]
		if !ok {
			return "", invalid("version comparator must be one of lt, le, gt, ge, eq, ne")
		}
		if err := checkText(v.Value); err != nil {
			return "", err
		}
		key := vercmp.Key(strings.TrimSpace(v.Value))
		if key == nil {
			return "", invalid("version %q cannot be compared", v.Value)
		}
		// Rows with an unknown version (NULL key) never match a version condition.
		conds = append(conds, "si.version_key "+op+" "+c.bind(key))
	}
	return "EXISTS (SELECT 1 FROM software_installs si JOIN software_titles st ON st.id = si.title_id WHERE " +
		strings.Join(conds, " AND ") + ")", nil
}
