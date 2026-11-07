// Package ptr turns a value into a pointer to a copy of it, for the nullable columns the generated queries take.
package ptr

// Of returns a pointer to v.
func Of[T any](v T) *T { return &v }
