package main

import "testing"

func TestMSIVersion(t *testing.T) {
	cases := []struct {
		in    string
		build int
		want  string
		bad   bool
	}{
		{"1.2.3", 0, "1.2.3.0", false},
		{"v1.2.3", 77, "1.2.3.0", false}, // release: build number ignored
		{"v10.0.65535", 0, "10.0.65535.0", false},
		{"1.2.3-rc.1", 0, "1.2.3.0", false},
		{"1.2.3-rc.1", 42, "1.2.3.42", false},
		{"0.1.0-dev", 9, "0.1.0.9", false},
		{"1.2.3+abc123", 5, "1.2.3.0", false},
		{"1.2.3-dev+abc", 5, "1.2.3.5", false},
		{"256.0.0", 0, "", true},
		{"1.256.0", 0, "", true},
		{"1.0.65536", 0, "", true},
		{"1.2", 0, "", true},
		{"1.2.3.4", 0, "", true},
		{"01.2.3", 0, "", true},
		{"latest", 0, "", true},
		{"", 0, "", true},
		{"1.2.3-dev", 70000, "", true},
		{"1.2.3-dev", -1, "", true},
		{"1.2.3 ; rm", 0, "", true},
	}
	for _, c := range cases {
		got, err := MSIVersion(c.in, c.build)
		if c.bad {
			if err == nil {
				t.Errorf("MSIVersion(%q, %d) = %q, want an error", c.in, c.build, got)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("MSIVersion(%q, %d) = %q, %v; want %q", c.in, c.build, got, err, c.want)
		}
	}
}
