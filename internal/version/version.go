// Package version defines the application version independently of wire protocols.
package version

import (
	_ "embed"
	"strconv"
	"strings"
)

//go:embed VERSION
var number string

func Current() string { return strings.TrimSpace(number) }

// Parse accepts bounded semantic versions, including prerelease/build labels.
func Parse(s string) (parts [3]uint64, pre string, ok bool) {
	if len(s) == 0 || len(s) > 96 {
		return
	}
	base, build, hasBuild := strings.Cut(s, "+")
	validLabel := func(label string, numeric bool) bool {
		for _, part := range strings.Split(label, ".") {
			if part == "" {
				return false
			}
			allDigits := true
			for _, c := range part {
				if !(c >= '0' && c <= '9' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c == '-') {
					return false
				}
				if c < '0' || c > '9' {
					allDigits = false
				}
			}
			if numeric && allDigits && len(part) > 1 && part[0] == '0' {
				return false
			}
		}
		return true
	}
	if hasBuild && !validLabel(build, false) {
		return
	}
	core, pre, hasPre := strings.Cut(base, "-")
	if hasPre && !validLabel(pre, true) {
		return parts, pre, false
	}
	p := strings.Split(core, ".")
	if len(p) != 3 {
		return parts, pre, false
	}
	for i, s := range p {
		if s == "" || len(s) > 1 && s[0] == '0' {
			return parts, pre, false
		}
		for _, c := range s {
			if c < '0' || c > '9' {
				return parts, pre, false
			}
		}
		n, e := strconv.ParseUint(s, 10, 64)
		if e != nil {
			return parts, pre, false
		}
		parts[i] = n
	}
	return parts, pre, true
}
func Valid(s string) bool { _, _, ok := Parse(s); return ok }

// Compare follows semantic-version precedence; build labels do not affect it.
func Compare(a, b string) int {
	x, p, _ := Parse(a)
	y, q, _ := Parse(b)
	for i := range x {
		if x[i] < y[i] {
			return -1
		}
		if x[i] > y[i] {
			return 1
		}
	}
	if p == q {
		return 0
	}
	if p == "" {
		return 1
	}
	if q == "" {
		return -1
	}
	ps, qs := strings.Split(p, "."), strings.Split(q, ".")
	numeric := func(s string) bool {
		for _, c := range s {
			if c < '0' || c > '9' {
				return false
			}
		}
		return true
	}
	for i := 0; i < min(len(ps), len(qs)); i++ {
		u, v := ps[i], qs[i]
		if u == v {
			continue
		}
		un, vn := numeric(u), numeric(v)
		if un != vn {
			if un {
				return -1
			}
			return 1
		}
		if un && len(u) != len(v) {
			if len(u) < len(v) {
				return -1
			}
			return 1
		}
		if u < v {
			return -1
		}
		return 1
	}
	if len(ps) < len(qs) {
		return -1
	}
	return 1
}
