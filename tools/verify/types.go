package main

import "fmt"

// report collects verification results.
type report struct {
	Passed int
	Failed int
	lines  []string
}

func (r *report) pass(msg string) {
	r.Passed++
	r.lines = append(r.lines, "✓ "+msg)
}

func (r *report) fail(msg string) {
	r.Failed++
	r.lines = append(r.lines, "✗ "+msg)
}

func (r *report) info(msg string) {
	r.lines = append(r.lines, "  "+msg)
}

// Print writes the collected lines followed by a summary that names the mode,
// so a failing CI run shows at a glance which checks ran and which failed.
func (r *report) Print(m mode) {
	fmt.Printf("verify mode=%s\n\n", m)
	for _, l := range r.lines {
		fmt.Println(l)
	}
	fmt.Printf("\n%d passed, %d failed\n", r.Passed, r.Failed)
}
