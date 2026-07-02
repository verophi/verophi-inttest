// Command verify compares a verophi AnalysisResult JSON file (Schema 1.0)
// against an expectations YAML (the single source of truth).
//
// Two modes:
//
//	exact (default): pins every field, namely schema, metrics, scores, status,
//	    assessment counts, and the full uncorrelated advisory list. Used by the
//	    deterministic regression gate that runs against a frozen SBOM.
//	drift: pins only what is stable across a live trivy/Renovate run, namely
//	    the schema version, the correlated+uncorrelated==total invariant, each
//	    expected change identity and changeType, and the presence of each known
//	    advisory match with its occurrence versions. Extra change requests,
//	    advisories, and score changes are tolerated. Used by the live full-cycle
//	    run so new CVEs do not break it, while a vanished known correlation does.
//
// Usage:
//
//	go run ./tools/verify --expectations <path> --result <path> [--mode exact|drift]
//
// Exit codes:
//
//	0: all assertions passed
//	1: one or more assertions failed
//	2: usage or file error
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"sort"
	"strings"

	"github.com/verophi/verophi-inttest/pkg/expectations"
	"github.com/verophi/verophi/pkg/model"
)

// mode selects how strictly the result is compared against expectations.
type mode int

const (
	modeExact mode = iota
	modeDrift
)

func (m mode) String() string {
	if m == modeDrift {
		return "drift"
	}
	return "exact"
}

// parseMode maps a flag value to a mode, rejecting unknown values.
func parseMode(s string) (mode, error) {
	switch s {
	case "exact":
		return modeExact, nil
	case "drift":
		return modeDrift, nil
	default:
		return modeExact, fmt.Errorf("unknown mode %q (want exact or drift)", s)
	}
}

func main() {
	expPath := flag.String("expectations", "", "path to expectations YAML")
	resultPath := flag.String("result", "", "path to verophi AnalysisResult JSON")
	modeFlag := flag.String("mode", "exact", "verification mode: exact or drift")
	flag.Parse()

	if *expPath == "" || *resultPath == "" {
		fmt.Fprintf(os.Stderr, "Usage: verify --expectations <path> --result <path> [--mode exact|drift]\n")
		os.Exit(2)
	}

	m, err := parseMode(*modeFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(2)
	}

	exp, err := expectations.Load(*expPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(2)
	}

	result, err := loadResult(*resultPath, exp.SchemaVersion)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(2)
	}

	r := verify(exp, result, m)
	r.Print(m)

	if r.Failed > 0 {
		os.Exit(1)
	}
}

func verify(exp expectations.File, result model.AnalysisResult, m mode) report {
	var r report

	checkSchemaVersion(&r, exp, result)
	checkStructural(&r, result)
	if m == modeExact {
		checkMetrics(&r, exp, result)
	}
	checkChangeRequests(&r, exp, result, m)
	if m == modeExact {
		checkUncorrelatedAdvisories(&r, exp, result)
	} else {
		noteUncorrelatedDrift(&r, exp, result)
	}

	return r
}

// checkSchemaVersion validates the JSON carries the schema version declared in expectations.
func checkSchemaVersion(r *report, exp expectations.File, result model.AnalysisResult) {
	if result.SchemaVersion != exp.SchemaVersion {
		r.fail(fmt.Sprintf("schemaVersion=%q, expected %q", result.SchemaVersion, exp.SchemaVersion))
	} else {
		r.pass("schemaVersion=" + exp.SchemaVersion)
	}
}

// checkMetrics validates summary-level metrics.
func checkMetrics(r *report, exp expectations.File, result model.AnalysisResult) {
	m := exp.Metrics
	sum := result.AdvisorySummary

	check := func(label string, got, want int) {
		if got != want {
			r.fail(fmt.Sprintf("metrics.%s=%d, expected %d", label, got, want))
		}
	}

	check("totalAdvisories", sum.Total, m.TotalAdvisories)
	check("correlated", sum.Correlated, m.Correlated)
	check("uncorrelated", sum.Uncorrelated, m.Uncorrelated)
	check("severity.critical", sum.Critical, m.Severity.Critical)
	check("severity.high", sum.High, m.Severity.High)
	check("severity.medium", sum.Medium, m.Severity.Medium)
	check("severity.low", sum.Low, m.Severity.Low)

	if !floatEq(result.TotalImpactScore, m.TotalImpactScore) {
		r.fail(fmt.Sprintf("totalImpactScore=%.1f, expected %.1f", result.TotalImpactScore, m.TotalImpactScore))
	}

	if result.ReducibleImpactScore != nil && !floatEq(*result.ReducibleImpactScore, m.ReducibleImpactScore) {
		r.fail(fmt.Sprintf("reducibleImpactScore=%.1f, expected %.1f", *result.ReducibleImpactScore, m.ReducibleImpactScore))
	}

	// Count request statuses.
	matched, unmatched, unparsed := 0, 0, 0
	for _, cr := range result.ChangeRequests {
		switch cr.Status {
		case model.StatusMatched:
			matched++
		case model.StatusUnmatched:
			unmatched++
		case model.StatusUnparsed:
			unparsed++
		}
	}
	check("matchedRequests", matched, m.MatchedRequests)
	check("unmatchedRequests", unmatched, m.UnmatchedRequests)
	check("unparsedRequests", unparsed, m.UnparsedRequests)

	r.pass("metrics consistency")
}

// checkStructural validates correlated + uncorrelated == total.
func checkStructural(r *report, result model.AnalysisResult) {
	sum := result.AdvisorySummary
	if sum.Correlated+sum.Uncorrelated != sum.Total {
		r.fail(fmt.Sprintf("AdvisorySummary: correlated(%d) + uncorrelated(%d) != total(%d)",
			sum.Correlated, sum.Uncorrelated, sum.Total))
	} else {
		r.pass("AdvisorySummary partition (correlated + uncorrelated == total)")
	}
}

// checkChangeRequests validates each expected change request against the result.
func checkChangeRequests(r *report, exp expectations.File, result model.AnalysisResult, m mode) {
	// Index result CRs by title for lookup.
	byTitle := make(map[string][]model.ChangeRequest, len(result.ChangeRequests))
	for _, cr := range result.ChangeRequests {
		byTitle[cr.Title] = append(byTitle[cr.Title], cr)
	}

	for _, expCR := range exp.ChangeRequests {
		if !expCR.IsEnabled() {
			continue
		}

		candidates, found := byTitle[expCR.Title]
		if !found {
			r.fail(fmt.Sprintf("CR %q: not found in result", expCR.Title))
			continue
		}

		// Use first match (titles should be unique).
		cr := candidates[0]
		checkSingleCR(r, expCR, cr, m)
	}

	// Report unexpected CRs not in expectations.
	known := make(map[string]bool, len(exp.ChangeRequests))
	for _, expCR := range exp.ChangeRequests {
		known[expCR.Title] = true
	}
	var extras []string
	for title := range byTitle {
		if !known[title] {
			extras = append(extras, title)
		}
	}
	if len(extras) > 0 {
		sort.Strings(extras)
		r.info(fmt.Sprintf("Note: %d extra CRs not in expectations: %s", len(extras), strings.Join(extras, ", ")))
	}
}

func checkSingleCR(r *report, exp expectations.ChangeRequest, cr model.ChangeRequest, m mode) {
	prefix := fmt.Sprintf("CR %q", exp.Title)
	ok := true

	// Scores, status, and flags drift when new advisories appear, so they are
	// pinned only in exact mode. Drift mode keeps the change identity and the
	// known advisory correlations, which are stable.
	if m == modeExact {
		ok = checkCRFields(r, prefix, exp, cr) && ok
	}

	ok = checkAssessments(r, prefix, exp.Assessments, cr.Assessments, m) && ok

	if ok {
		r.pass(prefix)
	}
}

// checkCRFields validates the pinned per-request fields (exact mode only).
func checkCRFields(r *report, prefix string, exp expectations.ChangeRequest, cr model.ChangeRequest) bool {
	ok := true

	if string(cr.Status) != exp.Status {
		r.fail(fmt.Sprintf("%s: status=%q, expected %q", prefix, cr.Status, exp.Status))
		ok = false
	}

	if cr.RiskTier.Name != exp.RiskTier.Name || cr.RiskTier.Risk != exp.RiskTier.Risk {
		r.fail(fmt.Sprintf("%s: riskTier={%s,%d}, expected {%s,%d}", prefix,
			cr.RiskTier.Name, cr.RiskTier.Risk, exp.RiskTier.Name, exp.RiskTier.Risk))
		ok = false
	}

	if cr.HasUnknownRisk != exp.HasUnknownRisk {
		r.fail(fmt.Sprintf("%s: hasUnknownRisk=%v, expected %v", prefix, cr.HasUnknownRisk, exp.HasUnknownRisk))
		ok = false
	}

	if !floatEq(cr.ImpactScore, exp.ImpactScore) {
		r.fail(fmt.Sprintf("%s: impactScore=%.1f, expected %.1f", prefix, cr.ImpactScore, exp.ImpactScore))
		ok = false
	}

	if exp.MergeEfficiency == nil {
		if cr.MergeEfficiency != nil {
			r.fail(fmt.Sprintf("%s: mergeEfficiency=%.4f, expected null", prefix, *cr.MergeEfficiency))
			ok = false
		}
	} else {
		if cr.MergeEfficiency == nil {
			r.fail(fmt.Sprintf("%s: mergeEfficiency=null, expected %.4f", prefix, *exp.MergeEfficiency))
			ok = false
		} else if !floatEq(*cr.MergeEfficiency, *exp.MergeEfficiency) {
			r.fail(fmt.Sprintf("%s: mergeEfficiency=%.4f, expected %.4f", prefix, *cr.MergeEfficiency, *exp.MergeEfficiency))
			ok = false
		}
	}

	if cr.Fixes.Total != exp.Fixes.Total {
		r.fail(fmt.Sprintf("%s: fixes.total=%d, expected %d", prefix, cr.Fixes.Total, exp.Fixes.Total))
		ok = false
	}

	if exp.SplitCandidate != nil {
		if cr.SplitCandidate == nil {
			r.fail(fmt.Sprintf("%s: splitCandidate is nil, expected %s", prefix, exp.SplitCandidate.DependencyName))
			ok = false
		} else if cr.SplitCandidate.DependencyName != exp.SplitCandidate.DependencyName {
			r.fail(fmt.Sprintf("%s: splitCandidate.dep=%q, expected %q", prefix,
				cr.SplitCandidate.DependencyName, exp.SplitCandidate.DependencyName))
			ok = false
		}
	}

	return ok
}

// checkAssessments validates the nested assessments by matching on the full
// identity (dependencyName + currentVersion + targetVersion). Falls back to
// positional matching when keys collide (same dep at same target from different
// current versions within different manifests).
//
// In exact mode the assessment count must match. In drift mode extra assessments
// are tolerated (a new advisory may surface a dependency), but every expected
// assessment must still be present, and its impact score is not pinned.
func checkAssessments(r *report, prefix string, expAssessments []expectations.Assessment, actAssessments []model.ChangeAssessment, m mode) bool {
	if m == modeExact && len(expAssessments) != len(actAssessments) {
		r.fail(fmt.Sprintf("%s: %d assessments, expected %d", prefix, len(actAssessments), len(expAssessments)))
		return false
	}

	// Build index of actual assessments by full identity.
	type key struct {
		name    string
		current string
		target  string
	}
	actByKey := make(map[key]model.ChangeAssessment, len(actAssessments))
	for _, a := range actAssessments {
		k := key{a.Change.DependencyName, normalize(a.Change.CurrentVersion), normalize(a.Change.TargetVersion)}
		actByKey[k] = a
	}

	ok := true
	for i, expA := range expAssessments {
		k := key{expA.Change.DependencyName, normalize(expA.Change.CurrentVersion), normalize(expA.Change.TargetVersion)}
		a, found := actByKey[k]
		if !found {
			// Exact mode may fall back to positional matching when counts are
			// equal; drift mode treats a missing known identity as a failure.
			if m == modeExact && i < len(actAssessments) {
				a = actAssessments[i]
			} else {
				r.fail(fmt.Sprintf("%s: assessment %s %s->%s not found", prefix,
					expA.Change.DependencyName, expA.Change.CurrentVersion, expA.Change.TargetVersion))
				ok = false
				continue
			}
		}

		aPrefix := fmt.Sprintf("%s > %s", prefix, expA.Change.DependencyName)

		// Change identity is driven by Renovate (capped versions), so it is
		// stable in both modes.
		if !versionsMatch(a.Change.CurrentVersion, expA.Change.CurrentVersion) {
			r.fail(fmt.Sprintf("%s: currentVersion=%q, expected %q", aPrefix, a.Change.CurrentVersion, expA.Change.CurrentVersion))
			ok = false
		}
		if a.Change.ChangeType.Name != expA.Change.ChangeType.Name {
			r.fail(fmt.Sprintf("%s: changeType.name=%q, expected %q", aPrefix, a.Change.ChangeType.Name, expA.Change.ChangeType.Name))
			ok = false
		}

		// Impact score drifts with the advisory set, so it is pinned only in exact mode.
		if m == modeExact && !floatEq(a.ImpactScore, expA.ImpactScore) {
			r.fail(fmt.Sprintf("%s: impactScore=%.1f, expected %.1f", aPrefix, a.ImpactScore, expA.ImpactScore))
			ok = false
		}

		ok = checkAdvisoryMatches(r, aPrefix, expA.AdvisoryMatches, a.AdvisoryMatches, m) && ok
	}

	return ok
}

// checkAdvisoryMatches validates advisory correlations by advisory ID. In exact
// mode the match count must equal the baseline; in drift mode extra matches are
// tolerated (new CVEs), but every expected match must still be present with its
// occurrence versions, since a fixed advisory does not stop being fixed.
func checkAdvisoryMatches(r *report, prefix string, expMatches []expectations.AdvisoryMatch, actMatches []model.AdvisoryMatch, m mode) bool {
	if m == modeExact && len(expMatches) != len(actMatches) {
		r.fail(fmt.Sprintf("%s: %d advisoryMatches, expected %d", prefix, len(actMatches), len(expMatches)))
		return false
	}

	// Index actual by advisory ID.
	actByID := make(map[string]model.AdvisoryMatch, len(actMatches))
	for _, mm := range actMatches {
		actByID[mm.Advisory.ID] = mm
	}

	ok := true
	for _, expM := range expMatches {
		act, found := actByID[expM.Advisory.ID]
		if !found {
			r.fail(fmt.Sprintf("%s: advisory %s not correlated", prefix, expM.Advisory.ID))
			ok = false
			continue
		}

		// Occurrence versions
		if !versionsMatch(act.Occurrence.AffectedVersion, expM.Occurrence.AffectedVersion) {
			r.fail(fmt.Sprintf("%s: %s affectedVersion=%q, expected %q", prefix,
				expM.Advisory.ID, act.Occurrence.AffectedVersion, expM.Occurrence.AffectedVersion))
			ok = false
		}
		if !versionsMatch(act.Occurrence.FixVersion, expM.Occurrence.FixVersion) {
			r.fail(fmt.Sprintf("%s: %s fixVersion=%q, expected %q", prefix,
				expM.Advisory.ID, act.Occurrence.FixVersion, expM.Occurrence.FixVersion))
			ok = false
		}
	}

	return ok
}

// noteUncorrelatedDrift reports, without failing, how the uncorrelated advisory
// set compares to the baseline. New uncorrelated advisories are expected as
// trivy publishes CVEs; a known one no longer present usually means it became
// correlated, which is surfaced for review rather than treated as a regression.
func noteUncorrelatedDrift(r *report, exp expectations.File, result model.AnalysisResult) {
	actByID := make(map[string]bool, len(result.UncorrelatedAdvisories))
	for _, a := range result.UncorrelatedAdvisories {
		actByID[a.ID] = true
	}

	var missing []string
	for _, expA := range exp.UncorrelatedAdvisories {
		if !actByID[expA.ID] {
			missing = append(missing, expA.ID)
		}
	}

	r.info(fmt.Sprintf("drift: %d uncorrelated advisories in result (baseline pinned %d)",
		len(result.UncorrelatedAdvisories), len(exp.UncorrelatedAdvisories)))
	if len(missing) > 0 {
		sort.Strings(missing)
		r.info(fmt.Sprintf("drift: %d baseline-uncorrelated advisories no longer uncorrelated: %s",
			len(missing), strings.Join(missing, ", ")))
	}
}

// checkUncorrelatedAdvisories validates the uncorrelated advisory list.
func checkUncorrelatedAdvisories(r *report, exp expectations.File, result model.AnalysisResult) {
	if len(exp.UncorrelatedAdvisories) == 0 {
		return
	}

	// Index actual uncorrelated by ID.
	actByID := make(map[string]model.Advisory, len(result.UncorrelatedAdvisories))
	for _, a := range result.UncorrelatedAdvisories {
		actByID[a.ID] = a
	}

	for _, expA := range exp.UncorrelatedAdvisories {
		act, found := actByID[expA.ID]
		if !found {
			r.fail(fmt.Sprintf("uncorrelated %s: not found in result", expA.ID))
			continue
		}

		// Severity (compare lowercase).
		actSev := strings.ToLower(act.Severity.Level)
		if actSev != expA.Severity {
			r.fail(fmt.Sprintf("uncorrelated %s: severity=%q, expected %q", expA.ID, actSev, expA.Severity))
		}

		// AddressedOccurrences (when specified in expectations).
		if expA.AddressedOccurrences > 0 && act.AddressedOccurrences != expA.AddressedOccurrences {
			r.fail(fmt.Sprintf("uncorrelated %s: addressedOccurrences=%d, expected %d",
				expA.ID, act.AddressedOccurrences, expA.AddressedOccurrences))
		}

		// OccurrenceCount (when specified).
		if expA.OccurrenceCount > 0 && len(act.Occurrences) != expA.OccurrenceCount {
			r.fail(fmt.Sprintf("uncorrelated %s: occurrenceCount=%d, expected %d",
				expA.ID, len(act.Occurrences), expA.OccurrenceCount))
		}
	}

	r.pass(fmt.Sprintf("uncorrelatedAdvisories (%d checked)", len(exp.UncorrelatedAdvisories)))
}

// --- Helpers ---

func versionsMatch(actual, expected string) bool {
	return normalize(actual) == normalize(expected)
}

func normalize(v string) string {
	v = strings.TrimSpace(v)
	v = strings.Trim(v, "\"")
	for _, prefix := range []string{"~>", "==", ">=", "<=", "^", "~", "=", "v"} {
		v = strings.TrimPrefix(v, prefix)
	}
	return strings.TrimSpace(v)
}

func floatEq(a, b float64) bool {
	return math.Abs(a-b) < 0.0001
}

// --- I/O ---

func loadResult(path string, expectedSchema string) (model.AnalysisResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return model.AnalysisResult{}, fmt.Errorf("reading result %s: %w", path, err)
	}

	// Pre-check schema version before full decode.
	var envelope struct {
		SchemaVersion string `json:"schemaVersion"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return model.AnalysisResult{}, fmt.Errorf("parsing result JSON: %w", err)
	}
	if envelope.SchemaVersion != expectedSchema {
		return model.AnalysisResult{}, fmt.Errorf("unsupported schemaVersion %q (expected %q)", envelope.SchemaVersion, expectedSchema)
	}

	var r model.AnalysisResult
	if err := json.Unmarshal(data, &r); err != nil {
		return model.AnalysisResult{}, fmt.Errorf("parsing result JSON: %w", err)
	}
	return r, nil
}
