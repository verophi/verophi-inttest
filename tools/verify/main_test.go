package main

import (
	"strings"
	"testing"

	"github.com/verophi/verophi-inttest/pkg/expectations"
	"github.com/verophi/verophi/pkg/model"
)

func float64Ptr(f float64) *float64 { return &f }

// reportText joins the report lines so tests can assert on their content.
func reportText(r report) string { return strings.Join(r.lines, "\n") }

func makeMinimalResult() model.AnalysisResult {
	return model.AnalysisResult{
		SchemaVersion: "1.0",
		Correlation:   model.Correlation{Status: "complete", Platform: "gitlab", Repository: "g/p"},
		AdvisorySummary: model.AdvisorySummary{
			Total:          3,
			Correlated:     2,
			Uncorrelated:   1,
			SeverityCounts: model.SeverityCounts{Critical: 1, High: 1, Medium: 1},
		},
		TotalImpactScore:     14,
		ReducibleImpactScore: float64Ptr(10),
		ChangeRequests: []model.ChangeRequest{
			{
				Title:           "fix(deps): update dependency lodash to v4.17.21",
				Status:          model.StatusMatched,
				RiskTier:        model.ChangePatch,
				HasUnknownRisk:  false,
				ImpactScore:     6,
				MergeEfficiency: float64Ptr(6),
				Fixes:           model.FixSummary{Total: 2, SeverityCounts: model.SeverityCounts{High: 1, Medium: 1}},
				Assessments: []model.ChangeAssessment{
					{
						Change: model.Change{
							DependencyName: "lodash",
							CurrentVersion: "4.17.20",
							TargetVersion:  "4.17.21",
							ChangeType:     model.ChangePatch,
						},
						ImpactScore: 6,
						AdvisoryMatches: []model.AdvisoryMatch{
							{
								Advisory:   model.AdvisoryRef{ID: "CVE-2021-23337", Severity: model.SeverityHigh},
								Occurrence: model.Occurrence{AffectedVersion: "4.17.20", FixVersion: "4.17.21", DependencyName: "lodash", Ecosystem: "npm"},
							},
							{
								Advisory:   model.AdvisoryRef{ID: "CVE-2020-28500", Severity: model.SeverityMedium},
								Occurrence: model.Occurrence{AffectedVersion: "4.17.20", FixVersion: "4.17.21", DependencyName: "lodash", Ecosystem: "npm"},
							},
						},
					},
				},
			},
		},
		UncorrelatedAdvisories: []model.Advisory{
			{
				ID:             "CVE-2023-1111",
				Severity:       model.SeverityCritical,
				Recommendation: "Upgrade openssl to version 1.1.1t",
				Occurrences:    []model.Occurrence{{DependencyName: "openssl", AffectedVersion: "1.1.1", FixVersion: "1.1.1t"}},
			},
		},
	}
}

func makeMinimalExpectations() expectations.File {
	return expectations.File{
		SchemaVersion: "1.0",
		Correlation:   expectations.Correlation{Status: "complete", Repository: "g/p"},
		Metrics: expectations.Metrics{
			TotalAdvisories:      3,
			Severity:             expectations.SeverityCounts{Critical: 1, High: 1, Medium: 1},
			Correlated:           2,
			Uncorrelated:         1,
			TotalImpactScore:     14,
			ReducibleImpactScore: 10,
			MatchedRequests:      1,
			UnmatchedRequests:    0,
			UnparsedRequests:     0,
		},
		ChangeRequests: []expectations.ChangeRequest{
			{
				Title:           "fix(deps): update dependency lodash to v4.17.21",
				Status:          "matched",
				RiskTier:        expectations.ChangeType{Name: "patch", Risk: 1},
				HasUnknownRisk:  false,
				ImpactScore:     6,
				MergeEfficiency: float64Ptr(6),
				Fixes:           expectations.FixSummary{Total: 2, High: 1, Medium: 1},
				Assessments: []expectations.Assessment{
					{
						Change: expectations.Change{
							DependencyName: "lodash",
							CurrentVersion: "4.17.20",
							TargetVersion:  "4.17.21",
							ChangeType:     expectations.ChangeType{Name: "patch", Risk: 1},
						},
						ImpactScore: 6,
						AdvisoryMatches: []expectations.AdvisoryMatch{
							{
								Advisory:   expectations.AdvisoryRef{ID: "CVE-2021-23337", Severity: "high"},
								Occurrence: expectations.OccurrenceExpected{AffectedVersion: "4.17.20", FixVersion: "4.17.21"},
							},
							{
								Advisory:   expectations.AdvisoryRef{ID: "CVE-2020-28500", Severity: "medium"},
								Occurrence: expectations.OccurrenceExpected{AffectedVersion: "4.17.20", FixVersion: "4.17.21"},
							},
						},
					},
				},
			},
		},
		UncorrelatedAdvisories: []expectations.UncorrelatedAdvisory{
			{
				ID:             "CVE-2023-1111",
				Severity:       "critical",
				Dependency:     "openssl@1.1.1",
				Recommendation: "Upgrade openssl to version 1.1.1t",
			},
		},
	}
}

// --- Exact mode ---

func TestVerify_AllMatch(t *testing.T) {
	r := verify(makeMinimalExpectations(), makeMinimalResult(), modeExact)
	if r.Failed != 0 {
		t.Logf("\n%s", reportText(r))
		t.Errorf("expected 0 failures, got %d", r.Failed)
	}
}

func TestVerify_SchemaVersionMismatch(t *testing.T) {
	exp := makeMinimalExpectations()
	result := makeMinimalResult()
	result.SchemaVersion = "2.0"

	r := verify(exp, result, modeExact)
	if r.Failed < 1 {
		t.Errorf("expected at least 1 failure for wrong schema, got %d", r.Failed)
	}
}

func TestVerify_StructuralInconsistency(t *testing.T) {
	exp := makeMinimalExpectations()
	result := makeMinimalResult()
	result.AdvisorySummary.Uncorrelated = 5 // breaks correlated + uncorrelated == total

	r := verify(exp, result, modeExact)
	if !strings.Contains(reportText(r), "correlated") || !strings.Contains(reportText(r), "total") {
		t.Error("expected structural failure for partition check")
	}
}

func TestVerify_MissingChangeRequest(t *testing.T) {
	exp := makeMinimalExpectations()
	result := makeMinimalResult()
	result.ChangeRequests[0].Title = "something else"

	r := verify(exp, result, modeExact)
	if r.Failed < 1 {
		t.Errorf("expected failure for missing CR, got %d failures", r.Failed)
	}
}

func TestVerify_StatusMismatch(t *testing.T) {
	exp := makeMinimalExpectations()
	result := makeMinimalResult()
	result.ChangeRequests[0].Status = model.StatusUnmatched

	r := verify(exp, result, modeExact)
	if !strings.Contains(reportText(r), "status") {
		t.Error("expected status mismatch failure")
	}
}

func TestVerify_AdvisoryNotCorrelated(t *testing.T) {
	exp := makeMinimalExpectations()
	result := makeMinimalResult()
	// Remove one advisory match.
	result.ChangeRequests[0].Assessments[0].AdvisoryMatches =
		result.ChangeRequests[0].Assessments[0].AdvisoryMatches[:1]

	r := verify(exp, result, modeExact)
	if r.Failed < 1 {
		t.Errorf("expected failure for missing advisory match, got %d failures", r.Failed)
	}
}

func TestVerify_DisabledCRSkipped(t *testing.T) {
	exp := makeMinimalExpectations()
	disabled := false
	exp.ChangeRequests = append(exp.ChangeRequests, expectations.ChangeRequest{
		Title:   "disabled-request",
		Status:  "matched",
		Enabled: &disabled,
	})

	result := makeMinimalResult()

	r := verify(exp, result, modeExact)
	if r.Failed != 0 {
		t.Logf("\n%s", reportText(r))
		t.Errorf("expected 0 failures, got %d", r.Failed)
	}
}

func TestVerify_NullMergeEfficiency(t *testing.T) {
	exp := makeMinimalExpectations()
	exp.ChangeRequests[0].MergeEfficiency = nil
	exp.ChangeRequests[0].Status = "unparsed"
	exp.ChangeRequests[0].RiskTier = expectations.ChangeType{Name: "", Risk: 0}
	exp.ChangeRequests[0].ImpactScore = 0
	exp.ChangeRequests[0].Fixes = expectations.FixSummary{}
	exp.ChangeRequests[0].Assessments = nil

	result := makeMinimalResult()
	result.ChangeRequests[0].MergeEfficiency = nil
	result.ChangeRequests[0].Status = model.StatusUnparsed
	result.ChangeRequests[0].RiskTier = model.ChangeUnknown
	result.ChangeRequests[0].ImpactScore = 0
	result.ChangeRequests[0].Fixes = model.FixSummary{}
	result.ChangeRequests[0].Assessments = nil
	result.AdvisorySummary.Correlated = 0
	result.AdvisorySummary.Uncorrelated = 3
	exp.Metrics.Correlated = 0
	exp.Metrics.Uncorrelated = 3
	exp.Metrics.MatchedRequests = 0
	exp.Metrics.UnparsedRequests = 1

	r := verify(exp, result, modeExact)
	if strings.Contains(reportText(r), "✗") && strings.Contains(reportText(r), "mergeEfficiency") {
		t.Error("should not fail on null mergeEfficiency match")
	}
}

func TestVerify_SplitCandidate(t *testing.T) {
	exp := makeMinimalExpectations()
	exp.ChangeRequests[0].SplitCandidate = &expectations.SplitCandidate{
		DependencyName:  "lodash",
		ImpactScore:     6,
		ShareOfRequest:  1,
		RiskTier:        expectations.ChangeType{Name: "patch", Risk: 1},
		MergeEfficiency: 6,
	}

	result := makeMinimalResult()
	result.ChangeRequests[0].SplitCandidate = &model.SplitCandidate{
		DependencyName:  "lodash",
		ImpactScore:     6,
		ShareOfRequest:  1,
		RiskTier:        model.ChangePatch,
		MergeEfficiency: 6,
	}

	r := verify(exp, result, modeExact)
	if r.Failed != 0 {
		t.Logf("\n%s", reportText(r))
		t.Errorf("expected 0 failures, got %d", r.Failed)
	}
}

func TestVerify_SplitCandidateMissing(t *testing.T) {
	exp := makeMinimalExpectations()
	exp.ChangeRequests[0].SplitCandidate = &expectations.SplitCandidate{
		DependencyName: "lodash",
	}

	result := makeMinimalResult()
	// No split candidate in result.

	r := verify(exp, result, modeExact)
	if !strings.Contains(reportText(r), "splitCandidate") {
		t.Error("expected splitCandidate failure")
	}
}

func TestVerify_UncorrelatedAdvisoryMissing(t *testing.T) {
	exp := makeMinimalExpectations()
	result := makeMinimalResult()
	result.UncorrelatedAdvisories = nil

	r := verify(exp, result, modeExact)
	if r.Failed < 1 {
		t.Errorf("expected failure for missing uncorrelated advisory, got %d failures", r.Failed)
	}
}

func TestVerify_Exact_FailsOnExtraAdvisoryMatch(t *testing.T) {
	exp := makeMinimalExpectations()
	result := makeMinimalResult()
	// A new CVE on lodash: exact mode pins the count, so this must fail.
	result.ChangeRequests[0].Assessments[0].AdvisoryMatches = append(
		result.ChangeRequests[0].Assessments[0].AdvisoryMatches,
		model.AdvisoryMatch{
			Advisory:   model.AdvisoryRef{ID: "CVE-2099-0001", Severity: model.SeverityLow},
			Occurrence: model.Occurrence{AffectedVersion: "4.17.20", FixVersion: "4.17.21"},
		},
	)

	r := verify(exp, result, modeExact)
	if r.Failed < 1 {
		t.Error("exact mode should fail on an extra advisory match (count mismatch)")
	}
}

// --- Drift mode ---

func TestVerify_Drift_AllMatch(t *testing.T) {
	r := verify(makeMinimalExpectations(), makeMinimalResult(), modeDrift)
	if r.Failed != 0 {
		t.Logf("\n%s", reportText(r))
		t.Errorf("expected 0 failures, got %d", r.Failed)
	}
}

func TestVerify_Drift_ToleratesNewAdvisoriesAndScoreChanges(t *testing.T) {
	exp := makeMinimalExpectations()
	result := makeMinimalResult()

	// Simulate a live trivy run that publishes new CVEs: an extra match on
	// lodash, an extra change request, an extra uncorrelated advisory, and the
	// score/status/metric shifts that follow. None of this should fail drift.
	result.ChangeRequests[0].Assessments[0].AdvisoryMatches = append(
		result.ChangeRequests[0].Assessments[0].AdvisoryMatches,
		model.AdvisoryMatch{
			Advisory:   model.AdvisoryRef{ID: "CVE-2099-0001", Severity: model.SeverityHigh},
			Occurrence: model.Occurrence{AffectedVersion: "4.17.20", FixVersion: "4.17.21"},
		},
	)
	result.ChangeRequests[0].ImpactScore = 99
	result.ChangeRequests[0].Assessments[0].ImpactScore = 99
	result.ChangeRequests[0].Fixes = model.FixSummary{Total: 3, SeverityCounts: model.SeverityCounts{High: 2, Medium: 1}}
	result.ChangeRequests = append(result.ChangeRequests, model.ChangeRequest{
		Title:    "fix(deps): update dependency newcomer to v2",
		Status:   model.StatusMatched,
		RiskTier: model.ChangeMajor,
	})
	result.UncorrelatedAdvisories = append(result.UncorrelatedAdvisories, model.Advisory{
		ID:       "CVE-2099-0002",
		Severity: model.SeverityMedium,
	})
	result.AdvisorySummary = model.AdvisorySummary{
		Total:          5,
		Correlated:     3,
		Uncorrelated:   2,
		SeverityCounts: model.SeverityCounts{Critical: 1, High: 2, Medium: 2},
	}

	r := verify(exp, result, modeDrift)
	if r.Failed != 0 {
		t.Logf("\n%s", reportText(r))
		t.Errorf("drift should tolerate new advisories and score changes, got %d failures", r.Failed)
	}
}

func TestVerify_Drift_FailsOnMissingKnownMatch(t *testing.T) {
	exp := makeMinimalExpectations()
	result := makeMinimalResult()
	// A historically fixed CVE that stops being correlated is a real regression.
	result.ChangeRequests[0].Assessments[0].AdvisoryMatches =
		result.ChangeRequests[0].Assessments[0].AdvisoryMatches[:1]

	r := verify(exp, result, modeDrift)
	if r.Failed < 1 {
		t.Error("drift should fail when a known advisory match disappears")
	}
}

func TestVerify_Drift_FailsOnMissingChangeRequest(t *testing.T) {
	exp := makeMinimalExpectations()
	result := makeMinimalResult()
	result.ChangeRequests[0].Title = "something else"

	r := verify(exp, result, modeDrift)
	if r.Failed < 1 {
		t.Error("drift should fail when a known change request disappears")
	}
}

func TestVerify_Drift_FailsOnChangedFixVersion(t *testing.T) {
	exp := makeMinimalExpectations()
	result := makeMinimalResult()
	// The fix version of a known correlation is an immutable historical fact.
	result.ChangeRequests[0].Assessments[0].AdvisoryMatches[0].Occurrence.FixVersion = "9.9.9"

	r := verify(exp, result, modeDrift)
	if !strings.Contains(reportText(r), "fixVersion") {
		t.Error("drift should fail when a known fix version changes")
	}
}

func TestVerify_Drift_FailsOnChangedChangeType(t *testing.T) {
	exp := makeMinimalExpectations()
	result := makeMinimalResult()
	// Change identity comes from Renovate and is pinned in both modes.
	result.ChangeRequests[0].Assessments[0].Change.ChangeType = model.ChangeMajor

	r := verify(exp, result, modeDrift)
	if !strings.Contains(reportText(r), "changeType") {
		t.Error("drift should fail when a change type changes")
	}
}

func TestVerify_Drift_EnforcesPartitionInvariant(t *testing.T) {
	exp := makeMinimalExpectations()
	result := makeMinimalResult()
	result.AdvisorySummary.Uncorrelated = 5 // breaks correlated + uncorrelated == total

	r := verify(exp, result, modeDrift)
	if !strings.Contains(reportText(r), "total") {
		t.Error("drift should still enforce the partition invariant")
	}
}

func TestVerify_Drift_IgnoresUncorrelatedSubset(t *testing.T) {
	exp := makeMinimalExpectations()
	result := makeMinimalResult()
	// A baseline-uncorrelated advisory that is now absent (e.g. became
	// correlated) is reported as a note, not a failure.
	result.UncorrelatedAdvisories = nil
	result.AdvisorySummary = model.AdvisorySummary{Total: 2, Correlated: 2, Uncorrelated: 0,
		SeverityCounts: model.SeverityCounts{High: 1, Medium: 1}}

	r := verify(exp, result, modeDrift)
	if r.Failed != 0 {
		t.Logf("\n%s", reportText(r))
		t.Errorf("drift should not fail on a shrinking uncorrelated set, got %d failures", r.Failed)
	}
	if !strings.Contains(reportText(r), "no longer uncorrelated") {
		t.Error("drift should note baseline-uncorrelated advisories that are now absent")
	}
}

// --- mode parsing ---

func TestParseMode(t *testing.T) {
	cases := []struct {
		in      string
		want    mode
		wantErr bool
	}{
		{"exact", modeExact, false},
		{"drift", modeDrift, false},
		{"", modeExact, true},
		{"strict", modeExact, true},
	}
	for _, tc := range cases {
		got, err := parseMode(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("parseMode(%q): expected error", tc.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseMode(%q): unexpected error %v", tc.in, err)
		}
		if got != tc.want {
			t.Errorf("parseMode(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestModeString(t *testing.T) {
	if modeExact.String() != "exact" {
		t.Errorf("modeExact.String() = %q", modeExact.String())
	}
	if modeDrift.String() != "drift" {
		t.Errorf("modeDrift.String() = %q", modeDrift.String())
	}
}

func TestNormalize(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"4.17.20", "4.17.20"},
		{"v0.16.0", "0.16.0"},
		{"==9.0.0", "9.0.0"},
		{"^2.2.1", "2.2.1"},
		{"~> 1.0", "1.0"},
		{"=0.20.8", "0.20.8"},
		{" \"6.1.4\" ", "6.1.4"},
	}
	for _, tc := range cases {
		got := normalize(tc.input)
		if got != tc.want {
			t.Errorf("normalize(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}
