package expectations

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_Valid(t *testing.T) {
	content := `schemaVersion: "1.0"
correlation:
    status: complete
    repository: verophi/test-fixtures
metrics:
    totalAdvisories: 10
    severity: {critical: 2, high: 4, medium: 3, low: 1}
    correlated: 6
    uncorrelated: 4
    totalImpactScore: 50
    reducibleImpactScore: 30
    matchedRequests: 2
    unmatchedRequests: 1
    unparsedRequests: 0
changeRequests:
    - title: 'fix(deps): update dependency lodash to v4.17.21'
      status: matched
      riskTier: {name: patch, risk: 1}
      hasUnknownRisk: false
      impactScore: 10
      mergeEfficiency: 10
      fixes: {total: 2, critical: 0, high: 1, medium: 1, low: 0}
      assessments:
        - change:
            dependencyName: lodash
            currentVersion: "4.17.20"
            targetVersion: "4.17.21"
            changeType: {name: patch, risk: 1}
          impactScore: 10
          advisoryMatches:
            - advisory: {id: CVE-2021-23337, severity: high}
              occurrence: {affectedVersion: 4.17.20, fixVersion: 4.17.21}
            - advisory: {id: CVE-2020-28500, severity: medium}
              occurrence: {affectedVersion: 4.17.20, fixVersion: 4.17.21}
    - title: 'chore(deps): update dependency express to v5'
      status: unmatched
      riskTier: {name: major, risk: 3}
      hasUnknownRisk: false
      impactScore: 0
      mergeEfficiency: 0
      fixes: {total: 0, critical: 0, high: 0, medium: 0, low: 0}
      enabled: false
      assessments:
        - change:
            dependencyName: express
            currentVersion: "4.17.1"
            targetVersion: "5.0.0"
            changeType: {name: major, risk: 3}
          impactScore: 0
          advisoryMatches: []
uncorrelatedAdvisories:
    - id: CVE-2023-1111
      severity: critical
      dependency: openssl@1.1.1
      recommendation: Upgrade openssl to version 1.1.1t
`
	path := writeTemp(t, content)

	f, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}

	if f.SchemaVersion != "1.0" {
		t.Errorf("schemaVersion = %q, want 1.0", f.SchemaVersion)
	}
	if f.Correlation.Status != "complete" {
		t.Errorf("correlation.status = %q", f.Correlation.Status)
	}
	if f.Correlation.Repository != "verophi/test-fixtures" {
		t.Errorf("correlation.repository = %q", f.Correlation.Repository)
	}
	if f.Metrics.TotalAdvisories != 10 {
		t.Errorf("metrics.totalAdvisories = %d", f.Metrics.TotalAdvisories)
	}
	if f.Metrics.Correlated != 6 {
		t.Errorf("metrics.correlated = %d", f.Metrics.Correlated)
	}
	if f.Metrics.Uncorrelated != 4 {
		t.Errorf("metrics.uncorrelated = %d", f.Metrics.Uncorrelated)
	}
	if f.Metrics.TotalImpactScore != 50 {
		t.Errorf("metrics.totalImpactScore = %f", f.Metrics.TotalImpactScore)
	}
	if f.Metrics.ReducibleImpactScore != 30 {
		t.Errorf("metrics.reducibleImpactScore = %f", f.Metrics.ReducibleImpactScore)
	}
	if f.Metrics.MatchedRequests != 2 {
		t.Errorf("metrics.matchedRequests = %d", f.Metrics.MatchedRequests)
	}

	if len(f.ChangeRequests) != 2 {
		t.Fatalf("expected 2 changeRequests, got %d", len(f.ChangeRequests))
	}

	cr := f.ChangeRequests[0]
	if cr.Title != "fix(deps): update dependency lodash to v4.17.21" {
		t.Errorf("title = %q", cr.Title)
	}
	if cr.Status != "matched" {
		t.Errorf("status = %q", cr.Status)
	}
	if cr.RiskTier.Name != "patch" || cr.RiskTier.Risk != 1 {
		t.Errorf("riskTier = %+v", cr.RiskTier)
	}
	if cr.ImpactScore != 10 {
		t.Errorf("impactScore = %f", cr.ImpactScore)
	}
	if cr.MergeEfficiency == nil || *cr.MergeEfficiency != 10 {
		t.Errorf("mergeEfficiency = %v", cr.MergeEfficiency)
	}
	if cr.Fixes.Total != 2 || cr.Fixes.High != 1 || cr.Fixes.Medium != 1 {
		t.Errorf("fixes = %+v", cr.Fixes)
	}
	if !cr.IsEnabled() {
		t.Error("first request should be enabled")
	}
	if len(cr.Assessments) != 1 {
		t.Fatalf("expected 1 assessment, got %d", len(cr.Assessments))
	}

	a := cr.Assessments[0]
	if a.Change.DependencyName != "lodash" {
		t.Errorf("change.dependencyName = %q", a.Change.DependencyName)
	}
	if a.Change.ChangeType.Name != "patch" || a.Change.ChangeType.Risk != 1 {
		t.Errorf("change.changeType = %+v", a.Change.ChangeType)
	}
	if len(a.AdvisoryMatches) != 2 {
		t.Fatalf("expected 2 advisoryMatches, got %d", len(a.AdvisoryMatches))
	}
	if a.AdvisoryMatches[0].Advisory.ID != "CVE-2021-23337" {
		t.Errorf("advisoryMatches[0].advisory.id = %q", a.AdvisoryMatches[0].Advisory.ID)
	}
	if a.AdvisoryMatches[0].Occurrence.AffectedVersion != "4.17.20" {
		t.Errorf("advisoryMatches[0].occurrence.affectedVersion = %q", a.AdvisoryMatches[0].Occurrence.AffectedVersion)
	}

	cr2 := f.ChangeRequests[1]
	if cr2.IsEnabled() {
		t.Error("second request should be disabled")
	}

	if len(f.UncorrelatedAdvisories) != 1 {
		t.Fatalf("expected 1 uncorrelated advisory, got %d", len(f.UncorrelatedAdvisories))
	}
	ua := f.UncorrelatedAdvisories[0]
	if ua.ID != "CVE-2023-1111" {
		t.Errorf("uncorrelatedAdvisories[0].id = %q", ua.ID)
	}
	if ua.Severity != "critical" {
		t.Errorf("uncorrelatedAdvisories[0].severity = %q", ua.Severity)
	}
	if ua.Recommendation != "Upgrade openssl to version 1.1.1t" {
		t.Errorf("uncorrelatedAdvisories[0].recommendation = %q", ua.Recommendation)
	}
}

func TestLoad_NullMergeEfficiency(t *testing.T) {
	content := `schemaVersion: "1.0"
correlation:
    status: complete
    repository: test/repo
metrics:
    totalAdvisories: 1
    severity: {critical: 0, high: 0, medium: 0, low: 1}
    correlated: 0
    uncorrelated: 1
    totalImpactScore: 1
    reducibleImpactScore: 0
    matchedRequests: 1
    unmatchedRequests: 0
    unparsedRequests: 0
changeRequests:
    - title: 'chore(deps): lock file maintenance'
      status: unparsed
      riskTier: {name: "", risk: 0}
      hasUnknownRisk: false
      impactScore: 0
      mergeEfficiency: null
      fixes: {total: 0, critical: 0, high: 0, medium: 0, low: 0}
      assessments: []
`
	path := writeTemp(t, content)
	f, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.ChangeRequests) != 1 {
		t.Fatalf("expected 1 request, got %d", len(f.ChangeRequests))
	}
	if f.ChangeRequests[0].MergeEfficiency != nil {
		t.Errorf("expected nil mergeEfficiency, got %v", f.ChangeRequests[0].MergeEfficiency)
	}
}

func TestLoad_SplitCandidate(t *testing.T) {
	content := `schemaVersion: "1.0"
correlation:
    status: complete
    repository: test/repo
metrics:
    totalAdvisories: 1
    severity: {critical: 1, high: 0, medium: 0, low: 0}
    correlated: 1
    uncorrelated: 0
    totalImpactScore: 8
    reducibleImpactScore: 8
    matchedRequests: 1
    unmatchedRequests: 0
    unparsedRequests: 0
changeRequests:
    - title: 'fix(deps): update split-candidate-group'
      status: matched
      riskTier: {name: major, risk: 3}
      hasUnknownRisk: false
      impactScore: 8
      mergeEfficiency: 2.6666666666666665
      fixes: {total: 1, critical: 1, high: 0, medium: 0, low: 0}
      splitCandidate:
        dependencyName: minimist
        impactScore: 8
        shareOfRequest: 1
        riskTier: {name: patch, risk: 1}
        mergeEfficiency: 8
      assessments:
        - change:
            dependencyName: minimist
            currentVersion: 1.2.5
            targetVersion: 1.2.6
            changeType: {name: patch, risk: 1}
          impactScore: 8
          advisoryMatches:
            - advisory: {id: CVE-2021-44906, severity: critical}
              occurrence: {affectedVersion: 1.2.5, fixVersion: 1.2.6}
`
	path := writeTemp(t, content)
	f, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	cr := f.ChangeRequests[0]
	if cr.SplitCandidate == nil {
		t.Fatal("expected splitCandidate to be non-nil")
	}
	if cr.SplitCandidate.DependencyName != "minimist" {
		t.Errorf("splitCandidate.dependencyName = %q", cr.SplitCandidate.DependencyName)
	}
	if cr.SplitCandidate.ShareOfRequest != 1 {
		t.Errorf("splitCandidate.shareOfRequest = %f", cr.SplitCandidate.ShareOfRequest)
	}
}

func TestLoad_FileNotFound(t *testing.T) {
	_, err := Load("/nonexistent/path.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	path := writeTemp(t, "{{invalid yaml")
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "expectations.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}
