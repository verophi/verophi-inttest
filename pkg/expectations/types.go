// Package expectations defines the expected E2E outcome structure.
// It models the single source of truth YAML that the verify tool
// compares against verophi's AnalysisResult (Schema 1.0).
package expectations

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// File represents the top-level YAML structure (Schema 1.0).
type File struct {
	SchemaVersion          string                 `yaml:"schemaVersion"`
	Correlation            Correlation            `yaml:"correlation"`
	Metrics                Metrics                `yaml:"metrics"`
	ChangeRequests         []ChangeRequest        `yaml:"changeRequests"`
	UncorrelatedAdvisories []UncorrelatedAdvisory `yaml:"uncorrelatedAdvisories,omitempty"`
}

// Correlation captures the expected platform and correlation state.
type Correlation struct {
	Status     string `yaml:"status"`
	Repository string `yaml:"repository"`
}

// Metrics captures the expected summary-level metrics.
type Metrics struct {
	TotalAdvisories      int            `yaml:"totalAdvisories"`
	Severity             SeverityCounts `yaml:"severity"`
	Correlated           int            `yaml:"correlated"`
	Uncorrelated         int            `yaml:"uncorrelated"`
	TotalImpactScore     float64        `yaml:"totalImpactScore"`
	ReducibleImpactScore float64        `yaml:"reducibleImpactScore"`
	MatchedRequests      int            `yaml:"matchedRequests"`
	UnmatchedRequests    int            `yaml:"unmatchedRequests"`
	UnparsedRequests     int            `yaml:"unparsedRequests"`
}

// SeverityCounts mirrors the severity breakdown.
type SeverityCounts struct {
	Critical int `yaml:"critical"`
	High     int `yaml:"high"`
	Medium   int `yaml:"medium"`
	Low      int `yaml:"low"`
}

// ChangeRequest represents an expected change request (MR/PR).
type ChangeRequest struct {
	Title           string          `yaml:"title"`
	Status          string          `yaml:"status"`
	RiskTier        ChangeType      `yaml:"riskTier"`
	HasUnknownRisk  bool            `yaml:"hasUnknownRisk"`
	ImpactScore     float64         `yaml:"impactScore"`
	MergeEfficiency *float64        `yaml:"mergeEfficiency"`
	Fixes           FixSummary      `yaml:"fixes"`
	SplitCandidate  *SplitCandidate `yaml:"splitCandidate,omitempty"`
	Notes           string          `yaml:"notes,omitempty"`
	Assessments     []Assessment    `yaml:"assessments"`
	Enabled         *bool           `yaml:"enabled,omitempty"`
}

// IsEnabled returns true unless explicitly disabled.
func (cr ChangeRequest) IsEnabled() bool {
	return cr.Enabled == nil || *cr.Enabled
}

// FixSummary is the per-request fix breakdown.
type FixSummary struct {
	Total    int `yaml:"total"`
	Critical int `yaml:"critical"`
	High     int `yaml:"high"`
	Medium   int `yaml:"medium"`
	Low      int `yaml:"low"`
}

// SplitCandidate describes a split hint on a request.
type SplitCandidate struct {
	DependencyName  string     `yaml:"dependencyName"`
	ImpactScore     float64    `yaml:"impactScore"`
	ShareOfRequest  float64    `yaml:"shareOfRequest"`
	RiskTier        ChangeType `yaml:"riskTier"`
	MergeEfficiency float64    `yaml:"mergeEfficiency"`
}

// ChangeType is the {name, risk} pair.
type ChangeType struct {
	Name string `yaml:"name"`
	Risk int    `yaml:"risk"`
}

// Assessment represents a per-dependency assessment within a change request.
type Assessment struct {
	Change          Change          `yaml:"change"`
	ImpactScore     float64         `yaml:"impactScore"`
	AdvisoryMatches []AdvisoryMatch `yaml:"advisoryMatches"`
}

// Change is the expected dependency change identity.
type Change struct {
	DependencyName string     `yaml:"dependencyName"`
	CurrentVersion string     `yaml:"currentVersion"`
	TargetVersion  string     `yaml:"targetVersion"`
	ChangeType     ChangeType `yaml:"changeType"`
}

// AdvisoryMatch is an expected advisory correlation.
type AdvisoryMatch struct {
	Advisory   AdvisoryRef        `yaml:"advisory"`
	Occurrence OccurrenceExpected `yaml:"occurrence"`
}

// AdvisoryRef is the identity-only advisory projection.
type AdvisoryRef struct {
	ID       string `yaml:"id"`
	Severity string `yaml:"severity"`
}

// OccurrenceExpected captures the pinned occurrence fields.
type OccurrenceExpected struct {
	AffectedVersion string `yaml:"affectedVersion"`
	FixVersion      string `yaml:"fixVersion"`
}

// UncorrelatedAdvisory represents an expected uncorrelated advisory.
type UncorrelatedAdvisory struct {
	ID                   string `yaml:"id"`
	Severity             string `yaml:"severity"`
	Dependency           string `yaml:"dependency"`
	Recommendation       string `yaml:"recommendation,omitempty"`
	AddressedOccurrences int    `yaml:"addressedOccurrences,omitempty"`
	OccurrenceCount      int    `yaml:"occurrenceCount,omitempty"`
}

// Load reads and parses the expectations YAML file.
func Load(path string) (File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return File{}, fmt.Errorf("reading expectations %s: %w", path, err)
	}
	var f File
	if err := yaml.Unmarshal(data, &f); err != nil {
		return File{}, fmt.Errorf("parsing expectations YAML: %w", err)
	}
	return f, nil
}
