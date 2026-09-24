package report

import (
	"encoding/json"
	"fmt"

	"github.com/sriharifortitude/credsweep/internal/detect"
)

// SARIF 2.1.0, the subset GitHub's code scanning UI reads: one run, one
// tool driver with every rule declared up front, and one result per
// finding not on the allowlist. An allowed finding is omitted entirely --
// SARIF is where a reviewer looks for open problems, and the JSON report
// is where "what did we allow and why" stays visible. The message never
// carries more than the already-redacted value; SARIF results can end up
// posted in a PR check, which is exactly the kind of place a raw secret
// must never land.
type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string                 `json:"id"`
	ShortDescription sarifText              `json:"shortDescription"`
	Properties       map[string]interface{} `json:"properties"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifText       `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

func SARIF(r Result) ([]byte, error) {
	seen := map[string]bool{}
	var ruleDefs []sarifRule
	for _, def := range detect.All() {
		if seen[def.ID()] {
			continue
		}
		seen[def.ID()] = true
		ruleDefs = append(ruleDefs, sarifRule{
			ID:               def.ID(),
			ShortDescription: sarifText{Text: def.Description()},
			Properties:       map[string]interface{}{"severity": string(def.Severity())},
		})
	}

	var results []sarifResult
	for _, row := range r.Rows {
		if row.Allowed {
			continue
		}
		results = append(results, sarifResult{
			RuleID:  row.RuleID,
			Level:   sarifLevel(row.Severity),
			Message: sarifText{Text: fmt.Sprintf("%s: %s", ruleDescription(row.RuleID, ruleDefs), row.Redacted)},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: row.Path},
					Region:           sarifRegion{StartLine: row.Line},
				},
			}},
		})
	}

	log := sarifLog{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool:    sarifTool{Driver: sarifDriver{Name: "credsweep", InformationURI: "https://github.com/sriharifortitude/credsweep", Rules: ruleDefs}},
			Results: results,
		}},
	}
	return json.MarshalIndent(log, "", "  ")
}

func ruleDescription(id string, defs []sarifRule) string {
	for _, d := range defs {
		if d.ID == id {
			return d.ShortDescription.Text
		}
	}
	return id
}

func sarifLevel(s detect.Severity) string {
	switch s {
	case detect.Critical, detect.High:
		return "error"
	default:
		return "warning"
	}
}
