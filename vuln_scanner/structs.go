package vuln_scanner

import "encoding/xml"

// Violation represents the structure used in the OPA policy
type Violation struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	CVEID       string `json:"cve_id"`
}

type ScanResults struct {
	XMLName           xml.Name           `xml:"oval_results"`
	OvalDefinitions   []OvalDefinition   `xml:"oval_definitions>definitions>definition"`
	ResultDefinitions []ResultDefinition `xml:"results>system>definitions>definition"`
}

type OvalDefinition struct {
	DefinitionID string   `xml:"id,attr"`
	Metadata     Metadata `xml:"metadata"`
}

type Metadata struct {
	Advisory    Advisory    `xml:"advisory"`
	Title       string      `xml:"title"`
	Description string      `xml:"description"`
	References  []Reference `xml:"reference"`
}

type Advisory struct {
	Severity string `xml:"severity"`
	// CVEs []CVE `xml:"cve"` Potentially want this
}

type Reference struct {
	RefSource string `xml:"source,attr"`
	RefID     string `xml:"ref_id,attr"`
}

type ResultDefinition struct {
	DefinitionID string `xml:"definition_id,attr"`
	Result       string `xml:"result,attr"` // We only care where this is true
	Version      string `xml:"version,attr"`
}
