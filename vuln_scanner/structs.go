package vuln_scanner

import "encoding/xml"

type KnownVulnerability struct {
	CVEID       string `json:"cve_id"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
}

type ScanResults struct {
	XMLName           xml.Name           `xml:"oval_results"`
	OvalDefinitions   []OvalDefinition   `xml:"oval_definitions>definitions>definition"`
	ResultDefinitions []ResultDefinition `xml:"results>system>definitions>definition"`
}

// type OvalDefinitions struct {
// 	Definitions []Definition `xml:"definitions>definition"`
// }

// type OvalResults struct {
// 	XMLName xml.Name `xml:"results"`
// 	System  System   `xml:"system"`
// }

type OvalDefinition struct {
	DefinitionID string   `xml:"id,attr"`
	Metadata     Metadata `xml:"metadata"`
}

// type System struct {
// 	Definitions []ResultDefinition `xml:"definitions>definition"`
// }

type Metadata struct {
	Advisory    Advisory    `xml:"advisory"`
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
