package vuln_scanner

import "encoding/xml"

type ScanResults struct {
	XMLName xml.Name `xml:"results"`
	System  System   `xml:"system"`
}

type System struct {
	Definitions []Definition `xml:"definitions>definition"`
}

type Definition struct {
	DefinitionID string `xml:"definition_id,attr"`
	Result       string `xml:"result,attr"` // We only care where this is true
	Version      string `xml:"version,attr"`
}

// type Criteria struct {
// 	Operator         string             `xml:"operator,attr"`
// 	Result           string             `xml:"result,attr"`
// 	Criteria         []Criteria         `xml:"criteria"` // Nested criteria
// 	Criterion        []Criterion        `xml:"criterion"`
// 	ExtendDefinition []ExtendDefinition `xml:"extend_definition"`
// }

// type Criterion struct {
// 	TestRef string `xml:"test_ref,attr"`
// 	Version string `xml:"version,attr"`
// 	Result  string `xml:"result,attr"`
// }
