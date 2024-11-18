package vuln_scanner

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"slices"
	"strings"

	"github.com/hashicorp/go-hclog"
)

// downloadOvalContent: Gets the oval content at the desired URL and writes to the given location
func downloadOVALContent(url string, osvDownloadLocation string) (err error) {
	// Create the file
	out, err := os.Create(osvDownloadLocation)
	if err != nil {
		return err
	}
	defer out.Close()

	// Get the data
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Check server response
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %s", resp.Status)
	}

	// Writer the body to file
	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return err
	}

	return nil
}

// GetOVALContent: Gets the OVAL content for this Ubuntu version and returns the name of the XML
func GetOVALContent(logger hclog.Logger, oscapContentLocation string) (*string, error) {
	lsbReleaseCommand := exec.Command("lsb_release", "-cs")
	lsbRelease, err := lsbReleaseCommand.Output()
	if err != nil {
		logger.Error("error getting lsb_release output")
		return nil, err
	}
	osvFileXMLName := fmt.Sprintf("com.ubuntu.%v.usn.oval.xml", strings.Replace(string(lsbRelease), "\n", "", -1))
	// osvFileXMLLocation := fmt.Sprintf("%v/%v", oscapContentLocation, osvFileXMLName)
	osvFileDownloadName := fmt.Sprintf("%v.bz2", osvFileXMLName)
	osvFileDownloadLocation := fmt.Sprintf("%v/%v.bz2", oscapContentLocation, osvFileXMLName)

	logger.Info(fmt.Sprintf("Downloading file %v and storing at %v.", osvFileDownloadName, osvFileDownloadLocation))

	url := fmt.Sprintf("https://security-metadata.canonical.com/oval/%v", osvFileDownloadName)

	err = downloadOVALContent(url, osvFileDownloadLocation)
	if err != nil {
		logger.Error(fmt.Sprintf("could not download oval content with url '%v'", osvFileDownloadName))
		return nil, err
	}
	logger.Info("Succesfully downloaded OVAL content.")

	// Unzip the OVAL content
	unzipCommand := exec.Command("bunzip2", osvFileDownloadLocation)
	_, err = unzipCommand.Output()
	if err != nil {
		logger.Error(fmt.Sprintf("error unzipping OSV file: '%v'", osvFileDownloadLocation))
		return nil, err
	}

	return &osvFileXMLName, nil

}

func InstallRequiredPackages(logger hclog.Logger) error {
	// Install requirements
	updateOutput := exec.Command("sudo", "apt-get", "update")
	_, updateError := updateOutput.Output()
	if updateError != nil {
		logger.Error(fmt.Sprintf("error updating packages: %v", updateError))
		return updateError
	}

	output := exec.Command("sudo", "apt-get", "install", "-y", "libopenscap8", "bzip2")
	_, err := output.Output()
	if err != nil {
		logger.Error(fmt.Sprintf("error installing packages: %v", err))
		return err
	}
	logger.Info("Succesfully installed required packages.")
	return nil
}

// RunOSCAPSCan: Installs OSCAP, downloads the content, and runs a vulnerability scan
func RunOSCAPScan(logger hclog.Logger, oscapContentLocation string, ovalContentName string) (*string, error) {
	resultsLoc := fmt.Sprintf("%v/results.xml", oscapContentLocation)
	ovalContentLocation := fmt.Sprintf("%v/%v", oscapContentLocation, ovalContentName)
	scanCommand := exec.Command("oscap", "oval", "eval", "--results", resultsLoc, ovalContentLocation)
	_, err := scanCommand.Output()
	if err != nil {
		logger.Error("error performing scan OSV file")
		return nil, err
	}
	logger.Info("Succesfully ran OSCAP scan.")
	return &resultsLoc, nil
}

// GenerateReport: Runs an OSCAP scan on the target machine and returns the report
func GetScanReport(logger hclog.Logger, resultsLocation string) (*ScanResults, error) {
	// Return the XML
	file, err := os.Open(resultsLocation)
	if err != nil {
		logger.Error("could not open scan results")
		return nil, err
	}
	xmlFile, err := io.ReadAll(file)
	if err != nil {
		logger.Error("could not read scan results")
		return nil, err
	}
	scanResults := ScanResults{}
	marshalErr := xml.Unmarshal(xmlFile, &scanResults)
	if marshalErr != nil {
		logger.Error("could not format scan results")
		return nil, marshalErr
	}
	return &scanResults, nil
}

// ProcessReport: Process the report struct into a format that can be evaluated by our policies
func ProcessReport(logger hclog.Logger, scanResults *ScanResults) []Violation {
	vulns := make([]Violation, 0)
	violationIDs := make([]string, 0)
	for _, res := range scanResults.ResultDefinitions {
		if res.Result == "true" {
			violationIDs = append(violationIDs, res.DefinitionID)
		}
	}
	logger.Debug(fmt.Sprintf("Found %v violations", len(violationIDs)))
	for _, def := range scanResults.OvalDefinitions {
		if slices.Contains(violationIDs, def.DefinitionID) {
			for _, ref := range def.Metadata.References {
				if ref.RefSource != "CVE" {
					continue
				}
				vulns = append(vulns, Violation{CVEID: ref.RefID, Severity: def.Metadata.Advisory.Severity, Description: def.Metadata.Description})
			}
		}

	}
	logger.Debug(fmt.Sprintf("Found %v vulnerabilities", len(vulns)))
	return vulns
}
