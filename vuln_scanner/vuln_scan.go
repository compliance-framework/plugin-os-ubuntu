package vuln_scanner

import (
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"

	"github.com/hashicorp/go-hclog"
	aptClient "github.com/sigmonsays/go-apt-client"
)

func downloadOVALContent(osvFileName string) (err error) {
	url := fmt.Sprintf("https://security-metadata.canonical.com/oval/%v", osvFileName)

	// Create the file
	out, err := os.Create(osvFileName)
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
func installRequiredPackages(logger hclog.Logger) error {
	// Install requirements
	// pkgs := make([]*aptClient.Package, 0)
	bunzipPkg, err := aptClient.Search("bzip2")
	if err != nil {
		log.Fatal("error finding package 'bzip2'")
		return err
	}
	//pkgs = append(pkgs, bunzipPkg...)
	_, installErr := aptClient.Install(bunzipPkg...)
	if installErr != nil {
		logger.Error("error installing package: 'libopenscap8'")
		return installErr
	}

	oscapPkg, err := aptClient.Search("libopenscap8")
	if err != nil {
		logger.Error("error finding package 'libopenscap8'")
		return err
	}
	// pkgs = append(pkgs, oscapPkg...)

	_, installOscapErr := aptClient.Install(oscapPkg...)
	if installOscapErr != nil {
		logger.Error("error installing packages: 'bzip2'")
		return installOscapErr
	}
	return nil
}

// Installs OSCAP on the target machine
func RunOSCAPScan(logger hclog.Logger) error {
	installRequiredPackages(logger)
	// Get the Linux Standard Base release (e.g. jammy) and download the OSV content
	lsbReleaseCommand := exec.Command("lsb_release", "-cs")
	lsbRelease, err := lsbReleaseCommand.Output()
	if err != nil {
		logger.Error("error getting lsb_release output")
		return err
	}
	osvFileName := fmt.Sprintf("com.ubuntu.%v.usn.oval.xml.bz2", lsbRelease)
	err = downloadOVALContent(osvFileName)
	if err != nil {
		logger.Error("could not download oval content")
		return err
	}

	// Unzip the OVAL content
	exec.Command("bunzip2", osvFileName)

	// Run the scan
	exec.Command("oscap", "oval", "eval", " --results", "results.xml", osvFileName)
	return nil
}

// GenerateReport: Runs an OSCAP scan on the target machine and returns the report
func GetScanReport(logger hclog.Logger) (*ScanResults, error) {
	// Return the XML
	file, err := os.Open("results.xml")
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
	marshalErr := xml.Unmarshal(xmlFile, scanResults)
	if marshalErr != nil {
		logger.Error("could not format scan results")
		return nil, marshalErr
	}
	return &scanResults, nil
}

// func ProcessReport() {
// 	...
// }
