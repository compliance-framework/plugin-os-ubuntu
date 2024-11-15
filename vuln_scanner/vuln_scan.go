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

func downloadOVALContent(lsb_release string, osvFileName string) (err error) {
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
func installRequiredPackages() {
	exec.Command("ssh", "-i", "~/ssh-test-key.pem", "ubuntu@ec2-3-8-194-197.eu-west-2.compute.amazonaws.com")
	// Install requirements
	pkgs := make([]*aptClient.Package, 0)
	bunzipPkg, err := aptClient.Search("bunzip2")
	if err != nil {
		log.Fatal("error finding package 'bunzip2'")
		return
	}
	pkgs = append(pkgs, bunzipPkg...)

	oscapPkg, err := aptClient.Search("libopenscap8")
	if err != nil {
		log.Fatal("error finding package 'libopenscap8'")
		return
	}
	pkgs = append(pkgs, oscapPkg...)

	_, installErr := aptClient.Install(pkgs...)
	if installErr != nil {
		log.Fatalf("error installing packages: 'bunzip2', 'libopenscap8'")
		return
	}

}

// Installs OSCAP on the target machine
func RunOSCAPScan(logger hclog.Logger) error {
	installRequiredPackages()
	// Get the Linux Standard Base release (e.g. jammy) and download the OSV content
	lsbReleaseCommand := exec.Command("lsb_release", "-cs")
	lsbRelease, err := lsbReleaseCommand.Output()
	if err != nil {
		logger.Error("error getting lsb_release output")
		return err
	}
	osvFileName := fmt.Sprintf("com.ubuntu.%v.usn.oval.xml.bz2", lsbRelease)
	err = downloadOVALContent(string(lsbRelease), osvFileName)
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
