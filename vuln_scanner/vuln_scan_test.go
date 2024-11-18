package vuln_scanner

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"

	"github.com/hashicorp/go-hclog"
)

var testDataFolder string = "/tmp/test_data"

func setupLogger() hclog.Logger {
	return hclog.New(&hclog.LoggerOptions{
		Level:      hclog.Debug,
		JSONFormat: true,
	})
}

func setupTestDataFolder(t *testing.T) {
	err := os.MkdirAll(testDataFolder, os.ModePerm) // os.ModePerm gives 0777 permissions
	if err != nil {
		t.Fatalf("error setting up test data folder: %v", err)
	}
}

func cleanupTests() {
	os.RemoveAll(testDataFolder)
}

func enforceUbuntu(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("test requires linux, skipping test")
	}
	lsb, err := exec.Command("lsb_release", "-ds").Output()
	if err != nil {
		t.Skip("test requires ubuntu and lsb-release, skipping test")
	}
	if !strings.Contains(string(lsb), "Ubuntu") {
		t.Skip("test requires ubuntu, skipping")
	}
}

// Ubuntu-specific tests (run via Docker)

// TestDownloadOVALContent: Tests OVAL content is correctly downloaded
func TestDownloadOVALContent(t *testing.T) {
	enforceUbuntu(t)
	setupTestDataFolder(t)
	ovalContent := "com.ubuntu.jammy.usn.oval.xml.bz2"
	downloadLocation := fmt.Sprintf("%v/%v", testDataFolder, ovalContent)
	url := fmt.Sprintf("https://security-metadata.canonical.com/oval/%v", ovalContent)
	err := downloadOVALContent(url, downloadLocation)
	if err != nil {
		t.Fatalf("error downloading oval content: %v", err)
	}
	_, err = os.Stat(downloadLocation)
	if err != nil {
		t.Fatalf("no oval content downloaded")
	}
	t.Cleanup(cleanupTests)
}

func TestInstallPackages(t *testing.T) {
	enforceUbuntu(t)
	err := InstallRequiredPackages(setupLogger())
	if err != nil {
		t.Fatalf("error installing required packages: %v", err)
	}
	_, err = exec.Command("bunzip2", "--version").Output()
	if err != nil {
		t.Fatalf("error installing bunzip2: %v", err)
	}
	_, err = exec.Command("oscap", "--version").Output()
	if err != nil {
		t.Fatalf("error installing oscap: %v", err)
	}
}

func TestRunOSCAPScan(t *testing.T) {
	enforceUbuntu(t)
	setupTestDataFolder(t)
	logger := setupLogger()
	InstallRequiredPackages(logger)
	ovalContentName, err := GetOVALContent(logger, testDataFolder)
	if err != nil {
		t.Fatalf("error getting oval content: %v", err)
	}
	var resultsLoc *string
	resultsLoc, err = RunOSCAPScan(logger, testDataFolder, *ovalContentName)
	if err != nil {
		t.Fatalf("error testing oscap scan: %v", err)
	}
	_, err = os.Stat(*resultsLoc)
	if err != nil {
		t.Fatalf("no oval content downloaded")
	}
	t.Cleanup(cleanupTests)
}

func TestFormatResults(t *testing.T) {
	logger := setupLogger()
	results, err := GetScanReport(logger, "../test_data/example_results.xml")
	if err != nil {
		t.Fatalf("error getting scan report: %v", err)
	}
	vulns := ProcessReport(logger, results)
	logger.Info(fmt.Sprintf("Vulnerabilties: %v", vulns[0].CVEID))
	if len(vulns) != 243 {
		t.Fatalf("did not find expected number of vulnerabilities (243)")
	}
	highSeverityVulns := 0
	for _, v := range vulns {
		if v.Severity == "High" {
			highSeverityVulns += 1
			logger.Debug(fmt.Sprintf("Vuln of severity high, ID %v and desc: %v", v.CVEID, v.Description))
		}
	}
	if highSeverityVulns != 2 {
		t.Fatalf("did not find expected number of high-severity vulnerabilities (2)")
	}
}
