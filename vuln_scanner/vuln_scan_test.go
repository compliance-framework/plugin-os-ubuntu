package vuln_scanner

import (
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/go-hclog"
)

func SetupLogger() hclog.Logger {
	return hclog.New(&hclog.LoggerOptions{
		Level:      hclog.Debug,
		JSONFormat: true,
	})
}

func SetupTests(testDataFolder string) error {
	return os.MkdirAll("/tmp/test_data", os.ModePerm) // os.ModePerm gives 0777 permissions
}

func CleanupTests() {
	os.RemoveAll("/tmp/test_data")
}

// func TestDownloadOVALContent(t *testing.T) {
// 	// logger := SetupLogger()
// 	err := downloadOVALContent("com.ubuntu.jammy.usn.oval.xml.bz2")
// 	if err != nil {
// 		t.Fatalf("error downloading oval content: %v", err)
// 	}
// }

// func TestInstallPackages(t *testing.T) {
// 	err := installRequiredPackages(SetupLogger())
// 	if err != nil {
// 		t.Fatalf("error install required packages: %v", err)
// 	}
// }

// func TestRunOSCAPScan(t *testing.T) {
// 	testDataFolder := "/tmp/test_data"
// 	err := SetupTests(testDataFolder)
// 	if err != nil {
// 		t.Fatalf("error setting up test folder: %v", err)
// 	}
// 	err = RunOSCAPScan(SetupLogger(), testDataFolder)
// 	if err != nil {
// 		t.Fatalf("error testing oscap scan: %v", err)
// 	}
// 	t.Cleanup(CleanupTests)
// }

func TestFormatResults(t *testing.T) {
	logger := SetupLogger()
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
		// logger.Info(v.Severity)
		if v.Severity == "High" {
			highSeverityVulns += 1
			logger.Debug(fmt.Sprintf("Vuln of severity high, ID %v and desc: %v", v.CVEID, v.Description))
		}
	}
	if highSeverityVulns != 2 {
		t.Fatalf("did not find expected number of high-severity vulnerabilities (2)")
	}
}
