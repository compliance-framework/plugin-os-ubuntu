package vuln_scanner

import (
	"testing"

	"github.com/hashicorp/go-hclog"
)

func SetupLogger() hclog.Logger {
	return hclog.New(&hclog.LoggerOptions{
		Level:      hclog.Debug,
		JSONFormat: true,
	})
}

func TestDownloadOVALContent(t *testing.T) {
	// logger := SetupLogger()
	err := downloadOVALContent("com.ubuntu.jammy.usn.oval.xml.bz2")
	if err != nil {
		t.Fatalf("error downloading oval content: %v", err)
	}
}
