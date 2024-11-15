package vuln_scanner

import "testing"

func TestDownloadOVALContent(t *testing.T) {
	downloadOVALContent("jammy", "test")
}
