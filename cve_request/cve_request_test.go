package cve_request

import (
	"github.com/hashicorp/go-hclog"
)

func SetupLogger() hclog.Logger {
	return hclog.New(&hclog.LoggerOptions{
		Level:      hclog.Debug,
		JSONFormat: true,
	})
}

// func TestGetCveRequest(t *testing.T) {
// 	GetPackageCves("openssl", "1.1.1")
// }

// func TestGetUbuntuManifest(t *testing.T) {
// 	packages := GetManifestPackages(SetupLogger(), "24.10", "amd64")
// 	fmt.Printf("Found manifest packages %v\n", packages)
// }

// func TestGetInstalledPackages(t *testing.T) {
// 	packages := GetInstalledPackages(SetupLogger())
// 	fmt.Printf("Found installed packages %v\n", packages)
// }

// func TestGetOSPackageCVEs(t *testing.T) {
// 	GetOSPackageCVEs(SetupLogger(), "24.10", "amd64")
// }

// func readTestData(t *testing.T, filename string) OSVResponse {
// 	file, err := os.Open(filename)
// 	if err != nil {
// 		t.Fatal()
// 	}
// 	defer file.Close()

// 	var expected OSVResponse
// 	// var data []byte = make([]byte, 0)
// 	// file.Read(data)
// 	data, err := io.ReadAll(file)
// 	if err != nil {
// 		t.Fatal("could not read test data")
// 	}
// 	json.Unmarshal(data, &expected)
// 	return expected
// }

// func TestPackageCVE(t *testing.T) {
// 	expected := readTestData(t, "../test_data/openssl_vuln_response.expected.json")
// 	vuln, err := GetPackageCVEs(SetupLogger(), "openssl", "1.1.1")
// 	if err != nil {
// 		t.Fatal()
// 	}
// 	if !reflect.DeepEqual(*vuln, expected) {
// 		t.Fatalf("expected vulnerability %v was not equal to %v", expected, vuln)
// 	}
// }

// func TestInvalidCVE(t *testing.T) {
// 	expected := readTestData(t, "../test_data/openssl_vuln_response.expected.json")
// 	vuln, err := GetPackageCVEs(SetupLogger(), "openssl", "1.1.1")
// 	if err != nil {
// 		t.Fatal()
// 	}
// 	if !reflect.DeepEqual(*vuln, expected) {
// 		t.Fatalf("expected vulnerability %v was not equal to %v", expected, vuln)
// 	}
// }
