package cve_request

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os/exec"
	"strings"

	"github.com/hashicorp/go-hclog"
)

type OpenSourceVulnerability struct {
	OSVID string `json:"id"`
	Info  struct {
		SeverityCategory string `json:"severity"`
	} `json:"database_specific"`
	CVEIDs   []string `json:"aliases"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
}

// NVDResponse represents the NVD API response structure
type OSVResponse struct {
	Vulnerabilities []OpenSourceVulnerability `json:"vulns"`
}

// TODO: create shared folder for this (defined in main)
type KnownVulnerability struct {
	CVEID       string `json:"cve_id"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
}

// GetManifestPackages: Gets packages that are installed with the OS
// their current versions will be checked for CVEs
func GetManifestPackages(logger hclog.Logger, osVersion string, arch string) map[string]struct{} {
	packageSet := make(map[string]struct{})
	url := fmt.Sprintf("https://releases.ubuntu.com/%v/ubuntu-%v-desktop-%v.manifest", osVersion, osVersion, arch)
	logger.Info(fmt.Sprintf("URL is %v", url))
	osManifest, err := http.Get(url)
	if err != nil || osManifest.StatusCode != 200 {
		logger.Error("Error getting Ubuntu manifest")
	}

	logger.Info(fmt.Sprintf("found manifest %v", osManifest))
	osManifestData, err := io.ReadAll(osManifest.Body)
	// var x string
	// json.Unmarshal(osManifestData, &x)
	// fmt.Println(fmt.Sprintf("Response is %v", string(osManifestData)))
	lines := strings.Split(string(osManifestData), "\n")
	for _, line := range lines {
		// Split line into fields
		fields := strings.Fields(line)
		// fmt.Printf("Fields: %v\n", fields)
		if len(fields) >= 2 {
			packageName := fields[0]
			var empty struct{}
			packageSet[packageName] = empty
			// fmt.Printf("Package name is %v\n", packageName)
			// packages[packageName] = packageVersion
			// fmt.Println("Getting package CVEs")
			// GetPackageCves(packageName, packageVersion)
		}
	}
	logger.Info(fmt.Sprintf("Found %v manifest packages", len(packageSet)))
	return packageSet
}

// GetInstalledPackages: gets currently installed packages
func GetInstalledPackages(logger hclog.Logger) map[string]string {
	// Step 1: Run `yum list installed` command and capture the output
	cmd := exec.Command("ssh", "-i", "~/ssh-test-key.pem", "ubuntu@ec2-3-8-194-197.eu-west-2.compute.amazonaws.com", "apt", "list")
	output, err := cmd.Output()
	if err != nil {
		log.Fatalf("Failed to run yum list installed: %v", err)
	}

	// Step 2: Initialize a map to store package names and versions
	packages := make(map[string]string)

	// Step 3: Process the output line by line
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		// Split line into fields
		fields := strings.Fields(line)
		if len(fields) < 2 {
			logger.Warn(fmt.Sprintf("no valid version for %v", line))
			continue
		}
		packageNames := strings.Split(fields[0], "/")
		var packageName string
		if len(packageNames) < 2 {
			packageName = fields[0]
		} else {
			packageName = packageNames[0]
		}
		packageVersion := fields[1]
		packages[packageName] = packageVersion
	}
	logger.Info(fmt.Sprintf("Found %v installed packages", len(packages)))
	return packages
}

func GetPackageCVEs(logger hclog.Logger, packageName string, packageVersion string) (*OSVResponse, error) {
	fmt.Println(fmt.Sprintf(`{"package": {"name": "%v"}, "version": "%v"}`, packageName, packageVersion))
	postData := []byte(fmt.Sprintf(`{"package": {"name": "%v"}, "version": "%v"}`, packageName, packageVersion))
	postBytes, err := json.Marshal(postData)
	if err != nil {
		fmt.Println("Error marshaling data")
		return nil, fmt.Errorf("error marshaling data for request")
	}
	fmt.Printf("Sending request with data %v\n", postBytes)
	resp, err := http.Post("https://api.osv.dev/v1/query", "application/json", bytes.NewBuffer(postData))
	if err != nil {
		fmt.Printf("error sending request: %v\n", err)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("error reading response: %v\n", err)
	}
	dataMap := OSVResponse{}
	json.Unmarshal(data, &dataMap)
	logger.Info(fmt.Sprintf("Response is %v", dataMap))
	return &dataMap, nil
}

// GetOSPackageCVEs: Gets CVEs for OS packages
func GetOSPackageCVEs(logger hclog.Logger, osVersion string, arch string) {
	manifestPackages := GetManifestPackages(logger, osVersion, arch)
	installedPackages := GetInstalledPackages(logger)
	// Find CVEs in the intersection of manifest & installed packages
	count := 0
	for pkg := range manifestPackages {
		version, ok := installedPackages[pkg]
		if !ok {
			continue
		}
		if count > 10 {
			break
		}
		count += 1
		logger.Info(fmt.Sprintf("Checking package %v with version %v", pkg, version))
		vuln, err := GetPackageCVEs(logger, pkg, version)
		if err != nil {
			logger.Error(fmt.Sprintf("Error getting CVE: %v", err))
			continue
		}
		logger.Info(fmt.Sprintf("Vuln is %v", vuln))
	}
}
