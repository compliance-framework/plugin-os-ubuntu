package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	policyManager "github.com/chris-cmsoft/concom/policy-manager"
	"github.com/chris-cmsoft/concom/runner"
	"github.com/chris-cmsoft/concom/runner/proto"
	"github.com/google/uuid"
	"github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
)

type CompliancePlugin struct {
	logger hclog.Logger
	data   []Violation
	config map[string]string
}

// Vulnerability represents the structure of each vulnerability item in the response
type Vulnerability struct {
	CVE struct {
		ID           string `json:"id"`
		Descriptions []struct {
			Lang  string `json:"lang"`
			Value string `json:"value"`
		} `json:"descriptions"`
		Metrics struct {
			CvssMetricV2 []struct {
				BaseSeverity string `json:"baseSeverity"`
			} `json:"cvssMetricV2"`
		} `json:"metrics"`
	} `json:"cve"`
}

// NVDResponse represents the NVD API response structure
type NVDResponse struct {
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

// Violation represents the structure used in the OPA policy
type Violation struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Remarks     string `json:"remarks"`
	CVEID       string `json:"cve_id"`
}

// FetchVulnerabilitiesForUbuntu queries the NVD API for vulnerabilities for a given Ubuntu version
func FetchVulnerabilitiesForUbuntu(version string) ([]Violation, error) {
	// Define the NVD API URL with query parameters
	url := "https://services.nvd.nist.gov/rest/json/cves/2.0"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %v", err)
	}

	// Set query parameters
	q := req.URL.Query()
	q.Add("cpeName", fmt.Sprintf("cpe:2.3:o:canonical:ubuntu_linux:%s", version))
	q.Add("cvssV3Severity", "CRITICAL")
	q.Add("resultsPerPage", "10")
	req.URL.RawQuery = q.Encode()

	// Perform the HTTP request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error making request to NVD API: %v", err)
	}
	defer resp.Body.Close()

	// Check for non-200 HTTP status
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected response status: %v", resp.StatusCode)
	}

	// Read and parse the JSON response using io.ReadAll
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %v", err)
	}

	var nvdResponse NVDResponse
	err = json.Unmarshal(body, &nvdResponse)
	if err != nil {
		return nil, fmt.Errorf("error parsing JSON: %v", err)
	}

	// Transform to Violation format for OPA
	var violations []Violation
	for _, vuln := range nvdResponse.Vulnerabilities {
		if len(vuln.CVE.Descriptions) > 0 && len(vuln.CVE.Metrics.CvssMetricV2) > 0 {
			violation := Violation{
				Title:       fmt.Sprintf("Vulnerability %s detected", vuln.CVE.ID),
				Description: vuln.CVE.Descriptions[0].Value,
				Severity:    vuln.CVE.Metrics.CvssMetricV2[0].BaseSeverity,
				Remarks:     "Review and apply patches to address this vulnerability.",
				CVEID:       vuln.CVE.ID,
			}
			violations = append(violations, violation)
		}
	}
	return violations, nil
}

// Configure, PrepareForEval, and Eval are called at different times during the plugin execution lifecycle,
// and are responsible for different tasks:
//
// Configure is called on plugin startup. It is primarily used to configure a plugin for its lifetime.
// Here you should store any configurations like usernames and password required by the plugin.
//
// PrepareForEval is called on a scheduled execution of the plugin. Whenever the plugin is going to be run,
// PrepareForEval is called, so it can collect any data necessary for making assertions.
// Here you should run any commands, call any endpoints, or process any reports, which you want to turn into
// compliance findings and observations.
//
// Eval is called multiple times for each scheduled execution. It is responsible for running policies against the
// collected data from PrepareForEval. When a user passed multiple matching policy bundles to the agent, each of them
// will be passed to Eval in sequence. Eval will run against the collected data N times, where N is the amount
// of matching policies passed into the agent.
//
// As a complete example:
//
// The Local SSH plugin checks the local SSH configuration on a host machine.
//
// A user starts the agent, and passes the Local SSH plugin and 2 policy bundles to it.
//
// The agent will:
// * Start the plugin
// * Call Configure() with teh required config
// * Call PrepareForEval() so the plugin can collect the local SSH configuration from the machine
// * Call Eval() with the first policy bundle, so the plugin can report any violations against the configuration
// * Call Eval() with the second policy bundle, so the plugin can report any violations against the configuration

func (l *CompliancePlugin) Configure(req *proto.ConfigureRequest) (*proto.ConfigureResponse, error) {

	// Configure is used to set up any configuration needed by this plugin over its lifetime.
	// This will likely only be called once on plugin startup, which may then run for an extended period of time.

	// In this method, you should save any configuration values to your plugin struct, so you can later
	// re-use them in PrepareForEval and Eval.

	l.config = req.Config
	return &proto.ConfigureResponse{}, nil
}

func (l *CompliancePlugin) PrepareForEval(req *proto.PrepareForEvalRequest) (*proto.PrepareForEvalResponse, error) {

	// TODO: Loop over last each major releases of LTS versions of Ubuntu - 16.lts 18.lts 20.lts etc
	knownVulnerabilities, err := FetchVulnerabilitiesForUbuntu("18.04")
	if err != nil {
		log.Fatalf("Failed to fetch vulnerabilities: %v", err)
	}

	// PrepareForEval is called once on every scheduled plugin execution.
	// Here you should collect the data that should be evaluated with policies or checks.
	// You should not make any observations or findings here. Only collect the data you need for policy / compliance checks.

	// This method does most of the heavy lifting for your plugin.
	// Here are a few examples of when it will be used:
	// Local SSH Plugin: Fetch the SSH configuration from the local machine
	// SAST Report Plugin: Convert a SAST sarif report into a usable structure for policies to be written against
	// Azure VM Label Plugin: Collect all the VMs from the Azure API so they can be evaluated against policies
	l.data = knownVulnerabilities
	return &proto.PrepareForEvalResponse{}, nil
}

func (l *CompliancePlugin) Eval(request *proto.EvalRequest) (*proto.EvalResponse, error) {
	ctx := context.TODO()
	start_time := time.Now().Format(time.RFC3339)

	response := runner.NewCallableEvalResponse()
	hasViolations := false

	for _, violation := range l.data {
		violationMap := map[string]interface{}{
			"cve_id":      violation.CVEID,
			"title":       violation.Title,
			"description": violation.Description,
			"severity":    violation.Severity,
			"remarks":     violation.Remarks,
		}

		dataMap := map[string]interface{}{
			"violation": []interface{}{violationMap},
		}

		newResults, err := policyManager.
			New(ctx, l.logger, request.BundlePath).
			Execute(ctx, "security", dataMap)

		if err != nil {
			return &proto.EvalResponse{}, err
		}

		for _, result := range newResults {
			if len(result.Violations) > 0 {
				hasViolations = true

				observation := &proto.Observation{
					Id:          uuid.New().String(),
					Title:       fmt.Sprintf("The plugin found violations for policy %s on machineId: %s", result.Policy.Package.PurePackage(), "ARN:12345"),
					Description: fmt.Sprintf("Observed %d violation(s) for policy %s within the Plugin on machineId: %s.", len(result.Violations), result.Policy.Package.PurePackage(), "ARN:12345"),
					Collected:   time.Now().Format(time.RFC3339),
					Expires:     time.Now().AddDate(0, 1, 0).Format(time.RFC3339),
					RelevantEvidence: []*proto.Evidence{
						{
							Description: fmt.Sprintf("Policy %v was evaluated, and %d violations were found on machineId: %s", result.Policy.Package.PurePackage(), len(result.Violations), "ARN:12345"),
						},
					},
				}
				response.AddObservation(observation)

				for _, violation := range result.Violations {
					response.AddFinding(&proto.Finding{
						Id:                  uuid.New().String(),
						Title:               violation.GetString("title", fmt.Sprintf("Validation on %s failed with violation %v", result.Policy.Package.PurePackage(), violation)),
						Description:         violation.GetString("description", ""),
						Remarks:             violation.GetString("remarks", ""),
						RelatedObservations: []string{observation.Id},
					})
				}
			}
		}
	}

	// Add a "success" observation only if no violations were found
	if !hasViolations {
		response.AddObservation(&proto.Observation{
			Id:          uuid.New().String(),
			Title:       "The plugin succeeded. No compliance issues to report.",
			Description: "The plugin policies did not return any violations. The configuration is in compliance with policies.",
			Collected:   time.Now().Format(time.RFC3339),
			Expires:     time.Now().AddDate(0, 1, 0).Format(time.RFC3339),
			RelevantEvidence: []*proto.Evidence{
				{
					Description: fmt.Sprintf("All policies were evaluated, and no violations were found on machineId: %s", "ARN:12345"),
				},
			},
		})
	}

	response.AddLogEntry(&proto.LogEntry{
		Title: "Plugin checks completed",
		Start: start_time,
		End:   time.Now().Format(time.RFC3339),
	})

	return response.Result(), nil
}

func main() {
	logger := hclog.New(&hclog.LoggerOptions{
		Level:      hclog.Debug,
		JSONFormat: true,
	})

	ubuntuOS := &CompliancePlugin{
		logger: logger,
	}

	logger.Debug("initiating plugin")

	goplugin.Serve(&goplugin.ServeConfig{
		HandshakeConfig: runner.HandshakeConfig,
		Plugins: map[string]goplugin.Plugin{
			"runner": &runner.RunnerGRPCPlugin{
				Impl: ubuntuOS,
			},
		},
		GRPCServer: goplugin.DefaultGRPCServer,
	})
}
