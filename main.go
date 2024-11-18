package main

import (
	"context"
	"fmt"
	"time"

	policyManager "github.com/chris-cmsoft/concom/policy-manager"
	"github.com/chris-cmsoft/concom/runner"
	"github.com/chris-cmsoft/concom/runner/proto"
	vulnScanner "github.com/compliance-framework/plugin-template/vuln_scanner"
	"github.com/google/uuid"
	"github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
)

type CompliancePlugin struct {
	logger hclog.Logger
	data   *vulnScanner.ScanResults
	config PluginConfig
}

type PluginConfig struct {
	OSCAPContentPath string
	OVALContentName  string
}

func (l *CompliancePlugin) Configure(req *proto.ConfigureRequest) (*proto.ConfigureResponse, error) {
	if req.Config["OSCAPContentPath"] == "" {
		return nil, fmt.Errorf("no OSCAP content location supplied")
	}
	oscapContentPath := req.Config["OSCAPContentPath"]
	vulnScanner.InstallRequiredPackages(l.logger)
	contentName, err := vulnScanner.GetOVALContent(l.logger, oscapContentPath)
	if err != nil {
		return nil, fmt.Errorf("not able to get OVAL content: %v", err)
	}
	l.config = PluginConfig{OSCAPContentPath: oscapContentPath, OVALContentName: *contentName}
	return &proto.ConfigureResponse{}, nil
}

func (l *CompliancePlugin) PrepareForEval(req *proto.PrepareForEvalRequest) (*proto.PrepareForEvalResponse, error) {
	scanResultsLocation, err := vulnScanner.RunOSCAPScan(l.logger, l.config.OSCAPContentPath, l.config.OVALContentName)
	if err != nil {
		l.logger.Error(fmt.Sprintf("failed to run scan: %v", err))
	}
	scanResults, err := vulnScanner.GetScanReport(l.logger, *scanResultsLocation)
	if err != nil {
		l.logger.Error(fmt.Sprintf("failed to get scan results: %v", err))
	}
	l.data = scanResults
	return &proto.PrepareForEvalResponse{}, nil
}

func (l *CompliancePlugin) Eval(request *proto.EvalRequest) (*proto.EvalResponse, error) {
	ctx := context.TODO()
	start_time := time.Now().Format(time.RFC3339)

	response := runner.NewCallableEvalResponse()
	hasViolations := false
	scanViolations := vulnScanner.ProcessReport(l.logger, l.data)

	for _, violation := range scanViolations {
		violationMap := map[string]interface{}{
			"cve_id":      violation.CVEID,
			"title":       violation.Title,
			"description": violation.Description,
			"severity":    violation.Severity,
			"remarks":     "Review and apply patches to address this vulnerability.",
		}

		dataMap := map[string]interface{}{
			"violation": []interface{}{violationMap},
		}

		policyResults, err := policyManager.
			New(ctx, l.logger, request.BundlePath).
			Execute(ctx, "security", dataMap)

		if err != nil {
			return &proto.EvalResponse{}, err
		}

		for _, result := range policyResults {
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
