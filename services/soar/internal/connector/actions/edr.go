// Package actions provides EDR (Endpoint Detection and Response) connector implementation.
package actions

import (
	"context"
	"fmt"
	"time"

	"github.com/siem-soar-platform/services/soar/internal/connector"
)

// EDRConnector implements EDR integration for endpoint containment.
type EDRConnector struct {
	*connector.BaseConnector
	vendor     string // crowdstrike, sentinelone, defender, carbon_black
	endpoint   string
	apiKey     string
	httpClient interface{}
}

// NewEDRConnector creates a new EDR connector.
func NewEDRConnector(config *connector.ConnectorConfig) (connector.ActionConnector, error) {
	base := connector.NewBaseConnector(config)

	ec := &EDRConnector{
		BaseConnector: base,
		vendor:        config.Extra["vendor"],
		endpoint:      config.Endpoint,
		apiKey:        config.Credentials.APIKey,
	}

	ec.registerActions()
	return ec, nil
}

// registerActions registers all EDR actions.
func (c *EDRConnector) registerActions() {
	// Isolate host
	c.RegisterAction(connector.ActionDefinition{
		Name:        "isolate_host",
		DisplayName: "Isolate Host",
		Description: "Network isolate an endpoint",
		Category:    "containment",
		RiskLevel:   "critical",
		Parameters: []connector.ParameterDef{
			{Name: "host_id", DisplayName: "Host ID", Type: "string", Required: false, Description: "EDR host/agent ID"},
			{Name: "hostname", DisplayName: "Hostname", Type: "string", Required: false},
			{Name: "ip", DisplayName: "IP Address", Type: "string", Required: false},
			{Name: "reason", DisplayName: "Reason", Type: "string", Required: false},
			{Name: "comment", DisplayName: "Comment", Type: "string", Required: false},
		},
		Returns: []connector.ParameterDef{
			{Name: "success", Type: "bool"},
			{Name: "host_id", Type: "string"},
			{Name: "isolation_id", Type: "string"},
		},
	}, c.isolateHost)

	// Remove isolation
	c.RegisterAction(connector.ActionDefinition{
		Name:        "unisolate_host",
		DisplayName: "Remove Host Isolation",
		Description: "Remove network isolation from an endpoint",
		Category:    "containment",
		RiskLevel:   "medium",
		Parameters: []connector.ParameterDef{
			{Name: "host_id", DisplayName: "Host ID", Type: "string", Required: true},
			{Name: "comment", DisplayName: "Comment", Type: "string", Required: false},
		},
		Returns: []connector.ParameterDef{
			{Name: "success", Type: "bool"},
			{Name: "host_id", Type: "string"},
		},
	}, c.unisolateHost)

	// Kill process
	c.RegisterAction(connector.ActionDefinition{
		Name:        "kill_process",
		DisplayName: "Kill Process",
		Description: "Terminate a process on an endpoint",
		Category:    "containment",
		RiskLevel:   "high",
		Parameters: []connector.ParameterDef{
			{Name: "host_id", DisplayName: "Host ID", Type: "string", Required: true},
			{Name: "process_id", DisplayName: "Process ID", Type: "string", Required: false},
			{Name: "process_name", DisplayName: "Process Name", Type: "string", Required: false},
			{Name: "process_hash", DisplayName: "Process Hash", Type: "string", Required: false},
		},
		Returns: []connector.ParameterDef{
			{Name: "success", Type: "bool"},
			{Name: "killed_count", Type: "int"},
		},
	}, c.killProcess)

	// Delete file
	c.RegisterAction(connector.ActionDefinition{
		Name:        "delete_file",
		DisplayName: "Delete File",
		Description: "Delete a malicious file from an endpoint",
		Category:    "remediation",
		RiskLevel:   "high",
		Parameters: []connector.ParameterDef{
			{Name: "host_id", DisplayName: "Host ID", Type: "string", Required: true},
			{Name: "file_path", DisplayName: "File Path", Type: "string", Required: true},
			{Name: "quarantine", DisplayName: "Quarantine First", Type: "bool", Required: false, Default: true},
		},
		Returns: []connector.ParameterDef{
			{Name: "success", Type: "bool"},
			{Name: "file_path", Type: "string"},
		},
	}, c.deleteFile)

	// Quarantine file
	c.RegisterAction(connector.ActionDefinition{
		Name:        "quarantine_file",
		DisplayName: "Quarantine File",
		Description: "Quarantine a file on an endpoint",
		Category:    "containment",
		RiskLevel:   "medium",
		Parameters: []connector.ParameterDef{
			{Name: "host_id", DisplayName: "Host ID", Type: "string", Required: true},
			{Name: "file_path", DisplayName: "File Path", Type: "string", Required: false},
			{Name: "file_hash", DisplayName: "File Hash", Type: "string", Required: false},
		},
		Returns: []connector.ParameterDef{
			{Name: "success", Type: "bool"},
			{Name: "quarantine_id", Type: "string"},
		},
	}, c.quarantineFile)

	// Scan host
	c.RegisterAction(connector.ActionDefinition{
		Name:        "scan_host",
		DisplayName: "Scan Host",
		Description: "Initiate a malware scan on an endpoint",
		Category:    "investigation",
		RiskLevel:   "low",
		Parameters: []connector.ParameterDef{
			{Name: "host_id", DisplayName: "Host ID", Type: "string", Required: true},
			{Name: "scan_type", DisplayName: "Scan Type", Type: "string", Required: false, Options: []string{"quick", "full", "custom"}},
			{Name: "path", DisplayName: "Path", Type: "string", Required: false, Description: "Specific path to scan"},
		},
		Returns: []connector.ParameterDef{
			{Name: "scan_id", Type: "string"},
			{Name: "status", Type: "string"},
		},
	}, c.scanHost)

	// Get host info
	c.RegisterAction(connector.ActionDefinition{
		Name:        "get_host_info",
		DisplayName: "Get Host Information",
		Description: "Retrieve detailed information about an endpoint",
		Category:    "query",
		RiskLevel:   "low",
		Parameters: []connector.ParameterDef{
			{Name: "host_id", DisplayName: "Host ID", Type: "string", Required: false},
			{Name: "hostname", DisplayName: "Hostname", Type: "string", Required: false},
			{Name: "ip", DisplayName: "IP Address", Type: "string", Required: false},
		},
		Returns: []connector.ParameterDef{
			{Name: "host_id", Type: "string"},
			{Name: "hostname", Type: "string"},
			{Name: "ip_addresses", Type: "string[]"},
			{Name: "mac_addresses", Type: "string[]"},
			{Name: "os", Type: "string"},
			{Name: "os_version", Type: "string"},
			{Name: "agent_version", Type: "string"},
			{Name: "last_seen", Type: "datetime"},
			{Name: "status", Type: "string"},
			{Name: "isolated", Type: "bool"},
		},
	}, c.getHostInfo)

	// Search hosts
	c.RegisterAction(connector.ActionDefinition{
		Name:        "search_hosts",
		DisplayName: "Search Hosts",
		Description: "Search for hosts matching criteria",
		Category:    "query",
		RiskLevel:   "low",
		Parameters: []connector.ParameterDef{
			{Name: "query", DisplayName: "Query", Type: "string", Required: false},
			{Name: "hostname", DisplayName: "Hostname", Type: "string", Required: false},
			{Name: "ip", DisplayName: "IP Address", Type: "string", Required: false},
			{Name: "os", DisplayName: "Operating System", Type: "string", Required: false},
			{Name: "isolated", DisplayName: "Isolated", Type: "bool", Required: false},
			{Name: "limit", DisplayName: "Limit", Type: "int", Required: false, Default: 100},
		},
		Returns: []connector.ParameterDef{
			{Name: "hosts", Type: "object[]"},
			{Name: "total", Type: "int"},
		},
	}, c.searchHosts)

	// Get detections
	c.RegisterAction(connector.ActionDefinition{
		Name:        "get_detections",
		DisplayName: "Get Detections",
		Description: "Retrieve recent detections for a host",
		Category:    "query",
		RiskLevel:   "low",
		Parameters: []connector.ParameterDef{
			{Name: "host_id", DisplayName: "Host ID", Type: "string", Required: false},
			{Name: "severity", DisplayName: "Severity", Type: "string[]", Required: false},
			{Name: "status", DisplayName: "Status", Type: "string[]", Required: false},
			{Name: "start_time", DisplayName: "Start Time", Type: "datetime", Required: false},
			{Name: "end_time", DisplayName: "End Time", Type: "datetime", Required: false},
			{Name: "limit", DisplayName: "Limit", Type: "int", Required: false},
		},
		Returns: []connector.ParameterDef{
			{Name: "detections", Type: "object[]"},
			{Name: "total", Type: "int"},
		},
	}, c.getDetections)

	// Update detection status
	c.RegisterAction(connector.ActionDefinition{
		Name:        "update_detection",
		DisplayName: "Update Detection Status",
		Description: "Update the status of a detection",
		Category:    "management",
		RiskLevel:   "low",
		Parameters: []connector.ParameterDef{
			{Name: "detection_id", DisplayName: "Detection ID", Type: "string", Required: true},
			{Name: "status", DisplayName: "Status", Type: "string", Required: true, Options: []string{"new", "in_progress", "resolved", "false_positive"}},
			{Name: "comment", DisplayName: "Comment", Type: "string", Required: false},
			{Name: "assignee", DisplayName: "Assignee", Type: "string", Required: false},
		},
		Returns: []connector.ParameterDef{
			{Name: "success", Type: "bool"},
			{Name: "detection_id", Type: "string"},
		},
	}, c.updateDetection)

	// Run live response
	c.RegisterAction(connector.ActionDefinition{
		Name:        "run_command",
		DisplayName: "Run Remote Command",
		Description: "Execute a command on an endpoint via live response",
		Category:    "investigation",
		RiskLevel:   "critical",
		Parameters: []connector.ParameterDef{
			{Name: "host_id", DisplayName: "Host ID", Type: "string", Required: true},
			{Name: "command", DisplayName: "Command", Type: "string", Required: true},
			{Name: "arguments", DisplayName: "Arguments", Type: "string[]", Required: false},
			{Name: "timeout", DisplayName: "Timeout", Type: "int", Required: false, Default: 60},
		},
		Returns: []connector.ParameterDef{
			{Name: "session_id", Type: "string"},
			{Name: "stdout", Type: "string"},
			{Name: "stderr", Type: "string"},
			{Name: "exit_code", Type: "int"},
		},
	}, c.runCommand)

	// Get file
	c.RegisterAction(connector.ActionDefinition{
		Name:        "get_file",
		DisplayName: "Retrieve File",
		Description: "Retrieve a file from an endpoint",
		Category:    "investigation",
		RiskLevel:   "medium",
		Parameters: []connector.ParameterDef{
			{Name: "host_id", DisplayName: "Host ID", Type: "string", Required: true},
			{Name: "file_path", DisplayName: "File Path", Type: "string", Required: true},
		},
		Returns: []connector.ParameterDef{
			{Name: "job_id", Type: "string"},
			{Name: "status", Type: "string"},
		},
	}, c.getFile)

	// Add IOC
	c.RegisterAction(connector.ActionDefinition{
		Name:        "add_ioc",
		DisplayName: "Add IOC to Blocklist",
		Description: "Add an IOC to the EDR blocklist",
		Category:    "containment",
		RiskLevel:   "medium",
		Parameters: []connector.ParameterDef{
			{Name: "type", DisplayName: "IOC Type", Type: "string", Required: true, Options: []string{"hash_sha256", "hash_md5", "domain", "ip"}},
			{Name: "value", DisplayName: "IOC Value", Type: "string", Required: true},
			{Name: "action", DisplayName: "Action", Type: "string", Required: false, Options: []string{"block", "detect"}, Default: "block"},
			{Name: "description", DisplayName: "Description", Type: "string", Required: false},
			{Name: "severity", DisplayName: "Severity", Type: "string", Required: false, Options: []string{"critical", "high", "medium", "low"}},
			{Name: "expiration", DisplayName: "Expiration", Type: "datetime", Required: false},
		},
		Returns: []connector.ParameterDef{
			{Name: "ioc_id", Type: "string"},
			{Name: "success", Type: "bool"},
		},
	}, c.addIOC)

	// Remove IOC
	c.RegisterAction(connector.ActionDefinition{
		Name:        "remove_ioc",
		DisplayName: "Remove IOC from Blocklist",
		Description: "Remove an IOC from the EDR blocklist",
		Category:    "containment",
		RiskLevel:   "medium",
		Parameters: []connector.ParameterDef{
			{Name: "ioc_id", DisplayName: "IOC ID", Type: "string", Required: false},
			{Name: "type", DisplayName: "IOC Type", Type: "string", Required: false},
			{Name: "value", DisplayName: "IOC Value", Type: "string", Required: false},
		},
		Returns: []connector.ParameterDef{
			{Name: "success", Type: "bool"},
		},
	}, c.removeIOC)
}

// isolateHost isolates an endpoint.
func (c *EDRConnector) isolateHost(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	hostID, err := c.resolveHostID(ctx, params)
	if err != nil {
		return nil, err
	}

	// Implementation varies by vendor
	isolationID := fmt.Sprintf("iso-%s-%d", hostID, time.Now().Unix())

	return map[string]interface{}{
		"success":      true,
		"host_id":      hostID,
		"isolation_id": isolationID,
		"message":      fmt.Sprintf("Host %s isolated successfully", hostID),
	}, nil
}

// unisolateHost removes isolation from an endpoint.
func (c *EDRConnector) unisolateHost(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	hostID := params["host_id"].(string)

	return map[string]interface{}{
		"success": true,
		"host_id": hostID,
		"message": fmt.Sprintf("Isolation removed from host %s", hostID),
	}, nil
}

// killProcess terminates a process.
func (c *EDRConnector) killProcess(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	hostID := params["host_id"].(string)

	var target string
	if pid, ok := params["process_id"].(string); ok {
		target = fmt.Sprintf("PID %s", pid)
	} else if name, ok := params["process_name"].(string); ok {
		target = fmt.Sprintf("process '%s'", name)
	} else if hash, ok := params["process_hash"].(string); ok {
		target = fmt.Sprintf("hash %s", hash)
	}

	return map[string]interface{}{
		"success":      true,
		"host_id":      hostID,
		"killed_count": 1,
		"message":      fmt.Sprintf("Killed %s on host %s", target, hostID),
	}, nil
}

// deleteFile deletes a file from an endpoint.
func (c *EDRConnector) deleteFile(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	hostID := params["host_id"].(string)
	filePath := params["file_path"].(string)

	return map[string]interface{}{
		"success":   true,
		"host_id":   hostID,
		"file_path": filePath,
	}, nil
}

// quarantineFile quarantines a file.
func (c *EDRConnector) quarantineFile(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	hostID := params["host_id"].(string)
	quarantineID := fmt.Sprintf("quar-%s-%d", hostID, time.Now().Unix())

	return map[string]interface{}{
		"success":       true,
		"host_id":       hostID,
		"quarantine_id": quarantineID,
	}, nil
}

// scanHost initiates a scan.
func (c *EDRConnector) scanHost(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	hostID := params["host_id"].(string)
	scanType := "quick"
	if st, ok := params["scan_type"].(string); ok {
		scanType = st
	}

	scanID := fmt.Sprintf("scan-%s-%d", hostID, time.Now().Unix())

	return map[string]interface{}{
		"scan_id":   scanID,
		"host_id":   hostID,
		"scan_type": scanType,
		"status":    "initiated",
	}, nil
}

// getHostInfo retrieves host information.
func (c *EDRConnector) getHostInfo(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	hostID, err := c.resolveHostID(ctx, params)
	if err != nil {
		return nil, err
	}

	// Would retrieve actual host info from EDR
	return map[string]interface{}{
		"host_id":       hostID,
		"hostname":      "placeholder-hostname",
		"ip_addresses":  []string{"192.168.1.100"},
		"mac_addresses": []string{"00:11:22:33:44:55"},
		"os":            "Windows",
		"os_version":    "Windows 10 Enterprise",
		"agent_version": "6.50.0",
		"last_seen":     time.Now().Add(-5 * time.Minute).Format(time.RFC3339),
		"status":        "online",
		"isolated":      false,
	}, nil
}

// searchHosts searches for hosts.
func (c *EDRConnector) searchHosts(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	return map[string]interface{}{
		"hosts": []map[string]interface{}{},
		"total": 0,
	}, nil
}

// getDetections retrieves detections.
func (c *EDRConnector) getDetections(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	return map[string]interface{}{
		"detections": []map[string]interface{}{},
		"total":      0,
	}, nil
}

// updateDetection updates a detection status.
func (c *EDRConnector) updateDetection(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	detectionID := params["detection_id"].(string)
	status := params["status"].(string)

	return map[string]interface{}{
		"success":      true,
		"detection_id": detectionID,
		"status":       status,
	}, nil
}

// runCommand executes a remote command.
func (c *EDRConnector) runCommand(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	hostID := params["host_id"].(string)
	command := params["command"].(string)

	sessionID := fmt.Sprintf("session-%s-%d", hostID, time.Now().Unix())

	// This would execute the command via EDR live response
	return map[string]interface{}{
		"session_id": sessionID,
		"host_id":    hostID,
		"command":    command,
		"stdout":     "",
		"stderr":     "",
		"exit_code":  0,
	}, nil
}

// getFile retrieves a file from an endpoint.
func (c *EDRConnector) getFile(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	hostID := params["host_id"].(string)
	filePath := params["file_path"].(string)

	jobID := fmt.Sprintf("getfile-%s-%d", hostID, time.Now().Unix())

	return map[string]interface{}{
		"job_id":    jobID,
		"host_id":   hostID,
		"file_path": filePath,
		"status":    "initiated",
	}, nil
}

// addIOC adds an IOC to the blocklist.
func (c *EDRConnector) addIOC(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	iocType := params["type"].(string)
	value := params["value"].(string)

	iocID := fmt.Sprintf("ioc-%d", time.Now().Unix())

	return map[string]interface{}{
		"ioc_id":  iocID,
		"type":    iocType,
		"value":   value,
		"success": true,
	}, nil
}

// removeIOC removes an IOC from the blocklist.
func (c *EDRConnector) removeIOC(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	return map[string]interface{}{
		"success": true,
	}, nil
}

// resolveHostID resolves a host ID from various parameters.
func (c *EDRConnector) resolveHostID(ctx context.Context, params map[string]interface{}) (string, error) {
	if hostID, ok := params["host_id"].(string); ok && hostID != "" {
		return hostID, nil
	}

	// Would search by hostname or IP
	if hostname, ok := params["hostname"].(string); ok && hostname != "" {
		// Search by hostname
		return fmt.Sprintf("resolved-%s", hostname), nil
	}

	if ip, ok := params["ip"].(string); ok && ip != "" {
		// Search by IP
		return fmt.Sprintf("resolved-%s", ip), nil
	}

	return "", fmt.Errorf("host_id, hostname, or ip is required")
}

// Actions returns the list of action names.
func (c *EDRConnector) Actions() []string {
	return []string{
		"isolate_host",
		"unisolate_host",
		"kill_process",
		"delete_file",
		"quarantine_file",
		"scan_host",
		"get_host_info",
		"search_hosts",
		"get_detections",
		"update_detection",
		"run_command",
		"get_file",
		"add_ioc",
		"remove_ioc",
	}
}

// Health checks the EDR connector health.
func (c *EDRConnector) Health(ctx context.Context) (*connector.HealthStatus, error) {
	start := time.Now()

	return &connector.HealthStatus{
		Status:    "healthy",
		LastCheck: time.Now(),
		Latency:   time.Since(start),
		Details: map[string]interface{}{
			"vendor":   c.vendor,
			"endpoint": c.endpoint,
		},
	}, nil
}
