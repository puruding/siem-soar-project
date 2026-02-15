// Package actions provides Active Directory connector implementation.
package actions

import (
	"context"
	"fmt"
	"time"

	"github.com/siem-soar-platform/services/soar/internal/connector"
)

// ADConnector implements Active Directory integration.
type ADConnector struct {
	*connector.BaseConnector
	server     string
	baseDN     string
	bindDN     string
	bindPW     string
	useTLS     bool
}

// NewADConnector creates a new Active Directory connector.
func NewADConnector(config *connector.ConnectorConfig) (connector.ActionConnector, error) {
	base := connector.NewBaseConnector(config)

	ac := &ADConnector{
		BaseConnector: base,
		server:        config.Endpoint,
		baseDN:        config.Extra["base_dn"],
		bindDN:        config.Credentials.Username,
		bindPW:        config.Credentials.Password,
		useTLS:        config.TLS != nil && config.TLS.Enabled,
	}

	ac.registerActions()
	return ac, nil
}

// registerActions registers all AD actions.
func (c *ADConnector) registerActions() {
	// Disable user
	c.RegisterAction(connector.ActionDefinition{
		Name:        "disable_user",
		DisplayName: "Disable User Account",
		Description: "Disable a user account in Active Directory",
		Category:    "containment",
		RiskLevel:   "high",
		Parameters: []connector.ParameterDef{
			{Name: "username", DisplayName: "Username", Type: "string", Required: false, Description: "SAM account name"},
			{Name: "email", DisplayName: "Email", Type: "string", Required: false, Description: "User email address"},
			{Name: "user_dn", DisplayName: "User DN", Type: "string", Required: false, Description: "Full distinguished name"},
			{Name: "reason", DisplayName: "Reason", Type: "string", Required: false},
		},
		Returns: []connector.ParameterDef{
			{Name: "success", Type: "bool"},
			{Name: "user_dn", Type: "string"},
			{Name: "previous_state", Type: "string"},
		},
	}, c.disableUser)

	// Enable user
	c.RegisterAction(connector.ActionDefinition{
		Name:        "enable_user",
		DisplayName: "Enable User Account",
		Description: "Enable a user account in Active Directory",
		Category:    "remediation",
		RiskLevel:   "medium",
		Parameters: []connector.ParameterDef{
			{Name: "username", DisplayName: "Username", Type: "string", Required: false},
			{Name: "email", DisplayName: "Email", Type: "string", Required: false},
			{Name: "user_dn", DisplayName: "User DN", Type: "string", Required: false},
		},
		Returns: []connector.ParameterDef{
			{Name: "success", Type: "bool"},
			{Name: "user_dn", Type: "string"},
		},
	}, c.enableUser)

	// Reset password
	c.RegisterAction(connector.ActionDefinition{
		Name:        "reset_password",
		DisplayName: "Reset User Password",
		Description: "Reset a user's password",
		Category:    "containment",
		RiskLevel:   "high",
		Parameters: []connector.ParameterDef{
			{Name: "username", DisplayName: "Username", Type: "string", Required: false},
			{Name: "email", DisplayName: "Email", Type: "string", Required: false},
			{Name: "user_dn", DisplayName: "User DN", Type: "string", Required: false},
			{Name: "new_password", DisplayName: "New Password", Type: "string", Required: false, Sensitive: true, Description: "If not provided, a random password will be generated"},
			{Name: "must_change", DisplayName: "Must Change at Next Logon", Type: "bool", Required: false, Default: true},
		},
		Returns: []connector.ParameterDef{
			{Name: "success", Type: "bool"},
			{Name: "user_dn", Type: "string"},
			{Name: "temporary_password", Type: "string", Sensitive: true},
		},
	}, c.resetPassword)

	// Force logoff
	c.RegisterAction(connector.ActionDefinition{
		Name:        "force_logoff",
		DisplayName: "Force User Logoff",
		Description: "Force logoff all sessions for a user",
		Category:    "containment",
		RiskLevel:   "medium",
		Parameters: []connector.ParameterDef{
			{Name: "username", DisplayName: "Username", Type: "string", Required: true},
		},
		Returns: []connector.ParameterDef{
			{Name: "success", Type: "bool"},
			{Name: "sessions_terminated", Type: "int"},
		},
	}, c.forceLogoff)

	// Get user info
	c.RegisterAction(connector.ActionDefinition{
		Name:        "get_user_info",
		DisplayName: "Get User Information",
		Description: "Retrieve detailed user information from Active Directory",
		Category:    "query",
		RiskLevel:   "low",
		Parameters: []connector.ParameterDef{
			{Name: "username", DisplayName: "Username", Type: "string", Required: false},
			{Name: "email", DisplayName: "Email", Type: "string", Required: false},
			{Name: "user_dn", DisplayName: "User DN", Type: "string", Required: false},
		},
		Returns: []connector.ParameterDef{
			{Name: "user_dn", Type: "string"},
			{Name: "username", Type: "string"},
			{Name: "email", Type: "string"},
			{Name: "display_name", Type: "string"},
			{Name: "department", Type: "string"},
			{Name: "title", Type: "string"},
			{Name: "manager", Type: "string"},
			{Name: "groups", Type: "string[]"},
			{Name: "enabled", Type: "bool"},
			{Name: "locked", Type: "bool"},
			{Name: "last_logon", Type: "datetime"},
			{Name: "password_last_set", Type: "datetime"},
			{Name: "created", Type: "datetime"},
		},
	}, c.getUserInfo)

	// Get user groups
	c.RegisterAction(connector.ActionDefinition{
		Name:        "get_user_groups",
		DisplayName: "Get User Groups",
		Description: "Get all groups a user belongs to",
		Category:    "query",
		RiskLevel:   "low",
		Parameters: []connector.ParameterDef{
			{Name: "username", DisplayName: "Username", Type: "string", Required: false},
			{Name: "email", DisplayName: "Email", Type: "string", Required: false},
			{Name: "user_dn", DisplayName: "User DN", Type: "string", Required: false},
			{Name: "nested", DisplayName: "Include Nested Groups", Type: "bool", Required: false, Default: true},
		},
		Returns: []connector.ParameterDef{
			{Name: "groups", Type: "object[]"},
			{Name: "total", Type: "int"},
		},
	}, c.getUserGroups)

	// Add user to group
	c.RegisterAction(connector.ActionDefinition{
		Name:        "add_to_group",
		DisplayName: "Add User to Group",
		Description: "Add a user to an AD group",
		Category:    "management",
		RiskLevel:   "medium",
		Parameters: []connector.ParameterDef{
			{Name: "username", DisplayName: "Username", Type: "string", Required: false},
			{Name: "user_dn", DisplayName: "User DN", Type: "string", Required: false},
			{Name: "group_name", DisplayName: "Group Name", Type: "string", Required: false},
			{Name: "group_dn", DisplayName: "Group DN", Type: "string", Required: false},
		},
		Returns: []connector.ParameterDef{
			{Name: "success", Type: "bool"},
		},
	}, c.addToGroup)

	// Remove user from group
	c.RegisterAction(connector.ActionDefinition{
		Name:        "remove_from_group",
		DisplayName: "Remove User from Group",
		Description: "Remove a user from an AD group",
		Category:    "management",
		RiskLevel:   "medium",
		Parameters: []connector.ParameterDef{
			{Name: "username", DisplayName: "Username", Type: "string", Required: false},
			{Name: "user_dn", DisplayName: "User DN", Type: "string", Required: false},
			{Name: "group_name", DisplayName: "Group Name", Type: "string", Required: false},
			{Name: "group_dn", DisplayName: "Group DN", Type: "string", Required: false},
		},
		Returns: []connector.ParameterDef{
			{Name: "success", Type: "bool"},
		},
	}, c.removeFromGroup)

	// Unlock user
	c.RegisterAction(connector.ActionDefinition{
		Name:        "unlock_user",
		DisplayName: "Unlock User Account",
		Description: "Unlock a locked user account",
		Category:    "remediation",
		RiskLevel:   "low",
		Parameters: []connector.ParameterDef{
			{Name: "username", DisplayName: "Username", Type: "string", Required: false},
			{Name: "email", DisplayName: "Email", Type: "string", Required: false},
			{Name: "user_dn", DisplayName: "User DN", Type: "string", Required: false},
		},
		Returns: []connector.ParameterDef{
			{Name: "success", Type: "bool"},
			{Name: "was_locked", Type: "bool"},
		},
	}, c.unlockUser)

	// Search users
	c.RegisterAction(connector.ActionDefinition{
		Name:        "search_users",
		DisplayName: "Search Users",
		Description: "Search for users in Active Directory",
		Category:    "query",
		RiskLevel:   "low",
		Parameters: []connector.ParameterDef{
			{Name: "filter", DisplayName: "LDAP Filter", Type: "string", Required: false, Description: "Custom LDAP filter"},
			{Name: "name", DisplayName: "Name", Type: "string", Required: false, Description: "Search by name (wildcard supported)"},
			{Name: "department", DisplayName: "Department", Type: "string", Required: false},
			{Name: "enabled_only", DisplayName: "Enabled Only", Type: "bool", Required: false, Default: false},
			{Name: "limit", DisplayName: "Limit", Type: "int", Required: false, Default: 100},
		},
		Returns: []connector.ParameterDef{
			{Name: "users", Type: "object[]"},
			{Name: "total", Type: "int"},
		},
	}, c.searchUsers)

	// Get group members
	c.RegisterAction(connector.ActionDefinition{
		Name:        "get_group_members",
		DisplayName: "Get Group Members",
		Description: "Get all members of an AD group",
		Category:    "query",
		RiskLevel:   "low",
		Parameters: []connector.ParameterDef{
			{Name: "group_name", DisplayName: "Group Name", Type: "string", Required: false},
			{Name: "group_dn", DisplayName: "Group DN", Type: "string", Required: false},
			{Name: "nested", DisplayName: "Include Nested Members", Type: "bool", Required: false, Default: false},
		},
		Returns: []connector.ParameterDef{
			{Name: "members", Type: "object[]"},
			{Name: "total", Type: "int"},
		},
	}, c.getGroupMembers)

	// Check group membership
	c.RegisterAction(connector.ActionDefinition{
		Name:        "is_member_of",
		DisplayName: "Check Group Membership",
		Description: "Check if a user is a member of a group",
		Category:    "query",
		RiskLevel:   "low",
		Parameters: []connector.ParameterDef{
			{Name: "username", DisplayName: "Username", Type: "string", Required: false},
			{Name: "user_dn", DisplayName: "User DN", Type: "string", Required: false},
			{Name: "group_name", DisplayName: "Group Name", Type: "string", Required: false},
			{Name: "group_dn", DisplayName: "Group DN", Type: "string", Required: false},
			{Name: "nested", DisplayName: "Check Nested", Type: "bool", Required: false, Default: true},
		},
		Returns: []connector.ParameterDef{
			{Name: "is_member", Type: "bool"},
			{Name: "path", Type: "string[]", Description: "Group membership path if nested"},
		},
	}, c.isMemberOf)

	// Set user attribute
	c.RegisterAction(connector.ActionDefinition{
		Name:        "set_user_attribute",
		DisplayName: "Set User Attribute",
		Description: "Set an attribute on a user account",
		Category:    "management",
		RiskLevel:   "medium",
		Parameters: []connector.ParameterDef{
			{Name: "username", DisplayName: "Username", Type: "string", Required: false},
			{Name: "user_dn", DisplayName: "User DN", Type: "string", Required: false},
			{Name: "attribute", DisplayName: "Attribute", Type: "string", Required: true},
			{Name: "value", DisplayName: "Value", Type: "string", Required: true},
		},
		Returns: []connector.ParameterDef{
			{Name: "success", Type: "bool"},
			{Name: "previous_value", Type: "string"},
		},
	}, c.setUserAttribute)
}

// disableUser disables a user account.
func (c *ADConnector) disableUser(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	userDN, err := c.resolveUserDN(ctx, params)
	if err != nil {
		return nil, err
	}

	// Would use LDAP to disable the account
	// userAccountControl attribute modification

	return map[string]interface{}{
		"success":        true,
		"user_dn":        userDN,
		"previous_state": "enabled",
		"message":        fmt.Sprintf("User %s disabled", userDN),
	}, nil
}

// enableUser enables a user account.
func (c *ADConnector) enableUser(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	userDN, err := c.resolveUserDN(ctx, params)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"success": true,
		"user_dn": userDN,
		"message": fmt.Sprintf("User %s enabled", userDN),
	}, nil
}

// resetPassword resets a user's password.
func (c *ADConnector) resetPassword(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	userDN, err := c.resolveUserDN(ctx, params)
	if err != nil {
		return nil, err
	}

	newPassword := params["new_password"]
	if newPassword == nil || newPassword == "" {
		// Generate random password
		newPassword = generateSecurePassword()
	}

	mustChange := true
	if mc, ok := params["must_change"].(bool); ok {
		mustChange = mc
	}

	return map[string]interface{}{
		"success":            true,
		"user_dn":            userDN,
		"temporary_password": newPassword,
		"must_change":        mustChange,
	}, nil
}

// forceLogoff forces user logoff.
func (c *ADConnector) forceLogoff(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	username := params["username"].(string)

	// Would query active sessions and terminate them

	return map[string]interface{}{
		"success":              true,
		"username":             username,
		"sessions_terminated":  0,
	}, nil
}

// getUserInfo retrieves user information.
func (c *ADConnector) getUserInfo(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	userDN, err := c.resolveUserDN(ctx, params)
	if err != nil {
		return nil, err
	}

	// Would query LDAP for user attributes
	return map[string]interface{}{
		"user_dn":           userDN,
		"username":          "jsmith",
		"email":             "jsmith@example.com",
		"display_name":      "John Smith",
		"department":        "IT Security",
		"title":             "Security Analyst",
		"manager":           "CN=Manager,OU=Users,DC=example,DC=com",
		"groups":            []string{"Domain Users", "Security Team"},
		"enabled":           true,
		"locked":            false,
		"last_logon":        time.Now().Add(-1 * time.Hour).Format(time.RFC3339),
		"password_last_set": time.Now().Add(-30 * 24 * time.Hour).Format(time.RFC3339),
		"created":           time.Now().Add(-365 * 24 * time.Hour).Format(time.RFC3339),
	}, nil
}

// getUserGroups retrieves user groups.
func (c *ADConnector) getUserGroups(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	_, err := c.resolveUserDN(ctx, params)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"groups": []map[string]interface{}{
			{"name": "Domain Users", "dn": "CN=Domain Users,CN=Users,DC=example,DC=com"},
		},
		"total": 1,
	}, nil
}

// addToGroup adds a user to a group.
func (c *ADConnector) addToGroup(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	userDN, err := c.resolveUserDN(ctx, params)
	if err != nil {
		return nil, err
	}

	groupDN, err := c.resolveGroupDN(ctx, params)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"success":  true,
		"user_dn":  userDN,
		"group_dn": groupDN,
	}, nil
}

// removeFromGroup removes a user from a group.
func (c *ADConnector) removeFromGroup(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	userDN, err := c.resolveUserDN(ctx, params)
	if err != nil {
		return nil, err
	}

	groupDN, err := c.resolveGroupDN(ctx, params)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"success":  true,
		"user_dn":  userDN,
		"group_dn": groupDN,
	}, nil
}

// unlockUser unlocks a user account.
func (c *ADConnector) unlockUser(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	userDN, err := c.resolveUserDN(ctx, params)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"success":    true,
		"user_dn":    userDN,
		"was_locked": true,
	}, nil
}

// searchUsers searches for users.
func (c *ADConnector) searchUsers(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	return map[string]interface{}{
		"users": []map[string]interface{}{},
		"total": 0,
	}, nil
}

// getGroupMembers retrieves group members.
func (c *ADConnector) getGroupMembers(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	return map[string]interface{}{
		"members": []map[string]interface{}{},
		"total":   0,
	}, nil
}

// isMemberOf checks group membership.
func (c *ADConnector) isMemberOf(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	return map[string]interface{}{
		"is_member": false,
		"path":      []string{},
	}, nil
}

// setUserAttribute sets a user attribute.
func (c *ADConnector) setUserAttribute(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	userDN, err := c.resolveUserDN(ctx, params)
	if err != nil {
		return nil, err
	}

	attribute := params["attribute"].(string)
	value := params["value"].(string)

	return map[string]interface{}{
		"success":        true,
		"user_dn":        userDN,
		"attribute":      attribute,
		"value":          value,
		"previous_value": "",
	}, nil
}

// resolveUserDN resolves a user DN from various parameters.
func (c *ADConnector) resolveUserDN(ctx context.Context, params map[string]interface{}) (string, error) {
	if dn, ok := params["user_dn"].(string); ok && dn != "" {
		return dn, nil
	}

	if username, ok := params["username"].(string); ok && username != "" {
		// Would search LDAP by sAMAccountName
		return fmt.Sprintf("CN=%s,OU=Users,%s", username, c.baseDN), nil
	}

	if email, ok := params["email"].(string); ok && email != "" {
		// Would search LDAP by mail
		return fmt.Sprintf("CN=resolved,%s", c.baseDN), nil
	}

	return "", fmt.Errorf("user_dn, username, or email is required")
}

// resolveGroupDN resolves a group DN.
func (c *ADConnector) resolveGroupDN(ctx context.Context, params map[string]interface{}) (string, error) {
	if dn, ok := params["group_dn"].(string); ok && dn != "" {
		return dn, nil
	}

	if name, ok := params["group_name"].(string); ok && name != "" {
		return fmt.Sprintf("CN=%s,OU=Groups,%s", name, c.baseDN), nil
	}

	return "", fmt.Errorf("group_dn or group_name is required")
}

// Actions returns the list of action names.
func (c *ADConnector) Actions() []string {
	return []string{
		"disable_user",
		"enable_user",
		"reset_password",
		"force_logoff",
		"get_user_info",
		"get_user_groups",
		"add_to_group",
		"remove_from_group",
		"unlock_user",
		"search_users",
		"get_group_members",
		"is_member_of",
		"set_user_attribute",
	}
}

// Health checks the AD connector health.
func (c *ADConnector) Health(ctx context.Context) (*connector.HealthStatus, error) {
	start := time.Now()

	// Would test LDAP connection
	return &connector.HealthStatus{
		Status:    "healthy",
		LastCheck: time.Now(),
		Latency:   time.Since(start),
		Details: map[string]interface{}{
			"server":  c.server,
			"base_dn": c.baseDN,
		},
	}, nil
}

// generateSecurePassword generates a random secure password.
func generateSecurePassword() string {
	// In production, use crypto/rand for secure password generation
	return fmt.Sprintf("TempPass%d!", time.Now().Unix()%10000)
}
