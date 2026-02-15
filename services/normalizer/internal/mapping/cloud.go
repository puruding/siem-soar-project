// Package mapping provides log source-specific UDM mappings.
package mapping

import (
	"github.com/siem-soar-platform/services/normalizer/internal/udm"
)

// AWSCloudTrailMapping returns UDM mapping for AWS CloudTrail logs.
func AWSCloudTrailMapping() *udm.MappingConfig {
	return &udm.MappingConfig{
		Name:         "aws_cloudtrail",
		SourceType:   "cloudtrail",
		VendorName:   "Amazon",
		ProductName:  "AWS CloudTrail",
		DefaultEventType: udm.EventTypeGeneric,
		EventTypeMappings: map[string]udm.EventType{
			"eventName==ConsoleLogin":              udm.EventTypeUserLogin,
			"eventName==SwitchRole":                udm.EventTypeUserLogin,
			"eventName==AssumeRole":                udm.EventTypeUserLogin,
			"eventName==CreateUser":                udm.EventTypeUserCreation,
			"eventName==DeleteUser":                udm.EventTypeUserDeletion,
			"eventName==UpdateUser":                udm.EventTypeUserPrivilegeChange,
			"eventName==CreateAccessKey":           udm.EventTypeUserPrivilegeChange,
			"eventName==DeleteAccessKey":           udm.EventTypeUserPrivilegeChange,
			"eventName==CreateGroup":               udm.EventTypeGroupCreation,
			"eventName==DeleteGroup":               udm.EventTypeGroupDeletion,
			"eventName==AddUserToGroup":            udm.EventTypeGroupModification,
			"eventName==RemoveUserFromGroup":       udm.EventTypeGroupModification,
			"eventName==AttachUserPolicy":          udm.EventTypeUserPrivilegeChange,
			"eventName==DetachUserPolicy":          udm.EventTypeUserPrivilegeChange,
			"eventName==CreateRole":                udm.EventTypeResourceCreation,
			"eventName==DeleteRole":                udm.EventTypeResourceDeletion,
			"eventName==CreateBucket":              udm.EventTypeResourceCreation,
			"eventName==DeleteBucket":              udm.EventTypeResourceDeletion,
			"eventName==PutBucketPolicy":           udm.EventTypeResourceAccess,
			"eventName==GetObject":                 udm.EventTypeFileRead,
			"eventName==PutObject":                 udm.EventTypeFileCreation,
			"eventName==DeleteObject":              udm.EventTypeFileDeletion,
			"eventName==RunInstances":              udm.EventTypeResourceCreation,
			"eventName==TerminateInstances":        udm.EventTypeResourceDeletion,
			"eventName==StartInstances":            udm.EventTypeServiceStart,
			"eventName==StopInstances":             udm.EventTypeServiceStop,
			"eventName==AuthorizeSecurityGroupIngress": udm.EventTypeNetworkConnection,
			"eventName==RevokeSecurityGroupIngress":    udm.EventTypeNetworkConnection,
		},
		FieldMappings: []udm.FieldMapping{
			// Metadata
			{SourceField: "eventTime", TargetField: "metadata.event_timestamp", Transform: "to_timestamp"},
			{SourceField: "eventName", TargetField: "metadata.product_event_type"},
			{SourceField: "eventSource", TargetField: "metadata.product_name"},
			{SourceField: "awsRegion", TargetField: "observer.cloud.availability_zone"},
			{SourceField: "eventID", TargetField: "metadata.id"},

			// Principal (Who)
			{SourceField: "userIdentity.userName", TargetField: "principal.user.user_name"},
			{SourceField: "userIdentity.arn", TargetField: "principal.user.product_object_id"},
			{SourceField: "userIdentity.accountId", TargetField: "principal.cloud.project.id"},
			{SourceField: "userIdentity.principalId", TargetField: "principal.user.user_id"},
			{SourceField: "userIdentity.type", TargetField: "principal.user.user_authentication_status"},
			{SourceField: "userIdentity.accessKeyId", TargetField: "extensions.auth.auth_metadata"},
			{SourceField: "sourceIPAddress", TargetField: "principal.ip"},
			{SourceField: "userAgent", TargetField: "network.http.user_agent"},

			// Target (What)
			{SourceField: "resources.0.ARN", TargetField: "target.resource.product_object_id"},
			{SourceField: "resources.0.type", TargetField: "target.resource.resource_type"},
			{SourceField: "resources.0.accountId", TargetField: "target.cloud.project.id"},
			{SourceField: "requestParameters.bucketName", TargetField: "target.resource.name"},
			{SourceField: "requestParameters.instanceId", TargetField: "target.asset.asset_id"},
			{SourceField: "requestParameters.userName", TargetField: "target.user.user_name"},
			{SourceField: "requestParameters.groupName", TargetField: "target.resource.name"},
			{SourceField: "requestParameters.roleName", TargetField: "target.resource.name"},
			{SourceField: "requestParameters.key", TargetField: "target.file.file_name"},

			// Cloud context
			{SourceField: "recipientAccountId", TargetField: "target.cloud.project.id"},
			{SourceField: "awsRegion", TargetField: "target.cloud.availability_zone"},
			{SourceField: "vpcEndpointId", TargetField: "target.cloud.vpc.id"},

			// Security result
			{
				SourceField: "errorCode",
				TargetField: "security_result.action",
				Transform:   "map_value",
				Parameters: map[string]string{
					"":                  "ALLOW",
					"AccessDenied":      "BLOCK",
					"UnauthorizedAccess": "BLOCK",
					"default":           "UNKNOWN",
				},
			},
			{SourceField: "errorMessage", TargetField: "security_result.severity_details"},
			{SourceField: "readOnly", TargetField: "security_result.category"},
		},
	}
}

// GCPAuditMapping returns UDM mapping for GCP Audit logs.
func GCPAuditMapping() *udm.MappingConfig {
	return &udm.MappingConfig{
		Name:         "gcp_audit",
		SourceType:   "gcp_audit",
		VendorName:   "Google",
		ProductName:  "GCP Audit Logs",
		DefaultEventType: udm.EventTypeGeneric,
		EventTypeMappings: map[string]udm.EventType{
			"protoPayload.methodName==google.login.LoginService.loginSuccess": udm.EventTypeUserLogin,
			"protoPayload.methodName==google.login.LoginService.loginFailure": udm.EventTypeUserLogin,
			"protoPayload.methodName==CreateUser":           udm.EventTypeUserCreation,
			"protoPayload.methodName==DeleteUser":           udm.EventTypeUserDeletion,
			"protoPayload.methodName==SetIamPolicy":         udm.EventTypeUserPrivilegeChange,
			"protoPayload.methodName==storage.objects.get":  udm.EventTypeFileRead,
			"protoPayload.methodName==storage.objects.create": udm.EventTypeFileCreation,
			"protoPayload.methodName==storage.objects.delete": udm.EventTypeFileDeletion,
			"protoPayload.methodName==compute.instances.insert": udm.EventTypeResourceCreation,
			"protoPayload.methodName==compute.instances.delete": udm.EventTypeResourceDeletion,
			"protoPayload.methodName==compute.instances.start":  udm.EventTypeServiceStart,
			"protoPayload.methodName==compute.instances.stop":   udm.EventTypeServiceStop,
		},
		FieldMappings: []udm.FieldMapping{
			// Metadata
			{SourceField: "timestamp", TargetField: "metadata.event_timestamp", Transform: "to_timestamp"},
			{SourceField: "protoPayload.methodName", TargetField: "metadata.product_event_type"},
			{SourceField: "protoPayload.serviceName", TargetField: "metadata.product_name"},
			{SourceField: "insertId", TargetField: "metadata.id"},
			{SourceField: "logName", TargetField: "metadata.log_type"},

			// Principal
			{SourceField: "protoPayload.authenticationInfo.principalEmail", TargetField: "principal.user.email_addresses", Multiple: true},
			{SourceField: "protoPayload.authenticationInfo.principalSubject", TargetField: "principal.user.user_id"},
			{SourceField: "protoPayload.requestMetadata.callerIp", TargetField: "principal.ip"},
			{SourceField: "protoPayload.requestMetadata.callerSuppliedUserAgent", TargetField: "network.http.user_agent"},

			// Target resource
			{SourceField: "protoPayload.resourceName", TargetField: "target.resource.product_object_id"},
			{SourceField: "resource.type", TargetField: "target.resource.resource_type"},
			{SourceField: "resource.labels.project_id", TargetField: "target.cloud.project.id"},
			{SourceField: "resource.labels.zone", TargetField: "target.cloud.availability_zone"},
			{SourceField: "resource.labels.instance_id", TargetField: "target.asset.asset_id"},
			{SourceField: "resource.labels.bucket_name", TargetField: "target.resource.name"},

			// Cloud context
			{SourceField: "resource.labels.project_id", TargetField: "observer.cloud.project.id"},
			{SourceField: "resource.labels.location", TargetField: "observer.cloud.availability_zone"},

			// Security result
			{
				SourceField: "protoPayload.status.code",
				TargetField: "security_result.action",
				Transform:   "map_value",
				Parameters: map[string]string{
					"0":  "ALLOW",  // OK
					"7":  "BLOCK",  // PERMISSION_DENIED
					"16": "BLOCK",  // UNAUTHENTICATED
					"default": "UNKNOWN",
				},
			},
			{SourceField: "protoPayload.status.message", TargetField: "security_result.severity_details"},
			{SourceField: "severity", TargetField: "security_result.severity"},
		},
	}
}

// AzureActivityMapping returns UDM mapping for Azure Activity logs.
func AzureActivityMapping() *udm.MappingConfig {
	return &udm.MappingConfig{
		Name:         "azure_activity",
		SourceType:   "azure_activity",
		VendorName:   "Microsoft",
		ProductName:  "Azure Activity Logs",
		DefaultEventType: udm.EventTypeGeneric,
		EventTypeMappings: map[string]udm.EventType{
			"operationName==Microsoft.Authorization/roleAssignments/write":   udm.EventTypeUserPrivilegeChange,
			"operationName==Microsoft.Authorization/roleAssignments/delete":  udm.EventTypeUserPrivilegeChange,
			"operationName==Microsoft.Compute/virtualMachines/write":         udm.EventTypeResourceCreation,
			"operationName==Microsoft.Compute/virtualMachines/delete":        udm.EventTypeResourceDeletion,
			"operationName==Microsoft.Compute/virtualMachines/start/action":  udm.EventTypeServiceStart,
			"operationName==Microsoft.Compute/virtualMachines/deallocate/action": udm.EventTypeServiceStop,
			"operationName==Microsoft.Storage/storageAccounts/write":         udm.EventTypeResourceCreation,
			"operationName==Microsoft.Storage/storageAccounts/delete":        udm.EventTypeResourceDeletion,
			"operationName==Microsoft.Network/networkSecurityGroups/securityRules/write": udm.EventTypeNetworkConnection,
		},
		FieldMappings: []udm.FieldMapping{
			// Metadata
			{SourceField: "eventTimestamp", TargetField: "metadata.event_timestamp", Transform: "to_timestamp"},
			{SourceField: "operationName", TargetField: "metadata.product_event_type"},
			{SourceField: "resourceProviderName", TargetField: "metadata.product_name"},
			{SourceField: "correlationId", TargetField: "metadata.id"},
			{SourceField: "category", TargetField: "metadata.log_type"},

			// Principal
			{SourceField: "caller", TargetField: "principal.user.email_addresses", Multiple: true},
			{SourceField: "claims.name", TargetField: "principal.user.user_name"},
			{SourceField: "claims.oid", TargetField: "principal.user.user_id"},
			{SourceField: "claims.ipaddr", TargetField: "principal.ip"},
			{SourceField: "httpRequest.clientIpAddress", TargetField: "principal.ip"},

			// Target resource
			{SourceField: "resourceId", TargetField: "target.resource.product_object_id"},
			{SourceField: "resourceType", TargetField: "target.resource.resource_type"},
			{SourceField: "subscriptionId", TargetField: "target.cloud.project.id"},
			{SourceField: "resourceGroupName", TargetField: "target.cloud.project.name"},

			// Cloud context
			{SourceField: "tenantId", TargetField: "observer.cloud.project.parent_project"},
			{SourceField: "level", TargetField: "observer.cloud.environment"},

			// Security result
			{
				SourceField: "status",
				TargetField: "security_result.action",
				Transform:   "map_value",
				Parameters: map[string]string{
					"Succeeded": "ALLOW",
					"Failed":    "BLOCK",
					"Started":   "ALLOW",
					"default":   "UNKNOWN",
				},
			},
			{SourceField: "subStatus", TargetField: "security_result.severity_details"},
			{
				SourceField: "level",
				TargetField: "security_result.severity",
				Transform:   "map_value",
				Parameters: map[string]string{
					"Critical":      "CRITICAL",
					"Error":         "HIGH",
					"Warning":       "MEDIUM",
					"Informational": "INFORMATIONAL",
					"default":       "UNKNOWN",
				},
			},
		},
	}
}

// Office365Mapping returns UDM mapping for Office 365 audit logs.
func Office365Mapping() *udm.MappingConfig {
	return &udm.MappingConfig{
		Name:         "office365",
		SourceType:   "office365",
		VendorName:   "Microsoft",
		ProductName:  "Office 365",
		DefaultEventType: udm.EventTypeGeneric,
		EventTypeMappings: map[string]udm.EventType{
			"Operation==UserLoggedIn":           udm.EventTypeUserLogin,
			"Operation==UserLoginFailed":        udm.EventTypeUserLogin,
			"Operation==PasswordLogonInitialAuthUsingPassword": udm.EventTypeUserLogin,
			"Operation==FileAccessed":           udm.EventTypeFileRead,
			"Operation==FileDownloaded":         udm.EventTypeFileRead,
			"Operation==FileUploaded":           udm.EventTypeFileCreation,
			"Operation==FileDeleted":            udm.EventTypeFileDeletion,
			"Operation==FileModified":           udm.EventTypeFileModification,
			"Operation==FileCopied":             udm.EventTypeFileCopy,
			"Operation==FileMoved":              udm.EventTypeFileMove,
			"Operation==Add member to group":    udm.EventTypeGroupModification,
			"Operation==Remove member from group": udm.EventTypeGroupModification,
			"Operation==Add user":               udm.EventTypeUserCreation,
			"Operation==Delete user":            udm.EventTypeUserDeletion,
			"Operation==Set user properties":    udm.EventTypeUserPrivilegeChange,
		},
		FieldMappings: []udm.FieldMapping{
			// Metadata
			{SourceField: "CreationTime", TargetField: "metadata.event_timestamp", Transform: "to_timestamp"},
			{SourceField: "Operation", TargetField: "metadata.product_event_type"},
			{SourceField: "Workload", TargetField: "metadata.product_name"},
			{SourceField: "Id", TargetField: "metadata.id"},
			{SourceField: "RecordType", TargetField: "metadata.log_type"},

			// Principal
			{SourceField: "UserId", TargetField: "principal.user.email_addresses", Multiple: true},
			{SourceField: "UserKey", TargetField: "principal.user.user_id"},
			{SourceField: "ClientIP", TargetField: "principal.ip"},
			{SourceField: "UserAgent", TargetField: "network.http.user_agent"},
			{SourceField: "Actor.0.ID", TargetField: "principal.user.user_name"},

			// Target
			{SourceField: "ObjectId", TargetField: "target.resource.product_object_id"},
			{SourceField: "SourceFileName", TargetField: "target.file.file_name"},
			{SourceField: "SourceRelativeUrl", TargetField: "target.file.full_path"},
			{SourceField: "SiteUrl", TargetField: "target.resource.name"},
			{SourceField: "TargetUserOrGroupName", TargetField: "target.user.user_name"},
			{SourceField: "ModifiedProperties", TargetField: "target.resource.attribute"},

			// Cloud context
			{SourceField: "OrganizationId", TargetField: "observer.cloud.project.id"},

			// Security result
			{
				SourceField: "ResultStatus",
				TargetField: "security_result.action",
				Transform:   "map_value",
				Parameters: map[string]string{
					"Succeeded": "ALLOW",
					"Success":   "ALLOW",
					"Failed":    "BLOCK",
					"default":   "UNKNOWN",
				},
			},
			{SourceField: "ExtendedProperties", TargetField: "security_result.detection_fields"},
		},
	}
}

// KubernetesAuditMapping returns UDM mapping for Kubernetes audit logs.
func KubernetesAuditMapping() *udm.MappingConfig {
	return &udm.MappingConfig{
		Name:         "kubernetes_audit",
		SourceType:   "kubernetes",
		VendorName:   "CNCF",
		ProductName:  "Kubernetes",
		DefaultEventType: udm.EventTypeResourceAccess,
		EventTypeMappings: map[string]udm.EventType{
			"verb==create": udm.EventTypeResourceCreation,
			"verb==delete": udm.EventTypeResourceDeletion,
			"verb==update": udm.EventTypeResourceAccess,
			"verb==patch":  udm.EventTypeResourceAccess,
			"verb==get":    udm.EventTypeResourceAccess,
			"verb==list":   udm.EventTypeResourceAccess,
			"verb==watch":  udm.EventTypeResourceAccess,
		},
		FieldMappings: []udm.FieldMapping{
			// Metadata
			{SourceField: "stageTimestamp", TargetField: "metadata.event_timestamp", Transform: "to_timestamp"},
			{SourceField: "verb", TargetField: "metadata.product_event_type"},
			{SourceField: "auditID", TargetField: "metadata.id"},
			{SourceField: "stage", TargetField: "metadata.log_type"},

			// Principal (Who)
			{SourceField: "user.username", TargetField: "principal.user.user_name"},
			{SourceField: "user.uid", TargetField: "principal.user.user_id"},
			{SourceField: "user.groups", TargetField: "principal.user.group_ids", Multiple: true},
			{SourceField: "sourceIPs.0", TargetField: "principal.ip"},
			{SourceField: "userAgent", TargetField: "network.http.user_agent"},
			{SourceField: "impersonatedUser.username", TargetField: "target.user.user_name"},

			// Target (What)
			{SourceField: "objectRef.resource", TargetField: "target.resource.resource_type"},
			{SourceField: "objectRef.namespace", TargetField: "target.namespace"},
			{SourceField: "objectRef.name", TargetField: "target.resource.name"},
			{SourceField: "objectRef.uid", TargetField: "target.resource.product_object_id"},
			{SourceField: "objectRef.apiGroup", TargetField: "target.resource.resource_subtype"},
			{SourceField: "objectRef.apiVersion", TargetField: "target.resource.attribute"},

			// Request info
			{SourceField: "requestURI", TargetField: "network.http.url"},

			// Security result
			{
				SourceField: "responseStatus.code",
				TargetField: "security_result.action",
				Transform:   "map_value",
				Parameters: map[string]string{
					"200": "ALLOW",
					"201": "ALLOW",
					"202": "ALLOW",
					"204": "ALLOW",
					"401": "BLOCK",
					"403": "BLOCK",
					"404": "BLOCK",
					"default": "UNKNOWN",
				},
			},
			{SourceField: "responseStatus.message", TargetField: "security_result.severity_details"},
			{SourceField: "responseStatus.reason", TargetField: "security_result.category"},
			{SourceField: "level", TargetField: "security_result.severity"},
		},
	}
}
