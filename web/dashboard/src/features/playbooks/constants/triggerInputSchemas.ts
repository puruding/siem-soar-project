/**
 * Default Input Schemas for each Trigger Type
 * These provide sensible defaults that can be extended per playbook
 */

import type { PlaybookInputField, TriggerType, IntegrationType } from '../types/inputSchema';

// Base schemas for each trigger type
export const TRIGGER_INPUT_SCHEMAS: Record<TriggerType, PlaybookInputField[]> = {
  alert: [
    {
      id: 'alert_id',
      name: 'alert_id',
      label: 'Alert ID',
      type: 'text',
      required: true,
      placeholder: 'ALERT-001',
      description: 'Unique alert identifier',
      order: 1,
    },
    {
      id: 'severity',
      name: 'severity',
      label: 'Severity',
      type: 'select',
      required: true,
      defaultValue: 'medium',
      order: 2,
      validation: {
        options: [
          { value: 'low', label: 'Low' },
          { value: 'medium', label: 'Medium' },
          { value: 'high', label: 'High' },
          { value: 'critical', label: 'Critical' },
        ],
      },
    },
    {
      id: 'source_ip',
      name: 'source_ip',
      label: 'Source IP',
      type: 'ip',
      required: false,
      placeholder: '192.168.1.100',
      group: 'Network',
      order: 3,
      validation: { ipVersion: 'both' },
    },
    {
      id: 'target_ip',
      name: 'target_ip',
      label: 'Target IP',
      type: 'ip',
      required: false,
      placeholder: '10.0.0.50',
      group: 'Network',
      order: 4,
      validation: { ipVersion: 'both' },
    },
    {
      id: 'hostname',
      name: 'hostname',
      label: 'Hostname',
      type: 'text',
      required: false,
      placeholder: 'workstation-01',
      group: 'Asset',
      order: 5,
    },
    {
      id: 'username',
      name: 'username',
      label: 'Username',
      type: 'text',
      required: false,
      placeholder: 'jdoe',
      group: 'User',
      order: 6,
    },
  ],

  webhook: [
    {
      id: 'payload',
      name: 'payload',
      label: 'Webhook Payload',
      type: 'json',
      required: true,
      description: 'JSON payload received from webhook',
      placeholder: '{"event": "...", "data": {...}}',
      order: 1,
    },
    {
      id: 'source_system',
      name: 'source_system',
      label: 'Source System',
      type: 'text',
      required: false,
      placeholder: 'external-service',
      order: 2,
    },
    {
      id: 'headers',
      name: 'headers',
      label: 'Request Headers',
      type: 'json',
      required: false,
      description: 'HTTP headers from the webhook request',
      order: 3,
    },
  ],

  manual: [
    {
      id: 'execution_reason',
      name: 'execution_reason',
      label: 'Execution Reason',
      type: 'textarea',
      required: false,
      placeholder: 'Describe why this playbook is being executed manually...',
      description: 'Optional notes for this manual execution',
      order: 1,
    },
    {
      id: 'operator',
      name: 'operator',
      label: 'Operator',
      type: 'text',
      required: false,
      placeholder: 'SOC Analyst',
      description: 'Person initiating this execution',
      order: 2,
    },
  ],

  schedule: [
    {
      id: 'scheduled_time',
      name: 'scheduled_time',
      label: 'Scheduled Time',
      type: 'datetime',
      required: false,
      description: 'When this execution was scheduled',
      readOnly: true,
      order: 1,
    },
    {
      id: 'schedule_name',
      name: 'schedule_name',
      label: 'Schedule Name',
      type: 'text',
      required: false,
      readOnly: true,
      order: 2,
    },
  ],

  case: [
    {
      id: 'case_id',
      name: 'case_id',
      label: 'Case ID',
      type: 'text',
      required: true,
      placeholder: 'CASE-001',
      order: 1,
    },
    {
      id: 'case_name',
      name: 'case_name',
      label: 'Case Name',
      type: 'text',
      required: false,
      placeholder: 'Malware Investigation',
      order: 2,
    },
    {
      id: 'case_severity',
      name: 'case_severity',
      label: 'Case Severity',
      type: 'select',
      required: false,
      defaultValue: 'medium',
      order: 3,
      validation: {
        options: [
          { value: 'low', label: 'Low' },
          { value: 'medium', label: 'Medium' },
          { value: 'high', label: 'High' },
          { value: 'critical', label: 'Critical' },
        ],
      },
    },
    {
      id: 'assignee',
      name: 'assignee',
      label: 'Assignee',
      type: 'text',
      required: false,
      placeholder: 'analyst@example.com',
      order: 4,
    },
  ],
};

// Integration-specific input templates
export const INTEGRATION_INPUT_TEMPLATES: Record<IntegrationType, PlaybookInputField[]> = {
  firewall: [
    {
      id: 'firewall_action',
      name: 'firewall_action',
      label: 'Action',
      type: 'select',
      required: true,
      order: 1,
      validation: {
        options: [
          { value: 'block', label: 'Block' },
          { value: 'allow', label: 'Allow' },
          { value: 'log', label: 'Log Only' },
          { value: 'quarantine', label: 'Quarantine' },
        ],
      },
    },
    {
      id: 'rule_name',
      name: 'rule_name',
      label: 'Rule Name',
      type: 'text',
      required: false,
      placeholder: 'Block-Malicious-IP',
      order: 2,
    },
    {
      id: 'source_cidr',
      name: 'source_cidr',
      label: 'Source CIDR',
      type: 'ip',
      required: false,
      placeholder: '192.168.0.0/24',
      group: 'Network',
      order: 3,
      validation: { ipVersion: 'both' },
    },
    {
      id: 'destination_cidr',
      name: 'destination_cidr',
      label: 'Destination CIDR',
      type: 'ip',
      required: false,
      placeholder: '10.0.0.0/8',
      group: 'Network',
      order: 4,
      validation: { ipVersion: 'both' },
    },
    {
      id: 'port',
      name: 'port',
      label: 'Port',
      type: 'number',
      required: false,
      placeholder: '443',
      group: 'Network',
      order: 5,
      validation: { min: 1, max: 65535 },
    },
    {
      id: 'protocol',
      name: 'protocol',
      label: 'Protocol',
      type: 'select',
      required: false,
      defaultValue: 'tcp',
      group: 'Network',
      order: 6,
      validation: {
        options: [
          { value: 'tcp', label: 'TCP' },
          { value: 'udp', label: 'UDP' },
          { value: 'icmp', label: 'ICMP' },
          { value: 'any', label: 'Any' },
        ],
      },
    },
  ],

  edr: [
    {
      id: 'endpoint_id',
      name: 'endpoint_id',
      label: 'Endpoint ID',
      type: 'text',
      required: true,
      placeholder: 'EP-001',
      order: 1,
    },
    {
      id: 'edr_action',
      name: 'edr_action',
      label: 'Action',
      type: 'select',
      required: true,
      order: 2,
      validation: {
        options: [
          { value: 'isolate', label: 'Isolate Endpoint' },
          { value: 'unisolate', label: 'Remove Isolation' },
          { value: 'scan', label: 'Full Scan' },
          { value: 'collect', label: 'Collect Artifacts' },
          { value: 'kill_process', label: 'Kill Process' },
        ],
      },
    },
    {
      id: 'file_hash',
      name: 'file_hash',
      label: 'File Hash',
      type: 'hash',
      required: false,
      placeholder: 'SHA256 hash',
      order: 3,
      validation: { hashType: 'any' },
    },
    {
      id: 'process_name',
      name: 'process_name',
      label: 'Process Name',
      type: 'text',
      required: false,
      placeholder: 'malware.exe',
      order: 4,
    },
  ],

  email: [
    {
      id: 'message_id',
      name: 'message_id',
      label: 'Message ID',
      type: 'text',
      required: true,
      placeholder: '<message-id@domain.com>',
      order: 1,
    },
    {
      id: 'sender_email',
      name: 'sender_email',
      label: 'Sender Email',
      type: 'email',
      required: false,
      placeholder: 'attacker@malicious.com',
      order: 2,
    },
    {
      id: 'email_action',
      name: 'email_action',
      label: 'Action',
      type: 'select',
      required: true,
      order: 3,
      validation: {
        options: [
          { value: 'delete', label: 'Delete Message' },
          { value: 'quarantine', label: 'Quarantine' },
          { value: 'block_sender', label: 'Block Sender' },
          { value: 'report_phishing', label: 'Report as Phishing' },
        ],
      },
    },
    {
      id: 'recipient_email',
      name: 'recipient_email',
      label: 'Recipient Email',
      type: 'email',
      required: false,
      placeholder: 'user@company.com',
      order: 4,
    },
  ],

  ticketing: [
    {
      id: 'ticket_type',
      name: 'ticket_type',
      label: 'Ticket Type',
      type: 'select',
      required: true,
      order: 1,
      validation: {
        options: [
          { value: 'incident', label: 'Incident' },
          { value: 'problem', label: 'Problem' },
          { value: 'change', label: 'Change Request' },
          { value: 'service_request', label: 'Service Request' },
        ],
      },
    },
    {
      id: 'ticket_priority',
      name: 'ticket_priority',
      label: 'Priority',
      type: 'select',
      required: false,
      defaultValue: 'medium',
      order: 2,
      validation: {
        options: [
          { value: 'low', label: 'Low' },
          { value: 'medium', label: 'Medium' },
          { value: 'high', label: 'High' },
          { value: 'urgent', label: 'Urgent' },
        ],
      },
    },
    {
      id: 'ticket_title',
      name: 'ticket_title',
      label: 'Title',
      type: 'text',
      required: true,
      placeholder: 'Security Incident - Malware Detected',
      order: 3,
    },
    {
      id: 'ticket_description',
      name: 'ticket_description',
      label: 'Description',
      type: 'textarea',
      required: true,
      placeholder: 'Describe the issue...',
      order: 4,
    },
    {
      id: 'ticket_assignee',
      name: 'ticket_assignee',
      label: 'Assignee',
      type: 'text',
      required: false,
      placeholder: 'security-team',
      order: 5,
    },
  ],

  siem: [
    {
      id: 'query',
      name: 'query',
      label: 'Search Query',
      type: 'textarea',
      required: true,
      placeholder: 'index=security sourcetype=firewall action=blocked',
      order: 1,
    },
    {
      id: 'time_range',
      name: 'time_range',
      label: 'Time Range',
      type: 'select',
      required: false,
      defaultValue: '24h',
      order: 2,
      validation: {
        options: [
          { value: '1h', label: 'Last 1 hour' },
          { value: '24h', label: 'Last 24 hours' },
          { value: '7d', label: 'Last 7 days' },
          { value: '30d', label: 'Last 30 days' },
          { value: 'custom', label: 'Custom Range' },
        ],
      },
    },
    {
      id: 'max_results',
      name: 'max_results',
      label: 'Max Results',
      type: 'number',
      required: false,
      defaultValue: 100,
      order: 3,
      validation: { min: 1, max: 10000 },
    },
  ],

  identity: [
    {
      id: 'user_principal',
      name: 'user_principal',
      label: 'User Principal Name',
      type: 'email',
      required: true,
      placeholder: 'user@domain.com',
      order: 1,
    },
    {
      id: 'identity_action',
      name: 'identity_action',
      label: 'Action',
      type: 'select',
      required: true,
      order: 2,
      validation: {
        options: [
          { value: 'disable', label: 'Disable Account' },
          { value: 'enable', label: 'Enable Account' },
          { value: 'reset_password', label: 'Reset Password' },
          { value: 'revoke_sessions', label: 'Revoke Sessions' },
          { value: 'force_mfa', label: 'Force MFA Re-enrollment' },
        ],
      },
    },
    {
      id: 'notify_user',
      name: 'notify_user',
      label: 'Notify User',
      type: 'boolean',
      required: false,
      defaultValue: false,
      order: 3,
    },
  ],

  cloud: [
    {
      id: 'cloud_provider',
      name: 'cloud_provider',
      label: 'Cloud Provider',
      type: 'select',
      required: true,
      order: 1,
      validation: {
        options: [
          { value: 'aws', label: 'AWS' },
          { value: 'azure', label: 'Azure' },
          { value: 'gcp', label: 'Google Cloud' },
        ],
      },
    },
    {
      id: 'resource_id',
      name: 'resource_id',
      label: 'Resource ID',
      type: 'text',
      required: true,
      placeholder: 'arn:aws:ec2:...',
      order: 2,
    },
    {
      id: 'cloud_action',
      name: 'cloud_action',
      label: 'Action',
      type: 'select',
      required: true,
      order: 3,
      validation: {
        options: [
          { value: 'stop', label: 'Stop Instance' },
          { value: 'isolate', label: 'Isolate (Remove from VPC)' },
          { value: 'snapshot', label: 'Create Snapshot' },
          { value: 'terminate', label: 'Terminate' },
        ],
      },
    },
    {
      id: 'region',
      name: 'region',
      label: 'Region',
      type: 'text',
      required: false,
      placeholder: 'us-east-1',
      order: 4,
    },
  ],

  custom: [
    {
      id: 'custom_param_1',
      name: 'custom_param_1',
      label: 'Parameter 1',
      type: 'text',
      required: false,
      placeholder: 'Enter value...',
      order: 1,
    },
    {
      id: 'custom_param_2',
      name: 'custom_param_2',
      label: 'Parameter 2',
      type: 'text',
      required: false,
      placeholder: 'Enter value...',
      order: 2,
    },
    {
      id: 'custom_json',
      name: 'custom_json',
      label: 'Custom JSON',
      type: 'json',
      required: false,
      placeholder: '{"key": "value"}',
      order: 3,
    },
  ],
};

// Helper function to get merged schema for a playbook
export function getPlaybookInputSchema(
  triggerType: TriggerType,
  additionalFields?: PlaybookInputField[],
  integrationTypes?: IntegrationType[]
): PlaybookInputField[] {
  // Start with base trigger schema
  let fields = [...TRIGGER_INPUT_SCHEMAS[triggerType]];

  // Add integration-specific fields
  if (integrationTypes) {
    for (const intType of integrationTypes) {
      const intFields = INTEGRATION_INPUT_TEMPLATES[intType];
      if (intFields) {
        // Avoid duplicates by checking id
        const existingIds = new Set(fields.map(f => f.id));
        for (const field of intFields) {
          if (!existingIds.has(field.id)) {
            fields.push(field);
          }
        }
      }
    }
  }

  // Add custom additional fields
  if (additionalFields) {
    const existingIds = new Set(fields.map(f => f.id));
    for (const field of additionalFields) {
      if (!existingIds.has(field.id)) {
        fields.push(field);
      }
    }
  }

  // Sort by order
  fields.sort((a, b) => (a.order ?? 999) - (b.order ?? 999));

  return fields;
}

// Get default values for a schema
export function getDefaultInputValues(fields: PlaybookInputField[]): Record<string, unknown> {
  const values: Record<string, unknown> = {};
  for (const field of fields) {
    if (field.defaultValue !== undefined) {
      values[field.name] = field.defaultValue;
    } else {
      // Set appropriate default based on type
      switch (field.type) {
        case 'boolean':
          values[field.name] = false;
          break;
        case 'number':
          values[field.name] = '';
          break;
        case 'array':
        case 'multiselect':
          values[field.name] = [];
          break;
        case 'json':
          values[field.name] = '';
          break;
        default:
          values[field.name] = '';
      }
    }
  }
  return values;
}
