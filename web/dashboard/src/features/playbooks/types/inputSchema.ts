/**
 * Dynamic Playbook Input Schema Types
 * Supports trigger-driven input fields with validation
 */

// Input field types optimized for security operations
export type InputFieldType =
  | 'text'        // Free text
  | 'number'      // Numeric input
  | 'boolean'     // Toggle/checkbox
  | 'select'      // Dropdown
  | 'multiselect' // Multi-select
  | 'ip'          // IP address with validation (v4/v6/CIDR)
  | 'email'       // Email with validation
  | 'domain'      // Domain name
  | 'url'         // URL with validation
  | 'hash'        // File hash (MD5/SHA1/SHA256)
  | 'json'        // JSON object editor
  | 'array'       // List of values
  | 'datetime'    // Date/time picker
  | 'duration'    // Time duration
  | 'credential'  // Masked/secure input
  | 'textarea';   // Multi-line text

export interface SelectOption {
  value: string;
  label: string;
}

export interface InputValidation {
  pattern?: string;           // Regex pattern
  patternMessage?: string;    // Error message for pattern failure
  minLength?: number;
  maxLength?: number;
  min?: number;               // For numbers
  max?: number;
  options?: SelectOption[];   // For select/multiselect
  allowCustom?: boolean;      // Allow values outside options
  ipVersion?: 'v4' | 'v6' | 'both';
  hashType?: 'md5' | 'sha1' | 'sha256' | 'any';
}

export interface ConditionalDisplay {
  field: string;              // Field ID to check
  operator: 'equals' | 'not_equals' | 'contains' | 'in' | 'not_empty';
  value?: unknown;            // Value to compare (not needed for not_empty)
}

export interface PlaybookInputField {
  id: string;
  name: string;               // Variable name for reference in playbook
  label: string;              // Display label
  type: InputFieldType;
  required: boolean;
  defaultValue?: unknown;
  description?: string;
  placeholder?: string;
  validation?: InputValidation;
  group?: string;             // Group related fields (e.g., "Network", "User")
  order?: number;             // Display order
  conditionalDisplay?: ConditionalDisplay;
  readOnly?: boolean;         // System-provided, cannot edit
}

// Trigger types (should match existing PlaybookTriggerType)
export type TriggerType = 'alert' | 'schedule' | 'webhook' | 'manual' | 'case';

// Integration types for templates
export type IntegrationType =
  | 'firewall'
  | 'edr'
  | 'email'
  | 'ticketing'
  | 'siem'
  | 'identity'
  | 'cloud'
  | 'custom';

// Input schema for a playbook
export interface PlaybookInputSchema {
  fields: PlaybookInputField[];
  groups?: {
    id: string;
    label: string;
    collapsible?: boolean;
    defaultCollapsed?: boolean;
  }[];
}

// Runtime input values
export type InputValues = Record<string, unknown>;

// Validation result
export interface ValidationResult {
  valid: boolean;
  errors: Record<string, string>;  // field id -> error message
}
