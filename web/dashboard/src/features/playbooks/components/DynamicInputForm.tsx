/**
 * DynamicInputForm - Renders playbook input fields based on schema
 */

import { useState, useMemo, useCallback } from 'react';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Switch } from '@/components/ui/switch';
import { Badge } from '@/components/ui/badge';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from '@/components/ui/collapsible';
import {
  ChevronDown,
  ChevronRight,
  AlertCircle,
  CheckCircle2,
  Lock,
  Info,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import type {
  PlaybookInputField,
  InputValues,
  ValidationResult,
} from '../types/inputSchema';

interface DynamicInputFormProps {
  fields: PlaybookInputField[];
  values: InputValues;
  onChange: (values: InputValues) => void;
  disabled?: boolean;
  showValidation?: boolean;
  compact?: boolean;
}

// Validation functions
function validateField(field: PlaybookInputField, value: unknown): string | null {
  // Check required
  if (field.required) {
    if (value === undefined || value === null || value === '') {
      return `${field.label} is required`;
    }
    if (Array.isArray(value) && value.length === 0) {
      return `${field.label} is required`;
    }
  }

  // Skip further validation if empty and not required
  if (value === undefined || value === null || value === '') {
    return null;
  }

  const validation = field.validation;
  if (!validation) return null;

  const strValue = String(value);

  // Pattern validation
  if (validation.pattern) {
    const regex = new RegExp(validation.pattern);
    if (!regex.test(strValue)) {
      return validation.patternMessage || `Invalid format for ${field.label}`;
    }
  }

  // Length validation
  if (validation.minLength !== undefined && strValue.length < validation.minLength) {
    return `${field.label} must be at least ${validation.minLength} characters`;
  }
  if (validation.maxLength !== undefined && strValue.length > validation.maxLength) {
    return `${field.label} must be at most ${validation.maxLength} characters`;
  }

  // Numeric validation
  if (field.type === 'number') {
    const numValue = Number(value);
    if (isNaN(numValue)) {
      return `${field.label} must be a number`;
    }
    if (validation.min !== undefined && numValue < validation.min) {
      return `${field.label} must be at least ${validation.min}`;
    }
    if (validation.max !== undefined && numValue > validation.max) {
      return `${field.label} must be at most ${validation.max}`;
    }
  }

  // IP validation
  if (field.type === 'ip') {
    const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/;
    const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}(\/\d{1,3})?$/;
    const ipVersion = validation.ipVersion || 'both';

    const isIPv4 = ipv4Regex.test(strValue);
    const isIPv6 = ipv6Regex.test(strValue);

    if (ipVersion === 'v4' && !isIPv4) {
      return 'Must be a valid IPv4 address';
    }
    if (ipVersion === 'v6' && !isIPv6) {
      return 'Must be a valid IPv6 address';
    }
    if (ipVersion === 'both' && !isIPv4 && !isIPv6) {
      return 'Must be a valid IP address';
    }
  }

  // Email validation
  if (field.type === 'email') {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(strValue)) {
      return 'Must be a valid email address';
    }
  }

  // Hash validation
  if (field.type === 'hash') {
    const hashType = validation.hashType || 'any';
    const md5Regex = /^[a-fA-F0-9]{32}$/;
    const sha1Regex = /^[a-fA-F0-9]{40}$/;
    const sha256Regex = /^[a-fA-F0-9]{64}$/;

    if (hashType === 'md5' && !md5Regex.test(strValue)) {
      return 'Must be a valid MD5 hash (32 hex characters)';
    }
    if (hashType === 'sha1' && !sha1Regex.test(strValue)) {
      return 'Must be a valid SHA1 hash (40 hex characters)';
    }
    if (hashType === 'sha256' && !sha256Regex.test(strValue)) {
      return 'Must be a valid SHA256 hash (64 hex characters)';
    }
    if (hashType === 'any' && !md5Regex.test(strValue) && !sha1Regex.test(strValue) && !sha256Regex.test(strValue)) {
      return 'Must be a valid hash (MD5, SHA1, or SHA256)';
    }
  }

  // JSON validation
  if (field.type === 'json') {
    try {
      JSON.parse(strValue);
    } catch {
      return 'Must be valid JSON';
    }
  }

  return null;
}

export function validateAllFields(
  fields: PlaybookInputField[],
  values: InputValues
): ValidationResult {
  const errors: Record<string, string> = {};
  let valid = true;

  for (const field of fields) {
    const error = validateField(field, values[field.name]);
    if (error) {
      errors[field.id] = error;
      valid = false;
    }
  }

  return { valid, errors };
}

// Field renderer components
function TextField({
  field,
  value,
  onChange,
  error,
  disabled,
}: {
  field: PlaybookInputField;
  value: string;
  onChange: (value: string) => void;
  error?: string;
  disabled?: boolean;
}) {
  return (
    <Input
      id={field.id}
      type={field.type === 'number' ? 'number' : 'text'}
      value={value}
      onChange={(e) => onChange(e.target.value)}
      placeholder={field.placeholder}
      disabled={disabled || field.readOnly}
      className={cn(
        'h-8 text-sm',
        error && 'border-red-500 focus-visible:ring-red-500',
        field.readOnly && 'bg-muted cursor-not-allowed'
      )}
    />
  );
}

function TextareaField({
  field,
  value,
  onChange,
  error,
  disabled,
}: {
  field: PlaybookInputField;
  value: string;
  onChange: (value: string) => void;
  error?: string;
  disabled?: boolean;
}) {
  return (
    <Textarea
      id={field.id}
      value={value}
      onChange={(e) => onChange(e.target.value)}
      placeholder={field.placeholder}
      disabled={disabled || field.readOnly}
      rows={3}
      className={cn(
        'text-sm resize-none',
        error && 'border-red-500 focus-visible:ring-red-500',
        field.readOnly && 'bg-muted cursor-not-allowed'
      )}
    />
  );
}

function SelectField({
  field,
  value,
  onChange,
  error,
  disabled,
}: {
  field: PlaybookInputField;
  value: string;
  onChange: (value: string) => void;
  error?: string;
  disabled?: boolean;
}) {
  const options = field.validation?.options || [];

  return (
    <Select
      value={value}
      onValueChange={onChange}
      disabled={disabled || field.readOnly}
    >
      <SelectTrigger
        className={cn(
          'h-8 text-sm',
          error && 'border-red-500 focus-visible:ring-red-500'
        )}
      >
        <SelectValue placeholder={field.placeholder || 'Select...'} />
      </SelectTrigger>
      <SelectContent>
        {options.map((option) => (
          <SelectItem key={option.value} value={option.value}>
            {option.label}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}

function BooleanField({
  field,
  value,
  onChange,
  disabled,
}: {
  field: PlaybookInputField;
  value: boolean;
  onChange: (value: boolean) => void;
  disabled?: boolean;
}) {
  return (
    <div className="flex items-center gap-2 h-8">
      <Switch
        id={field.id}
        checked={value}
        onCheckedChange={onChange}
        disabled={disabled || field.readOnly}
      />
      <span className="text-sm text-muted-foreground">
        {value ? 'Yes' : 'No'}
      </span>
    </div>
  );
}

function JsonField({
  field,
  value,
  onChange,
  error,
  disabled,
}: {
  field: PlaybookInputField;
  value: string;
  onChange: (value: string) => void;
  error?: string;
  disabled?: boolean;
}) {
  return (
    <Textarea
      id={field.id}
      value={value}
      onChange={(e) => onChange(e.target.value)}
      placeholder={field.placeholder || '{"key": "value"}'}
      disabled={disabled || field.readOnly}
      rows={4}
      className={cn(
        'text-sm font-mono resize-none',
        error && 'border-red-500 focus-visible:ring-red-500',
        field.readOnly && 'bg-muted cursor-not-allowed'
      )}
    />
  );
}

// Single field wrapper
function FieldWrapper({
  field,
  value,
  onChange,
  error,
  disabled,
  compact,
}: {
  field: PlaybookInputField;
  value: unknown;
  onChange: (value: unknown) => void;
  error?: string;
  disabled?: boolean;
  compact?: boolean;
}) {
  const renderField = () => {
    switch (field.type) {
      case 'select':
        return (
          <SelectField
            field={field}
            value={String(value || '')}
            onChange={onChange}
            error={error}
            disabled={disabled}
          />
        );
      case 'boolean':
        return (
          <BooleanField
            field={field}
            value={Boolean(value)}
            onChange={onChange}
            disabled={disabled}
          />
        );
      case 'textarea':
        return (
          <TextareaField
            field={field}
            value={String(value || '')}
            onChange={onChange}
            error={error}
            disabled={disabled}
          />
        );
      case 'json':
        return (
          <JsonField
            field={field}
            value={String(value || '')}
            onChange={onChange}
            error={error}
            disabled={disabled}
          />
        );
      default:
        return (
          <TextField
            field={field}
            value={String(value || '')}
            onChange={onChange}
            error={error}
            disabled={disabled}
          />
        );
    }
  };

  return (
    <div className={cn('space-y-1.5', compact && 'space-y-1')}>
      <div className="flex items-center gap-1.5">
        <Label
          htmlFor={field.id}
          className={cn(
            'text-xs font-medium',
            field.required && 'after:content-["*"] after:text-red-500 after:ml-0.5'
          )}
        >
          {field.label}
        </Label>
        {field.readOnly && (
          <Lock className="w-3 h-3 text-muted-foreground" />
        )}
        {field.description && !compact && (
          <span className="text-muted-foreground cursor-help" title={field.description}>
            <Info className="w-3 h-3" />
          </span>
        )}
      </div>
      {renderField()}
      {error && (
        <div className="flex items-center gap-1 text-xs text-red-500">
          <AlertCircle className="w-3 h-3" />
          {error}
        </div>
      )}
    </div>
  );
}

// Group component
function FieldGroup({
  groupId,
  groupLabel,
  fields,
  values,
  onChange,
  errors,
  disabled,
  compact,
  defaultCollapsed,
}: {
  groupId: string;
  groupLabel: string;
  fields: PlaybookInputField[];
  values: InputValues;
  onChange: (name: string, value: unknown) => void;
  errors: Record<string, string>;
  disabled?: boolean;
  compact?: boolean;
  defaultCollapsed?: boolean;
}) {
  const [isOpen, setIsOpen] = useState(!defaultCollapsed);
  const hasErrors = fields.some((f) => errors[f.id]);

  return (
    <Collapsible open={isOpen} onOpenChange={setIsOpen}>
      <CollapsibleTrigger className="flex items-center gap-2 w-full py-1.5 text-sm font-medium hover:text-foreground transition-colors">
        {isOpen ? (
          <ChevronDown className="w-4 h-4" />
        ) : (
          <ChevronRight className="w-4 h-4" />
        )}
        <span>{groupLabel}</span>
        <Badge variant="secondary" className="text-xs px-1.5 py-0">
          {fields.length}
        </Badge>
        {hasErrors && (
          <AlertCircle className="w-3.5 h-3.5 text-red-500" />
        )}
      </CollapsibleTrigger>
      <CollapsibleContent>
        <div className={cn(
          'grid gap-3 pl-6 pt-2',
          compact ? 'grid-cols-1' : 'grid-cols-2'
        )}>
          {fields.map((field) => (
            <FieldWrapper
              key={field.id}
              field={field}
              value={values[field.name]}
              onChange={(value) => onChange(field.name, value)}
              error={errors[field.id]}
              disabled={disabled}
              compact={compact}
            />
          ))}
        </div>
      </CollapsibleContent>
    </Collapsible>
  );
}

// Main component
export function DynamicInputForm({
  fields,
  values,
  onChange,
  disabled,
  showValidation = true,
  compact = false,
}: DynamicInputFormProps) {
  const [touched, setTouched] = useState<Set<string>>(new Set());

  // Group fields
  const { ungroupedFields, groupedFields } = useMemo(() => {
    const ungrouped: PlaybookInputField[] = [];
    const grouped: Map<string, PlaybookInputField[]> = new Map();

    for (const field of fields) {
      if (field.group) {
        if (!grouped.has(field.group)) {
          grouped.set(field.group, []);
        }
        grouped.get(field.group)!.push(field);
      } else {
        ungrouped.push(field);
      }
    }

    return {
      ungroupedFields: ungrouped,
      groupedFields: Array.from(grouped.entries()),
    };
  }, [fields]);

  // Validation
  const validationResult = useMemo(() => {
    if (!showValidation) return { valid: true, errors: {} };
    return validateAllFields(fields, values);
  }, [fields, values, showValidation]);

  // Only show errors for touched fields
  const visibleErrors = useMemo(() => {
    const errors: Record<string, string> = {};
    for (const [fieldId, error] of Object.entries(validationResult.errors)) {
      if (touched.has(fieldId)) {
        errors[fieldId] = error;
      }
    }
    return errors;
  }, [validationResult.errors, touched]);

  const handleFieldChange = useCallback(
    (name: string, value: unknown) => {
      const field = fields.find((f) => f.name === name);
      if (field) {
        setTouched((prev) => new Set(prev).add(field.id));
      }
      onChange({ ...values, [name]: value });
    },
    [fields, values, onChange]
  );

  return (
    <div className="space-y-4">
      {/* Ungrouped fields */}
      {ungroupedFields.length > 0 && (
        <div className={cn(
          'grid gap-3',
          compact ? 'grid-cols-1' : 'grid-cols-2'
        )}>
          {ungroupedFields.map((field) => (
            <FieldWrapper
              key={field.id}
              field={field}
              value={values[field.name]}
              onChange={(value) => handleFieldChange(field.name, value)}
              error={visibleErrors[field.id]}
              disabled={disabled}
              compact={compact}
            />
          ))}
        </div>
      )}

      {/* Grouped fields */}
      {groupedFields.map(([groupId, groupFields]) => (
        <FieldGroup
          key={groupId}
          groupId={groupId}
          groupLabel={groupId}
          fields={groupFields}
          values={values}
          onChange={handleFieldChange}
          errors={visibleErrors}
          disabled={disabled}
          compact={compact}
          defaultCollapsed={false}
        />
      ))}

      {/* Validation summary */}
      {showValidation && touched.size > 0 && (
        <div className={cn(
          'flex items-center gap-2 text-xs px-2 py-1.5 rounded',
          validationResult.valid
            ? 'bg-green-500/10 text-green-600'
            : 'bg-red-500/10 text-red-600'
        )}>
          {validationResult.valid ? (
            <>
              <CheckCircle2 className="w-3.5 h-3.5" />
              All fields valid
            </>
          ) : (
            <>
              <AlertCircle className="w-3.5 h-3.5" />
              {Object.keys(validationResult.errors).length} validation error(s)
            </>
          )}
        </div>
      )}
    </div>
  );
}

export default DynamicInputForm;
