import { useState, useCallback, useMemo } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Switch } from '@/components/ui/switch';
import { Label } from '@/components/ui/label';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectLabel,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { X, Plus, Layers, Info } from 'lucide-react';
import { cn } from '@/lib/utils';
import type { AlertAggregation, UdmGroupByField } from '../types';
import {
  UDM_GROUP_BY_FIELDS,
  AGGREGATION_WINDOWS,
  AGGREGATION_ACTIONS,
} from '../types';

interface RuleAggregationEditorProps {
  value?: AlertAggregation;
  onChange: (value: AlertAggregation | undefined) => void;
  disabled?: boolean;
  className?: string;
}

// Group UDM fields by category
function groupFieldsByCategory(fields: UdmGroupByField[]): Record<string, UdmGroupByField[]> {
  const grouped: Record<string, UdmGroupByField[]> = {};
  fields.forEach((field) => {
    if (!grouped[field.category]) {
      grouped[field.category] = [];
    }
    grouped[field.category]!.push(field);
  });
  return grouped;
}

const DEFAULT_AGGREGATION: AlertAggregation = {
  group_by: [],
  window: '1h',
  action: 'merge',
  max_count: 100,
};

export function RuleAggregationEditor({
  value,
  onChange,
  disabled = false,
  className,
}: RuleAggregationEditorProps) {
  const [isEnabled, setIsEnabled] = useState(!!value);
  const [localValue, setLocalValue] = useState<AlertAggregation>(
    value || DEFAULT_AGGREGATION
  );

  // Group fields by category for select dropdown
  const groupedFields = useMemo(
    () => groupFieldsByCategory(UDM_GROUP_BY_FIELDS),
    []
  );

  // Get field label by value
  const getFieldLabel = useCallback((fieldValue: string) => {
    const field = UDM_GROUP_BY_FIELDS.find((f) => f.value === fieldValue);
    return field?.label || fieldValue;
  }, []);

  // Get field category by value
  const getFieldCategory = useCallback((fieldValue: string) => {
    const field = UDM_GROUP_BY_FIELDS.find((f) => f.value === fieldValue);
    return field?.category || 'Other';
  }, []);

  // Handle enable toggle
  const handleEnableChange = useCallback(
    (checked: boolean) => {
      setIsEnabled(checked);
      if (checked) {
        onChange(localValue);
      } else {
        onChange(undefined);
      }
    },
    [localValue, onChange]
  );

  // Handle field addition
  const handleAddField = useCallback(
    (fieldValue: string) => {
      if (localValue.group_by.includes(fieldValue)) return;
      const newValue = {
        ...localValue,
        group_by: [...localValue.group_by, fieldValue],
      };
      setLocalValue(newValue);
      if (isEnabled) {
        onChange(newValue);
      }
    },
    [localValue, isEnabled, onChange]
  );

  // Handle field removal
  const handleRemoveField = useCallback(
    (fieldValue: string) => {
      const newValue = {
        ...localValue,
        group_by: localValue.group_by.filter((f) => f !== fieldValue),
      };
      setLocalValue(newValue);
      if (isEnabled) {
        onChange(newValue);
      }
    },
    [localValue, isEnabled, onChange]
  );

  // Handle window change
  const handleWindowChange = useCallback(
    (window: string) => {
      const newValue = { ...localValue, window };
      setLocalValue(newValue);
      if (isEnabled) {
        onChange(newValue);
      }
    },
    [localValue, isEnabled, onChange]
  );

  // Handle action change
  const handleActionChange = useCallback(
    (action: AlertAggregation['action']) => {
      const newValue = { ...localValue, action };
      setLocalValue(newValue);
      if (isEnabled) {
        onChange(newValue);
      }
    },
    [localValue, isEnabled, onChange]
  );

  // Handle max_count change
  const handleMaxCountChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const max_count = Math.max(1, parseInt(e.target.value) || 1);
      const newValue = { ...localValue, max_count };
      setLocalValue(newValue);
      if (isEnabled) {
        onChange(newValue);
      }
    },
    [localValue, isEnabled, onChange]
  );

  // Generate preview text
  const previewText = useMemo(() => {
    if (!isEnabled || localValue.group_by.length === 0) {
      return null;
    }

    const fieldLabels = localValue.group_by.map(getFieldLabel).join(' + ');
    const windowLabel =
      AGGREGATION_WINDOWS.find((w) => w.value === localValue.window)?.label ||
      localValue.window;
    const actionInfo = AGGREGATION_ACTIONS.find(
      (a) => a.value === localValue.action
    );

    return {
      groupBy: fieldLabels,
      window: windowLabel,
      action: actionInfo?.label || localValue.action,
      actionDesc: actionInfo?.description || '',
      maxCount: localValue.max_count,
    };
  }, [isEnabled, localValue, getFieldLabel]);

  // Get category color for badges
  const getCategoryColor = (category: string) => {
    switch (category) {
      case 'Principal':
        return 'bg-blue-500/20 text-blue-400 border-blue-500/50';
      case 'Target':
        return 'bg-purple-500/20 text-purple-400 border-purple-500/50';
      case 'File':
        return 'bg-amber-500/20 text-amber-400 border-amber-500/50';
      case 'Network':
        return 'bg-green-500/20 text-green-400 border-green-500/50';
      case 'Process':
        return 'bg-red-500/20 text-red-400 border-red-500/50';
      default:
        return 'bg-gray-500/20 text-gray-400 border-gray-500/50';
    }
  };

  return (
    <Card className={cn('', className)}>
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Layers className="w-4 h-4 text-muted-foreground" />
            <CardTitle className="text-sm font-medium">
              Alert Aggregation
            </CardTitle>
          </div>
          <div className="flex items-center gap-2">
            <Label
              htmlFor="aggregation-enabled"
              className="text-xs text-muted-foreground"
            >
              {isEnabled ? 'Enabled' : 'Disabled'}
            </Label>
            <Switch
              id="aggregation-enabled"
              checked={isEnabled}
              onCheckedChange={handleEnableChange}
              disabled={disabled}
            />
          </div>
        </div>
      </CardHeader>

      <CardContent
        className={cn(
          'space-y-4 transition-opacity',
          !isEnabled && 'opacity-50 pointer-events-none'
        )}
      >
        {/* Group By Fields */}
        <div className="space-y-2">
          <Label className="text-xs font-medium">Group By Fields</Label>
          <div className="flex flex-wrap gap-2 min-h-[36px] p-2 bg-muted/30 rounded-md border border-border">
            {localValue.group_by.length === 0 ? (
              <span className="text-xs text-muted-foreground">
                No fields selected
              </span>
            ) : (
              localValue.group_by.map((field) => (
                <Badge
                  key={field}
                  variant="outline"
                  className={cn(
                    'text-xs gap-1',
                    getCategoryColor(getFieldCategory(field))
                  )}
                >
                  {getFieldLabel(field)}
                  <button
                    type="button"
                    onClick={() => handleRemoveField(field)}
                    className="ml-1 hover:bg-background/20 rounded-full p-0.5"
                    disabled={disabled}
                  >
                    <X className="w-3 h-3" />
                  </button>
                </Badge>
              ))
            )}
          </div>

          {/* Field selector dropdown */}
          <Select onValueChange={handleAddField} disabled={disabled}>
            <SelectTrigger className="h-8 text-xs">
              <div className="flex items-center gap-2">
                <Plus className="w-3 h-3" />
                <SelectValue placeholder="Add field..." />
              </div>
            </SelectTrigger>
            <SelectContent>
              {Object.entries(groupedFields).map(([category, fields]) => (
                <SelectGroup key={category}>
                  <SelectLabel className="text-xs font-semibold">
                    {category}
                  </SelectLabel>
                  {fields.map((field) => (
                    <SelectItem
                      key={field.value}
                      value={field.value}
                      disabled={localValue.group_by.includes(field.value)}
                      className="text-xs"
                    >
                      {field.label}
                    </SelectItem>
                  ))}
                </SelectGroup>
              ))}
            </SelectContent>
          </Select>
        </div>

        {/* Time Window and Action */}
        <div className="grid grid-cols-3 gap-3">
          {/* Time Window */}
          <div className="space-y-1.5">
            <Label className="text-xs font-medium">Time Window</Label>
            <Select
              value={localValue.window}
              onValueChange={handleWindowChange}
              disabled={disabled}
            >
              <SelectTrigger className="h-8 text-xs">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {AGGREGATION_WINDOWS.map((window) => (
                  <SelectItem
                    key={window.value}
                    value={window.value}
                    className="text-xs"
                  >
                    {window.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          {/* Action */}
          <div className="space-y-1.5">
            <Label className="text-xs font-medium">Action</Label>
            <Select
              value={localValue.action}
              onValueChange={(val) =>
                handleActionChange(val as AlertAggregation['action'])
              }
              disabled={disabled}
            >
              <SelectTrigger className="h-8 text-xs">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {AGGREGATION_ACTIONS.map((action) => (
                  <SelectItem
                    key={action.value}
                    value={action.value}
                    className="text-xs"
                  >
                    {action.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          {/* Max Count */}
          <div className="space-y-1.5">
            <Label className="text-xs font-medium">Max Alerts</Label>
            <Input
              type="number"
              min={1}
              value={localValue.max_count}
              onChange={handleMaxCountChange}
              className="h-8 text-xs"
              disabled={disabled}
            />
          </div>
        </div>

        {/* Preview */}
        {previewText && (
          <div className="p-3 bg-muted/30 rounded-lg border border-border space-y-2">
            <div className="flex items-center gap-1.5 text-xs font-medium text-muted-foreground">
              <Info className="w-3 h-3" />
              Preview
            </div>
            <div className="text-xs space-y-1">
              <p>
                <span className="text-muted-foreground">Alerts grouped by: </span>
                <span className="text-foreground font-medium">
                  Rule ID + {previewText.groupBy}
                </span>
              </p>
              <p>
                <span className="text-muted-foreground">Within: </span>
                <span className="text-foreground font-medium">
                  {previewText.window} window
                </span>
              </p>
              <p>
                <span className="text-muted-foreground">Action: </span>
                <span className="text-foreground font-medium">
                  {previewText.action}
                </span>
                <span className="text-muted-foreground">
                  {' '}
                  - {previewText.actionDesc}
                </span>
              </p>
              <p>
                <span className="text-muted-foreground">Threshold: </span>
                <span className="text-foreground font-medium">
                  {previewText.maxCount} alerts
                </span>
              </p>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
