import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import type { ParserFormat } from '../types';

interface FormatSelectorProps {
  value: ParserFormat;
  onChange: (value: ParserFormat) => void;
  disabled?: boolean;
}

const formatInfo: Record<ParserFormat, { label: string; description: string; color: string }> = {
  grok: {
    label: 'Grok',
    description: 'Logstash-style patterns with named captures. Best for structured text logs like syslog, Apache, Nginx.',
    color: 'bg-purple-500/20 text-purple-400 border-purple-500/30',
  },
  json: {
    label: 'JSON',
    description: 'Parse JSON-formatted logs. Supports nested objects and arrays with JSONPath field mappings.',
    color: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
  },
  cef: {
    label: 'CEF',
    description: 'Common Event Format by ArcSight. Standard format for security devices like firewalls and IDS.',
    color: 'bg-green-500/20 text-green-400 border-green-500/30',
  },
  leef: {
    label: 'LEEF',
    description: 'Log Event Extended Format by IBM QRadar. Similar to CEF with tab-separated key-value pairs.',
    color: 'bg-cyan-500/20 text-cyan-400 border-cyan-500/30',
  },
  regex: {
    label: 'Regex',
    description: 'Custom regular expressions with named capture groups. Maximum flexibility for non-standard formats.',
    color: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  },
  kv: {
    label: 'Key-Value',
    description: 'Parse key=value pairs from logs. Supports custom delimiters and quoted values.',
    color: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  },
};

export function FormatSelector({ value, onChange, disabled }: FormatSelectorProps) {
  const currentFormat = formatInfo[value];

  return (
    <div className="space-y-2">
      <Select value={value} onValueChange={(v) => onChange(v as ParserFormat)} disabled={disabled}>
        <SelectTrigger className="w-full bg-background/50">
          <SelectValue placeholder="Select format">
            <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${currentFormat.color}`}>
              {currentFormat.label}
            </span>
          </SelectValue>
        </SelectTrigger>
        <SelectContent>
          {Object.entries(formatInfo).map(([key, info]) => (
            <SelectItem key={key} value={key}>
              <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${info.color}`}>
                {info.label}
              </span>
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      <p className="text-xs text-muted-foreground">
        {currentFormat.description}
      </p>
    </div>
  );
}

export function FormatBadge({ format }: { format: ParserFormat }) {
  const info = formatInfo[format];
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${info.color}`}>
      {info.label}
    </span>
  );
}
