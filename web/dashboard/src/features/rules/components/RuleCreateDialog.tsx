import React from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import * as z from 'zod';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Separator } from '@/components/ui/separator';
import { X } from 'lucide-react';
import type { SigmaRule, AttackTactic, AttackTechnique } from '../types';
import { ATTACK_TACTICS } from '../types';

// Common techniques for selection
const COMMON_TECHNIQUES: AttackTechnique[] = [
  { id: 'T1566', name: 'Phishing', subtechnique: '001' },
  { id: 'T1059', name: 'Command and Scripting Interpreter', subtechnique: '001' },
  { id: 'T1003', name: 'OS Credential Dumping', subtechnique: '001' },
  { id: 'T1486', name: 'Data Encrypted for Impact' },
  { id: 'T1110', name: 'Brute Force' },
  { id: 'T1053', name: 'Scheduled Task/Job', subtechnique: '005' },
  { id: 'T1548', name: 'Abuse Elevation Control Mechanism', subtechnique: '002' },
  { id: 'T1562', name: 'Impair Defenses', subtechnique: '001' },
  { id: 'T1135', name: 'Network Share Discovery' },
  { id: 'T1021', name: 'Remote Services', subtechnique: '002' },
  { id: 'T1560', name: 'Archive Collected Data', subtechnique: '001' },
  { id: 'T1567', name: 'Exfiltration Over Web Service', subtechnique: '002' },
  { id: 'T1047', name: 'Windows Management Instrumentation' },
  { id: 'T1489', name: 'Service Stop' },
];

const ruleFormSchema = z.object({
  title: z.string().min(1, 'Title is required').max(200, 'Title too long'),
  description: z.string().min(1, 'Description is required').max(1000, 'Description too long'),
  severity: z.enum(['critical', 'high', 'medium', 'low', 'informational']),
  status: z.enum(['draft', 'testing', 'active', 'disabled']),
  logsourceProduct: z.string().optional(),
  logsourceCategory: z.string().optional(),
  logsourceService: z.string().optional(),
  detection: z.string().min(1, 'Detection logic is required'),
  author: z.string().default('SOC Team'),
  tags: z.string().optional(),
  references: z.string().optional(),
});

type RuleFormValues = z.infer<typeof ruleFormSchema>;

interface RuleCreateDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onCreate: (rule: Partial<SigmaRule>) => void;
}

export function RuleCreateDialog({
  open,
  onOpenChange,
  onCreate,
}: RuleCreateDialogProps) {
  const {
    register,
    handleSubmit,
    formState: { errors },
    reset,
    setValue,
    watch,
  } = useForm<RuleFormValues>({
    resolver: zodResolver(ruleFormSchema),
    defaultValues: {
      title: '',
      description: '',
      severity: 'medium',
      status: 'draft',
      detection: '',
      author: 'SOC Team',
      tags: '',
      references: '',
    },
  });

  const [selectedTactics, setSelectedTactics] = React.useState<AttackTactic[]>([]);
  const [selectedTechniques, setSelectedTechniques] = React.useState<AttackTechnique[]>([]);

  const onSubmit = (data: RuleFormValues) => {
    // Build the Sigma YAML
    const yamlParts = [
      `title: ${data.title}`,
      `description: ${data.description}`,
      `status: ${data.status}`,
      `author: ${data.author}`,
    ];

    // Add logsource
    const logsourceParts: string[] = [];
    if (data.logsourceProduct) logsourceParts.push(`    product: ${data.logsourceProduct}`);
    if (data.logsourceCategory) logsourceParts.push(`    category: ${data.logsourceCategory}`);
    if (data.logsourceService) logsourceParts.push(`    service: ${data.logsourceService}`);

    if (logsourceParts.length > 0) {
      yamlParts.push('logsource:');
      yamlParts.push(...logsourceParts);
    }

    // Add detection
    yamlParts.push('detection:');
    yamlParts.push(data.detection.split('\n').map(line => `    ${line}`).join('\n'));

    // Add severity
    yamlParts.push(`level: ${data.severity}`);

    const rawYaml = yamlParts.join('\n');

    // Create the rule object
    const newRule: Partial<SigmaRule> = {
      title: data.title,
      description: data.description,
      severity: data.severity,
      status: data.status,
      author: data.author,
      logsources: {
        product: data.logsourceProduct,
        category: data.logsourceCategory,
        service: data.logsourceService,
      },
      rawYaml,
      attack: {
        tactics: selectedTactics,
        techniques: selectedTechniques,
      },
      tags: data.tags ? data.tags.split(',').map(t => t.trim()).filter(Boolean) : [],
      references: data.references ? data.references.split('\n').filter(Boolean) : [],
      enabled: false,
      triggerCount: 0,
    };

    onCreate(newRule);
    reset();
    setSelectedTactics([]);
    setSelectedTechniques([]);
    onOpenChange(false);
  };

  const handleAddTactic = (tacticId: string) => {
    const tactic = ATTACK_TACTICS.find(t => t.id === tacticId);
    if (tactic && !selectedTactics.find(t => t.id === tacticId)) {
      setSelectedTactics([...selectedTactics, tactic]);
    }
  };

  const handleRemoveTactic = (tacticId: string) => {
    setSelectedTactics(selectedTactics.filter(t => t.id !== tacticId));
  };

  const handleAddTechnique = (techniqueId: string) => {
    const technique = COMMON_TECHNIQUES.find(t =>
      t.subtechnique
        ? `${t.id}.${t.subtechnique}` === techniqueId
        : t.id === techniqueId
    );
    if (technique && !selectedTechniques.find(t =>
      (t.subtechnique ? `${t.id}.${t.subtechnique}` : t.id) === techniqueId
    )) {
      setSelectedTechniques([...selectedTechniques, technique]);
    }
  };

  const handleRemoveTechnique = (techniqueId: string) => {
    setSelectedTechniques(selectedTechniques.filter(t =>
      (t.subtechnique ? `${t.id}.${t.subtechnique}` : t.id) !== techniqueId
    ));
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-3xl max-h-[90vh]">
        <DialogHeader>
          <DialogTitle>Create New Detection Rule</DialogTitle>
          <DialogDescription>
            Create a new Sigma detection rule with MITRE ATT&CK mappings
          </DialogDescription>
        </DialogHeader>

        <ScrollArea className="max-h-[calc(90vh-200px)] pr-4">
          <form onSubmit={handleSubmit(onSubmit)} className="space-y-6">
            {/* Basic Information */}
            <div className="space-y-4">
              <h3 className="text-sm font-semibold">Basic Information</h3>

              <div className="space-y-2">
                <Label htmlFor="title">
                  Title <span className="text-destructive">*</span>
                </Label>
                <Input
                  id="title"
                  {...register('title')}
                  placeholder="e.g., Suspicious PowerShell Execution"
                />
                {errors.title && (
                  <p className="text-sm text-destructive">{errors.title.message}</p>
                )}
              </div>

              <div className="space-y-2">
                <Label htmlFor="description">
                  Description <span className="text-destructive">*</span>
                </Label>
                <Textarea
                  id="description"
                  {...register('description')}
                  placeholder="Describe what this rule detects..."
                  rows={3}
                />
                {errors.description && (
                  <p className="text-sm text-destructive">{errors.description.message}</p>
                )}
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="severity">
                    Severity <span className="text-destructive">*</span>
                  </Label>
                  <Select
                    defaultValue="medium"
                    onValueChange={(value) => setValue('severity', value as any)}
                  >
                    <SelectTrigger id="severity">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="critical">Critical</SelectItem>
                      <SelectItem value="high">High</SelectItem>
                      <SelectItem value="medium">Medium</SelectItem>
                      <SelectItem value="low">Low</SelectItem>
                      <SelectItem value="informational">Informational</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <div className="space-y-2">
                  <Label htmlFor="status">
                    Status <span className="text-destructive">*</span>
                  </Label>
                  <Select
                    defaultValue="draft"
                    onValueChange={(value) => setValue('status', value as any)}
                  >
                    <SelectTrigger id="status">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="draft">Draft</SelectItem>
                      <SelectItem value="testing">Testing</SelectItem>
                      <SelectItem value="active">Active</SelectItem>
                      <SelectItem value="disabled">Disabled</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>

              <div className="space-y-2">
                <Label htmlFor="author">Author</Label>
                <Input
                  id="author"
                  {...register('author')}
                  placeholder="SOC Team"
                />
              </div>
            </div>

            <Separator />

            {/* Log Source */}
            <div className="space-y-4">
              <h3 className="text-sm font-semibold">Log Source</h3>

              <div className="grid grid-cols-3 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="logsourceProduct">Product</Label>
                  <Input
                    id="logsourceProduct"
                    {...register('logsourceProduct')}
                    placeholder="e.g., windows"
                  />
                </div>

                <div className="space-y-2">
                  <Label htmlFor="logsourceCategory">Category</Label>
                  <Input
                    id="logsourceCategory"
                    {...register('logsourceCategory')}
                    placeholder="e.g., process_creation"
                  />
                </div>

                <div className="space-y-2">
                  <Label htmlFor="logsourceService">Service</Label>
                  <Input
                    id="logsourceService"
                    {...register('logsourceService')}
                    placeholder="e.g., security"
                  />
                </div>
              </div>
            </div>

            <Separator />

            {/* Detection Logic */}
            <div className="space-y-4">
              <h3 className="text-sm font-semibold">Detection Logic</h3>

              <div className="space-y-2">
                <Label htmlFor="detection">
                  Detection (YAML) <span className="text-destructive">*</span>
                </Label>
                <Textarea
                  id="detection"
                  {...register('detection')}
                  placeholder={`selection:\n    Image|endswith: '\\powershell.exe'\n    CommandLine|contains: '-enc'\ncondition: selection`}
                  rows={8}
                  className="font-mono text-sm"
                />
                {errors.detection && (
                  <p className="text-sm text-destructive">{errors.detection.message}</p>
                )}
              </div>
            </div>

            <Separator />

            {/* MITRE ATT&CK Mappings */}
            <div className="space-y-4">
              <h3 className="text-sm font-semibold">MITRE ATT&CK Mappings</h3>

              <div className="space-y-2">
                <Label>Tactics</Label>
                <Select onValueChange={handleAddTactic}>
                  <SelectTrigger>
                    <SelectValue placeholder="Select tactics..." />
                  </SelectTrigger>
                  <SelectContent>
                    {ATTACK_TACTICS.map((tactic) => (
                      <SelectItem key={tactic.id} value={tactic.id}>
                        {tactic.name} ({tactic.id})
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                {selectedTactics.length > 0 && (
                  <div className="flex flex-wrap gap-2 mt-2">
                    {selectedTactics.map((tactic) => (
                      <Badge
                        key={tactic.id}
                        variant="secondary"
                        className="gap-1"
                      >
                        {tactic.name}
                        <button
                          type="button"
                          onClick={() => handleRemoveTactic(tactic.id)}
                          className="ml-1 hover:text-destructive"
                        >
                          <X className="w-3 h-3" />
                        </button>
                      </Badge>
                    ))}
                  </div>
                )}
              </div>

              <div className="space-y-2">
                <Label>Techniques</Label>
                <Select onValueChange={handleAddTechnique}>
                  <SelectTrigger>
                    <SelectValue placeholder="Select techniques..." />
                  </SelectTrigger>
                  <SelectContent>
                    {COMMON_TECHNIQUES.map((technique) => {
                      const key = technique.subtechnique
                        ? `${technique.id}.${technique.subtechnique}`
                        : technique.id;
                      return (
                        <SelectItem key={key} value={key}>
                          {technique.name} ({key})
                        </SelectItem>
                      );
                    })}
                  </SelectContent>
                </Select>
                {selectedTechniques.length > 0 && (
                  <div className="flex flex-wrap gap-2 mt-2">
                    {selectedTechniques.map((technique) => {
                      const key = technique.subtechnique
                        ? `${technique.id}.${technique.subtechnique}`
                        : technique.id;
                      return (
                        <Badge
                          key={key}
                          variant="secondary"
                          className="gap-1"
                        >
                          {technique.name} ({key})
                          <button
                            type="button"
                            onClick={() => handleRemoveTechnique(key)}
                            className="ml-1 hover:text-destructive"
                          >
                            <X className="w-3 h-3" />
                          </button>
                        </Badge>
                      );
                    })}
                  </div>
                )}
              </div>
            </div>

            <Separator />

            {/* Additional Metadata */}
            <div className="space-y-4">
              <h3 className="text-sm font-semibold">Additional Metadata</h3>

              <div className="space-y-2">
                <Label htmlFor="tags">Tags (comma-separated)</Label>
                <Input
                  id="tags"
                  {...register('tags')}
                  placeholder="e.g., malware, ransomware, endpoint"
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="references">References (one per line)</Label>
                <Textarea
                  id="references"
                  {...register('references')}
                  placeholder="https://example.com/reference1&#10;https://example.com/reference2"
                  rows={3}
                />
              </div>
            </div>
          </form>
        </ScrollArea>

        <DialogFooter>
          <Button
            type="button"
            variant="outline"
            onClick={() => onOpenChange(false)}
          >
            Cancel
          </Button>
          <Button type="submit" onClick={handleSubmit(onSubmit)}>
            Create Rule
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
