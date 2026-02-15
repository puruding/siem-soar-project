import { useState, useCallback } from 'react';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
  DialogDescription,
} from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { Progress } from '@/components/ui/progress';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Upload, FileSpreadsheet, Check, X, AlertCircle } from 'lucide-react';
import { cn } from '@/lib/utils';
import type { Asset, ImportPreview, ImportField } from '../types';

interface AssetImportProps {
  open: boolean;
  onClose: () => void;
  onImport: (assets: Partial<Asset>[]) => void;
}

type ImportStep = 'upload' | 'mapping' | 'preview' | 'importing' | 'complete';

const assetFields: { key: keyof Asset; label: string; required?: boolean }[] = [
  { key: 'name', label: 'Name', required: true },
  { key: 'hostname', label: 'Hostname', required: true },
  { key: 'ipAddresses', label: 'IP Addresses' },
  { key: 'macAddresses', label: 'MAC Addresses' },
  { key: 'type', label: 'Type' },
  { key: 'osType', label: 'OS Type' },
  { key: 'osVersion', label: 'OS Version' },
  { key: 'owner', label: 'Owner' },
  { key: 'department', label: 'Department' },
  { key: 'location', label: 'Location' },
  { key: 'tags', label: 'Tags' },
  { key: 'criticality', label: 'Criticality' },
  { key: 'status', label: 'Status' },
];

// Parse CSV content
function parseCSV(content: string): { headers: string[]; rows: string[][] } {
  const lines = content.split('\n').filter((line) => line.trim());
  if (lines.length === 0) return { headers: [], rows: [] };

  const firstLine = lines[0];
  if (!firstLine) return { headers: [], rows: [] };
  const headers = firstLine.split(',').map((h) => h.trim().replace(/^"|"$/g, ''));
  const rows = lines.slice(1).map((line) => {
    const values: string[] = [];
    let current = '';
    let inQuotes = false;

    for (const char of line) {
      if (char === '"') {
        inQuotes = !inQuotes;
      } else if (char === ',' && !inQuotes) {
        values.push(current.trim());
        current = '';
      } else {
        current += char;
      }
    }
    values.push(current.trim());
    return values;
  });

  return { headers, rows };
}

export function AssetImport({ open, onClose, onImport }: AssetImportProps) {
  const [step, setStep] = useState<ImportStep>('upload');
  const [file, setFile] = useState<File | null>(null);
  const [preview, setPreview] = useState<ImportPreview | null>(null);
  const [mapping, setMapping] = useState<Record<string, keyof Asset | ''>>({});
  const [progress, setProgress] = useState(0);
  const [importResult, setImportResult] = useState<{
    success: number;
    failed: number;
  } | null>(null);
  const [isDragging, setIsDragging] = useState(false);

  const handleFileSelect = useCallback(async (selectedFile: File) => {
    setFile(selectedFile);

    const content = await selectedFile.text();
    const { headers, rows } = parseCSV(content);

    // Auto-map headers to fields
    const autoMapping: Record<string, keyof Asset | ''> = {};
    headers.forEach((header) => {
      const normalizedHeader = header.toLowerCase().replace(/[^a-z]/g, '');
      const matchingField = assetFields.find((f) => {
        const normalizedField = f.key.toLowerCase();
        return (
          normalizedHeader === normalizedField ||
          normalizedHeader.includes(normalizedField) ||
          normalizedField.includes(normalizedHeader)
        );
      });
      autoMapping[header] = matchingField?.key || '';
    });

    setMapping(autoMapping);
    setPreview({
      headers,
      rows: rows.slice(0, 100), // Limit preview rows
      totalRows: rows.length,
      mapping: headers.map((h) => ({
        sourceColumn: h,
        targetField: autoMapping[h] || '',
        preview: rows.slice(0, 3).map((r) => r[headers.indexOf(h)] || ''),
      })),
    });
    setStep('mapping');
  }, []);

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setIsDragging(false);
      const droppedFile = e.dataTransfer.files[0];
      if (droppedFile && (droppedFile.name.endsWith('.csv') || droppedFile.name.endsWith('.xlsx'))) {
        handleFileSelect(droppedFile);
      }
    },
    [handleFileSelect]
  );

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = () => {
    setIsDragging(false);
  };

  const handleMappingChange = (sourceColumn: string, targetField: keyof Asset | '') => {
    setMapping((prev) => ({ ...prev, [sourceColumn]: targetField }));
    if (preview) {
      setPreview({
        ...preview,
        mapping: preview.mapping.map((m) =>
          m.sourceColumn === sourceColumn ? { ...m, targetField } : m
        ),
      });
    }
  };

  const handleStartImport = async () => {
    if (!preview) return;

    setStep('importing');
    setProgress(0);

    // Simulate import process
    const assets: Partial<Asset>[] = [];
    let failed = 0;

    for (let i = 0; i < preview.rows.length; i++) {
      const row = preview.rows[i];
      const asset: Partial<Asset> = {};

      if (row) {
        preview.headers.forEach((header, idx) => {
          const targetField = mapping[header];
          const cellValue = row[idx];
          if (targetField && cellValue) {
            if (targetField === 'ipAddresses' || targetField === 'macAddresses' || targetField === 'tags') {
              (asset as Record<string, unknown>)[targetField] = cellValue.split(';').map((v) => v.trim());
            } else {
              (asset as Record<string, unknown>)[targetField] = cellValue;
            }
          }
        });
      }

      // Validate required fields
      if (asset.name && asset.hostname) {
        assets.push(asset);
      } else {
        failed++;
      }

      // Update progress
      setProgress(Math.round(((i + 1) / preview.rows.length) * 100));
      await new Promise((r) => setTimeout(r, 10)); // Simulate delay
    }

    setImportResult({ success: assets.length, failed });
    onImport(assets);
    setStep('complete');
  };

  const handleClose = () => {
    setStep('upload');
    setFile(null);
    setPreview(null);
    setMapping({});
    setProgress(0);
    setImportResult(null);
    onClose();
  };

  const requiredFieldsMapped = assetFields
    .filter((f) => f.required)
    .every((f) => Object.values(mapping).includes(f.key));

  return (
    <Dialog open={open} onOpenChange={(isOpen) => !isOpen && handleClose()}>
      <DialogContent className="max-w-4xl max-h-[90vh] overflow-hidden flex flex-col">
        <DialogHeader>
          <DialogTitle>
            {step === 'upload' && 'Import Assets'}
            {step === 'mapping' && 'Map Fields'}
            {step === 'preview' && 'Preview Import'}
            {step === 'importing' && 'Importing...'}
            {step === 'complete' && 'Import Complete'}
          </DialogTitle>
          <DialogDescription>
            {step === 'upload' && 'Upload a CSV or Excel file containing asset data.'}
            {step === 'mapping' && 'Map the columns from your file to asset fields.'}
            {step === 'preview' && 'Review the data before importing.'}
            {step === 'importing' && 'Please wait while assets are being imported.'}
            {step === 'complete' && 'Import process has finished.'}
          </DialogDescription>
        </DialogHeader>

        <div className="flex-1 overflow-hidden">
          {/* Upload Step */}
          {step === 'upload' && (
            <div
              className={cn(
                'h-64 border-2 border-dashed rounded-lg flex flex-col items-center justify-center gap-4 transition-colors',
                isDragging ? 'border-primary bg-primary/5' : 'border-border'
              )}
              onDrop={handleDrop}
              onDragOver={handleDragOver}
              onDragLeave={handleDragLeave}
            >
              <div className="p-4 rounded-full bg-muted">
                <Upload className="w-8 h-8 text-muted-foreground" />
              </div>
              <div className="text-center">
                <p className="text-sm font-medium">
                  Drop your file here or{' '}
                  <label className="text-primary cursor-pointer hover:underline">
                    browse
                    <input
                      type="file"
                      accept=".csv,.xlsx"
                      className="hidden"
                      onChange={(e) => {
                        const f = e.target.files?.[0];
                        if (f) handleFileSelect(f);
                      }}
                    />
                  </label>
                </p>
                <p className="text-xs text-muted-foreground mt-1">
                  Supports CSV and Excel files
                </p>
              </div>
            </div>
          )}

          {/* Mapping Step */}
          {step === 'mapping' && preview && (
            <ScrollArea className="h-[400px]">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-[200px]">Source Column</TableHead>
                    <TableHead className="w-[200px]">Map To Field</TableHead>
                    <TableHead>Preview</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {preview.mapping.map((field) => (
                    <TableRow key={field.sourceColumn}>
                      <TableCell className="font-medium">
                        <div className="flex items-center gap-2">
                          <FileSpreadsheet className="w-4 h-4 text-muted-foreground" />
                          {field.sourceColumn}
                        </div>
                      </TableCell>
                      <TableCell>
                        <Select
                          value={field.targetField || 'skip'}
                          onValueChange={(value) =>
                            handleMappingChange(
                              field.sourceColumn,
                              value === 'skip' ? '' : (value as keyof Asset)
                            )
                          }
                        >
                          <SelectTrigger className="w-[180px]">
                            <SelectValue placeholder="Select field" />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="skip">Skip this column</SelectItem>
                            {assetFields.map((f) => (
                              <SelectItem key={f.key} value={f.key}>
                                {f.label}
                                {f.required && ' *'}
                              </SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                      </TableCell>
                      <TableCell>
                        <div className="flex flex-wrap gap-1">
                          {field.preview.slice(0, 3).map((val, idx) => (
                            <span
                              key={idx}
                              className="text-xs px-2 py-0.5 bg-muted rounded truncate max-w-[150px]"
                              title={val}
                            >
                              {val || '(empty)'}
                            </span>
                          ))}
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </ScrollArea>
          )}

          {/* Preview Step */}
          {step === 'preview' && preview && (
            <ScrollArea className="h-[400px]">
              <Table>
                <TableHeader>
                  <TableRow>
                    {preview.headers
                      .filter((h) => mapping[h])
                      .map((header) => (
                        <TableHead key={header}>
                          {assetFields.find((f) => f.key === mapping[header])?.label || header}
                        </TableHead>
                      ))}
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {preview.rows.slice(0, 10).map((row, rowIdx) => (
                    <TableRow key={rowIdx}>
                      {preview.headers
                        .filter((h) => mapping[h])
                        .map((header, colIdx) => (
                          <TableCell key={colIdx} className="text-sm">
                            {row[preview.headers.indexOf(header)] || '-'}
                          </TableCell>
                        ))}
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
              {preview.totalRows > 10 && (
                <p className="text-center text-sm text-muted-foreground py-4">
                  Showing 10 of {preview.totalRows} rows
                </p>
              )}
            </ScrollArea>
          )}

          {/* Importing Step */}
          {step === 'importing' && (
            <div className="h-64 flex flex-col items-center justify-center gap-6">
              <Progress value={progress} className="w-64" />
              <p className="text-sm text-muted-foreground">
                Importing assets... {progress}%
              </p>
            </div>
          )}

          {/* Complete Step */}
          {step === 'complete' && importResult && (
            <div className="h-64 flex flex-col items-center justify-center gap-4">
              <div className="p-4 rounded-full bg-neon-green/20">
                <Check className="w-8 h-8 text-neon-green" />
              </div>
              <div className="text-center">
                <p className="text-lg font-medium">Import Complete</p>
                <div className="flex items-center justify-center gap-4 mt-2">
                  <span className="flex items-center gap-1 text-sm text-neon-green">
                    <Check className="w-4 h-4" />
                    {importResult.success} imported
                  </span>
                  {importResult.failed > 0 && (
                    <span className="flex items-center gap-1 text-sm text-destructive">
                      <X className="w-4 h-4" />
                      {importResult.failed} failed
                    </span>
                  )}
                </div>
              </div>
            </div>
          )}
        </div>

        <DialogFooter className="flex items-center justify-between sm:justify-between">
          <div>
            {step === 'mapping' && !requiredFieldsMapped && (
              <span className="flex items-center gap-1 text-xs text-destructive">
                <AlertCircle className="w-3 h-3" />
                Map required fields (Name, Hostname)
              </span>
            )}
            {step === 'mapping' && file && (
              <span className="text-xs text-muted-foreground">
                {file.name} - {preview?.totalRows} rows
              </span>
            )}
          </div>
          <div className="flex items-center gap-2">
            {step !== 'importing' && (
              <Button variant="outline" onClick={handleClose}>
                {step === 'complete' ? 'Close' : 'Cancel'}
              </Button>
            )}
            {step === 'mapping' && (
              <>
                <Button variant="outline" onClick={() => setStep('upload')}>
                  Back
                </Button>
                <Button onClick={() => setStep('preview')} disabled={!requiredFieldsMapped}>
                  Next
                </Button>
              </>
            )}
            {step === 'preview' && (
              <>
                <Button variant="outline" onClick={() => setStep('mapping')}>
                  Back
                </Button>
                <Button onClick={handleStartImport}>
                  Import {preview?.totalRows} Assets
                </Button>
              </>
            )}
          </div>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
