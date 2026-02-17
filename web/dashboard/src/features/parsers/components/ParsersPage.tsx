import { useState, useCallback } from 'react';
import { Button } from '@/components/ui/button';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { FileCode2, PanelLeftClose, PanelLeft } from 'lucide-react';
import { useParsers, useParserTest } from '../hooks/useParsers';
import { ParserList } from './ParserList';
import { ParserEditor } from './ParserEditor';
import { GrokTestPanel } from './GrokTestPanel';
import { FormatSelector } from './FormatSelector';
import type { ParserFormat, Parser } from '../types';

export function ParsersPage() {
  const {
    parsers,
    selectedParser,
    setSelectedParser,
    createParser,
    updateParser,
    deleteParser,
  } = useParsers();

  const { isRunning, result, runTest, clearResult } = useParserTest();

  const [showCreateDialog, setShowCreateDialog] = useState(false);
  const [newParserName, setNewParserName] = useState('');
  const [newParserFormat, setNewParserFormat] = useState<ParserFormat>('grok');
  const [isListCollapsed, setIsListCollapsed] = useState(false);

  const handleCreateParser = useCallback(() => {
    if (newParserName.trim()) {
      const parser = createParser({
        name: newParserName.trim(),
        format: newParserFormat,
        pattern: '',
        fieldMappings: [],
        sampleLogs: [],
        status: 'draft',
      });
      setSelectedParser(parser);
      setShowCreateDialog(false);
      setNewParserName('');
      setNewParserFormat('grok');
    }
  }, [newParserName, newParserFormat, createParser, setSelectedParser]);

  const handleSaveParser = useCallback(
    (updates: Partial<Parser>) => {
      if (selectedParser) {
        updateParser(selectedParser.id, updates);
      }
    },
    [selectedParser, updateParser]
  );

  const handleDeleteParser = useCallback(() => {
    if (selectedParser) {
      deleteParser(selectedParser.id);
    }
  }, [selectedParser, deleteParser]);

  const handleTest = useCallback(
    (sampleLog: string) => {
      if (selectedParser) {
        runTest(selectedParser, sampleLog);
      }
    },
    [selectedParser, runTest]
  );

  return (
    <div className="h-[calc(100vh-140px)] flex flex-col animate-fade-in">
      {/* Page header */}
      <div className="flex items-center justify-between pb-4 flex-shrink-0">
        <div>
          <h1 className="text-2xl font-display font-bold tracking-tight">
            Parser Management
          </h1>
          <p className="text-muted-foreground">
            Create and test log parsers with Grok, JSON, CEF, and more
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => setIsListCollapsed(!isListCollapsed)}
          >
            {isListCollapsed ? (
              <>
                <PanelLeft className="w-4 h-4 mr-2" />
                Show List
              </>
            ) : (
              <>
                <PanelLeftClose className="w-4 h-4 mr-2" />
                Hide List
              </>
            )}
          </Button>
        </div>
      </div>

      {/* Main Layout - Using flex instead of ResizablePanelGroup */}
      <div className="flex-1 min-h-0 flex rounded-lg border border-border/50 bg-card/50 overflow-hidden">
        {/* Parser List Panel */}
        {!isListCollapsed && (
          <div className="w-64 shrink-0 border-r border-border/50">
            <ParserList
              parsers={parsers}
              selectedParser={selectedParser}
              onSelect={setSelectedParser}
              onCreate={() => setShowCreateDialog(true)}
            />
          </div>
        )}

        {/* Editor Panel */}
        <div className="flex-1 min-w-0 border-r border-border/50">
          {selectedParser ? (
            <ParserEditor
              key={selectedParser.id}
              parser={selectedParser}
              onSave={handleSaveParser}
              onDelete={handleDeleteParser}
            />
          ) : (
            <div className="h-full flex items-center justify-center text-muted-foreground">
              <div className="text-center">
                <FileCode2 className="w-16 h-16 mx-auto mb-4 opacity-20" />
                <p className="text-lg font-medium mb-2">No Parser Selected</p>
                <p className="text-sm">
                  Select a parser from the list or create a new one
                </p>
                <Button
                  variant="outline"
                  className="mt-4"
                  onClick={() => setShowCreateDialog(true)}
                >
                  Create Parser
                </Button>
              </div>
            </div>
          )}
        </div>

        {/* Test Panel */}
        <div className="w-[400px] shrink-0">
          {selectedParser ? (
            <GrokTestPanel
              parser={selectedParser}
              isRunning={isRunning}
              result={result}
              onTest={handleTest}
              onClear={clearResult}
            />
          ) : (
            <div className="h-full flex items-center justify-center text-muted-foreground">
              <div className="text-center">
                <p className="text-sm">Select a parser to test</p>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Create Parser Dialog */}
      <Dialog open={showCreateDialog} onOpenChange={setShowCreateDialog}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Create New Parser</DialogTitle>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label htmlFor="name">Parser Name</Label>
              <Input
                id="name"
                value={newParserName}
                onChange={(e) => setNewParserName(e.target.value)}
                placeholder="e.g., AWS CloudTrail Parser"
                className="bg-background/50"
              />
            </div>
            <div className="space-y-2">
              <Label>Format</Label>
              <FormatSelector
                value={newParserFormat}
                onChange={setNewParserFormat}
              />
            </div>
          </div>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setShowCreateDialog(false)}
            >
              Cancel
            </Button>
            <Button
              onClick={handleCreateParser}
              disabled={!newParserName.trim()}
              className="bg-gradient-to-r from-[#00A4A6] to-[#00A4A6]/80"
            >
              Create Parser
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
