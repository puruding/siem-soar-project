import { useState } from 'react';
import Editor from '@monaco-editor/react';
import { Copy, Check } from 'lucide-react';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { Button } from '@/components/ui/button';
import { ScrollArea } from '@/components/ui/scroll-area';
import type { NodeExecutionResult } from '../../types/execution.types';

interface NodeDetailViewerProps {
  nodeResult: NodeExecutionResult | null;
}

export function NodeDetailViewer({ nodeResult }: NodeDetailViewerProps) {
  const [activeTab, setActiveTab] = useState<'input' | 'output' | 'error'>('output');
  const [copiedTab, setCopiedTab] = useState<string | null>(null);

  if (!nodeResult) {
    return (
      <div className="flex items-center justify-center h-full text-muted-foreground text-sm">
        Select a node to view details
      </div>
    );
  }

  const hasInput = nodeResult.input && Object.keys(nodeResult.input).length > 0;
  const hasOutput = nodeResult.output && Object.keys(nodeResult.output).length > 0;
  const hasError = nodeResult.error !== undefined;

  // Auto-select appropriate tab
  const effectiveTab = (() => {
    if (activeTab === 'error' && !hasError) return hasOutput ? 'output' : 'input';
    if (activeTab === 'output' && !hasOutput) return hasError ? 'error' : 'input';
    if (activeTab === 'input' && !hasInput) return hasOutput ? 'output' : 'error';
    return activeTab;
  })();

  const handleCopy = (content: string, tab: string) => {
    navigator.clipboard.writeText(content);
    setCopiedTab(tab);
    setTimeout(() => setCopiedTab(null), 2000);
  };

  const renderJsonEditor = (data: unknown, tabName: string) => {
    const jsonString = JSON.stringify(data, null, 2);

    return (
      <div className="relative h-full">
        <div className="absolute top-2 right-2 z-10">
          <Button
            size="sm"
            variant="ghost"
            onClick={() => handleCopy(jsonString, tabName)}
            className="h-7 px-2"
          >
            {copiedTab === tabName ? (
              <>
                <Check className="w-3 h-3 mr-1" />
                Copied
              </>
            ) : (
              <>
                <Copy className="w-3 h-3 mr-1" />
                Copy
              </>
            )}
          </Button>
        </div>

        <Editor
          height="100%"
          language="json"
          theme="vs-dark"
          value={jsonString}
          options={{
            readOnly: true,
            minimap: { enabled: false },
            scrollBeyondLastLine: false,
            fontSize: 12,
            lineNumbers: 'on',
            folding: true,
            wordWrap: 'on',
            automaticLayout: true,
          }}
        />
      </div>
    );
  };

  return (
    <div className="flex flex-col h-full">
      {/* Node info header */}
      <div className="p-4 border-b border-[#2D3339]">
        <h3 className="text-sm font-semibold text-[#FFFFFF]">{nodeResult.nodeName}</h3>
        <p className="text-xs text-[#9BA7B4] mt-1">Node ID: {nodeResult.nodeId}</p>
      </div>

      {/* Tabs */}
      <Tabs value={effectiveTab} onValueChange={(v) => setActiveTab(v as typeof activeTab)} className="flex-1 flex flex-col">
        <div className="border-b border-[#2D3339] px-4">
          <TabsList className="bg-transparent h-10 p-0">
            <TabsTrigger
              value="input"
              disabled={!hasInput}
              className="data-[state=active]:bg-transparent data-[state=active]:border-b-2 data-[state=active]:border-[#00A4A6] rounded-none"
            >
              Input
            </TabsTrigger>
            <TabsTrigger
              value="output"
              disabled={!hasOutput}
              className="data-[state=active]:bg-transparent data-[state=active]:border-b-2 data-[state=active]:border-[#00A4A6] rounded-none"
            >
              Output
            </TabsTrigger>
            <TabsTrigger
              value="error"
              disabled={!hasError}
              className="data-[state=active]:bg-transparent data-[state=active]:border-b-2 data-[state=active]:border-[#DC4E41] rounded-none text-[#DC4E41]"
            >
              Error
            </TabsTrigger>
          </TabsList>
        </div>

        <div className="flex-1 overflow-hidden">
          <TabsContent value="input" className="h-full m-0 p-0">
            {hasInput ? (
              renderJsonEditor(nodeResult.input, 'input')
            ) : (
              <div className="flex items-center justify-center h-full text-muted-foreground text-sm">
                No input data
              </div>
            )}
          </TabsContent>

          <TabsContent value="output" className="h-full m-0 p-0">
            {hasOutput ? (
              renderJsonEditor(nodeResult.output, 'output')
            ) : (
              <div className="flex items-center justify-center h-full text-muted-foreground text-sm">
                No output data
              </div>
            )}
          </TabsContent>

          <TabsContent value="error" className="h-full m-0 p-0">
            {hasError ? (
              <ScrollArea className="h-full">
                <div className="p-4 space-y-4">
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <h4 className="text-sm font-semibold text-[#DC4E41]">Error Message</h4>
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => handleCopy(nodeResult.error?.message || '', 'error-message')}
                        className="h-7 px-2"
                      >
                        {copiedTab === 'error-message' ? (
                          <>
                            <Check className="w-3 h-3 mr-1" />
                            Copied
                          </>
                        ) : (
                          <>
                            <Copy className="w-3 h-3 mr-1" />
                            Copy
                          </>
                        )}
                      </Button>
                    </div>
                    <pre className="text-xs text-[#FFFFFF] bg-[#1F2527] p-3 rounded border border-[#2D3339] whitespace-pre-wrap">
                      {nodeResult.error?.message}
                    </pre>
                  </div>

                  {nodeResult.error?.code && (
                    <div>
                      <h4 className="text-sm font-semibold text-[#DC4E41] mb-2">Error Code</h4>
                      <pre className="text-xs text-[#FFFFFF] bg-[#1F2527] p-3 rounded border border-[#2D3339]">
                        {nodeResult.error.code}
                      </pre>
                    </div>
                  )}

                  {nodeResult.error?.stack && (
                    <div>
                      <div className="flex items-center justify-between mb-2">
                        <h4 className="text-sm font-semibold text-[#DC4E41]">Stack Trace</h4>
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => handleCopy(nodeResult.error?.stack || '', 'error-stack')}
                          className="h-7 px-2"
                        >
                          {copiedTab === 'error-stack' ? (
                            <>
                              <Check className="w-3 h-3 mr-1" />
                              Copied
                            </>
                          ) : (
                            <>
                              <Copy className="w-3 h-3 mr-1" />
                              Copy
                            </>
                          )}
                        </Button>
                      </div>
                      <pre className="text-xs text-[#9BA7B4] bg-[#1F2527] p-3 rounded border border-[#2D3339] whitespace-pre-wrap font-mono">
                        {nodeResult.error.stack}
                      </pre>
                    </div>
                  )}
                </div>
              </ScrollArea>
            ) : (
              <div className="flex items-center justify-center h-full text-muted-foreground text-sm">
                No errors
              </div>
            )}
          </TabsContent>
        </div>
      </Tabs>
    </div>
  );
}
