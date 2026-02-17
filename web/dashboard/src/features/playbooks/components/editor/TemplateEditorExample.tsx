import { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { TemplateEditor, type UpstreamNode } from './TemplateEditor';

/**
 * Example usage of TemplateEditor component
 *
 * This demonstrates how to use the TemplateEditor with upstream nodes
 * for auto-completion of {{ $node.xxx.json.yyy }} syntax
 */
export function TemplateEditorExample() {
  const [templateValue, setTemplateValue] = useState(
    'Send alert to {{ $node.EnrichAlert.json.recipient_email }} with subject: {{ $node.EnrichAlert.json.alert.severity }}'
  );

  // Example upstream nodes - in real usage, these would come from the workflow graph
  const upstreamNodes: UpstreamNode[] = [
    {
      nodeId: 'trigger-1',
      nodeName: 'AlertTrigger',
    },
    {
      nodeId: 'enrich-1',
      nodeName: 'EnrichAlert',
    },
    {
      nodeId: 'decision-1',
      nodeName: 'CheckSeverity',
    },
  ];

  return (
    <Card className="w-full max-w-4xl">
      <CardHeader>
        <CardTitle>Template Editor Example</CardTitle>
        <CardDescription>
          Try typing <code className="px-1.5 py-0.5 rounded bg-muted text-sm">{'{{ $node.'}</code> to see auto-complete suggestions
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div>
          <label className="text-sm font-medium mb-2 block">
            Email Template
          </label>
          <TemplateEditor
            value={templateValue}
            onChange={setTemplateValue}
            upstreamNodes={upstreamNodes}
            placeholder="Enter email template with {{ }} expressions..."
            minHeight={120}
            maxHeight={300}
          />
        </div>

        <div className="mt-4 p-4 bg-muted/50 rounded-lg">
          <h4 className="text-sm font-semibold mb-2">Preview</h4>
          <pre className="text-xs whitespace-pre-wrap font-mono text-muted-foreground">
            {templateValue}
          </pre>
        </div>

        <div className="mt-4 space-y-2">
          <h4 className="text-sm font-semibold">Available Completions:</h4>
          <ul className="text-xs text-muted-foreground space-y-1">
            <li>• <code className="px-1 py-0.5 rounded bg-muted">{'{{ $node.AlertTrigger.json... }}'}</code> - Access trigger data</li>
            <li>• <code className="px-1 py-0.5 rounded bg-muted">{'{{ $node.EnrichAlert.json... }}'}</code> - Access enriched alert data</li>
            <li>• <code className="px-1 py-0.5 rounded bg-muted">{'{{ $node.CheckSeverity.json... }}'}</code> - Access decision result</li>
            <li>• <code className="px-1 py-0.5 rounded bg-muted">{'{{ $json... }}'}</code> - Access current node data</li>
            <li>• <code className="px-1 py-0.5 rounded bg-muted">{'{{ $execution... }}'}</code> - Access execution metadata</li>
          </ul>
        </div>
      </CardContent>
    </Card>
  );
}
