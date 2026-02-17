/**
 * CopilotPage - Full-page wrapper for Security Copilot
 */
import { CopilotChat, CopilotConfig } from './CopilotChat';

const defaultConfig: CopilotConfig = {
  apiEndpoint: '/api',
  wsEndpoint: `${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${window.location.host}/ws`,
  language: 'auto',
  streamingEnabled: false,
  mockMode: false, // Connect to real backend API
};

export function CopilotPage() {
  return (
    <div className="h-full flex flex-col animate-fade-in">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h1 className="text-2xl font-display font-bold tracking-tight">
            AI Copilot
          </h1>
          <p className="text-muted-foreground">
            Security AI assistant for queries, analysis, and recommendations
          </p>
        </div>
      </div>
      <div className="flex-1 min-h-0">
        <CopilotChat config={defaultConfig} isExpanded />
      </div>
    </div>
  );
}
