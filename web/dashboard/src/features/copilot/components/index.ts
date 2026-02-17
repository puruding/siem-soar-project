/**
 * Copilot UI Components
 *
 * Security Copilot chat interface with support for:
 * - Streaming responses via WebSocket
 * - NL2SQL query generation and results
 * - Incident summarization
 * - Playbook recommendations
 * - Korean/English language support
 */

export { CopilotChat } from './CopilotChat';
export type { CopilotConfig } from './CopilotChat';

export { CopilotPage } from './CopilotPage';

export { CopilotSidebar } from './CopilotSidebar';
export type { ConversationHistoryItem, ContextItem, SavedQuery } from './CopilotSidebar';

export { MessageBubble } from './MessageBubble';
export type { Message, MessageContent, MessageRole } from './MessageBubble';

export { SuggestionChips, DEFAULT_SUGGESTIONS, KOREAN_SUGGESTIONS } from './SuggestionChips';
export type { Suggestion } from './SuggestionChips';

export { QueryResult } from './QueryResult';
export type { QueryResultData } from './QueryResult';
