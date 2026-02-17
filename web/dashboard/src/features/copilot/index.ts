/**
 * Security Copilot Feature Module
 *
 * AI-powered assistant for security analysts providing:
 * - Natural language query interface (NL2SQL)
 * - Incident summarization
 * - Playbook recommendations
 * - Similar case search
 * - Korean/English bilingual support
 */

// Components
export {
  CopilotChat,
  CopilotPage,
  CopilotSidebar,
  MessageBubble,
  SuggestionChips,
  QueryResult,
  DEFAULT_SUGGESTIONS,
  KOREAN_SUGGESTIONS,
} from './components';

export type {
  CopilotConfig,
  ConversationHistoryItem,
  ContextItem,
  SavedQuery,
  Message,
  MessageContent,
  MessageRole,
  Suggestion,
  QueryResultData,
} from './components';

// Hooks
export { useCopilot } from './hooks';
export type { CopilotApiConfig, CopilotState, UseCopilotReturn } from './hooks';

// Types
export type {
  QueryType,
  CopilotLanguage,
  ContextType,
  PlaybookRecommendation,
  SimilarCase,
  NL2SQLResult,
  IncidentSummaryResult,
  ActionSuggestion,
  ChatResponse,
} from './types';
