/**
 * Copilot Type Definitions
 *
 * Re-exports types from components for backward compatibility.
 * New code should import directly from the component modules.
 */

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
} from '../components';

export type {
  CopilotApiConfig,
  CopilotState,
  UseCopilotReturn,
} from '../hooks';

// Additional type definitions

/**
 * Query types supported by the Copilot.
 */
export type QueryType =
  | 'investigation'
  | 'query'
  | 'playbook'
  | 'explanation'
  | 'recommendation'
  | 'summarization';

/**
 * Supported languages for Copilot interface.
 */
export type CopilotLanguage = 'en' | 'ko' | 'auto';

/**
 * Context types for session context management.
 */
export type ContextType =
  | 'alert'
  | 'case'
  | 'event'
  | 'query_result'
  | 'playbook'
  | 'user_preference';

/**
 * Playbook recommendation from the Copilot API.
 */
export interface PlaybookRecommendation {
  playbook_id: string;
  name: string;
  description: string;
  category: string;
  confidence: number;
  match_reasons: string[];
  estimated_impact: string;
  prerequisites: string[];
  warnings: string[];
  auto_execute: boolean;
  success_rate: number;
  avg_execution_time: number;
}

/**
 * Similar case result from the Copilot API.
 */
export interface SimilarCase {
  case_id: string;
  title: string;
  description: string;
  similarity_score: number;
  match_reasons: string[];
  resolution: string;
  playbooks_used: string[];
  time_to_resolve: number;
  severity: string;
  incident_type: string;
}

/**
 * NL2SQL response from the Copilot API.
 */
export interface NL2SQLResult {
  sql: string;
  confidence: number;
  tables_used: string[];
  estimated_cost: string;
  warnings: string[];
  explanation?: string;
  is_valid: boolean;
  validation_issues: string[];
  suggestions: string[];
}

/**
 * Incident summary from the Copilot API.
 */
export interface IncidentSummaryResult {
  incident_id: string;
  title: string;
  executive_summary: string;
  detailed_summary: string;
  key_findings: string[];
  ioc_summary: Array<{
    type: string;
    value: string;
    context: string;
  }>;
  timeline_summary: Array<{
    timestamp: string;
    event: string;
    significance: string;
  }>;
  mitre_mapping: Array<{
    tactic: string;
    technique: string;
    procedure: string;
  }>;
  recommendations: string[];
  severity: string;
  confidence: number;
  language: string;
}

/**
 * Action suggestion from the Copilot API.
 */
export interface ActionSuggestion {
  action_id: string;
  title: string;
  description: string;
  category: string;
  priority: 'critical' | 'high' | 'medium' | 'low';
  estimated_time: number;
  automation_available: boolean;
  playbook_id?: string;
  prerequisites: string[];
  dependencies: string[];
  tools_required: string[];
}

/**
 * Chat response from the Copilot API.
 */
export interface ChatResponse {
  message: string;
  query_type: QueryType;
  conversation_id: string;
  suggestions: string[];
  generated_query?: string;
  generated_playbook?: Record<string, unknown>;
  sources: string[];
  confidence: number;
}
