/**
 * useCopilot - React hook for Copilot API interactions.
 */
import { useState, useCallback, useRef, useEffect } from 'react';
import { Message, QueryResultData, ContextItem, ConversationHistoryItem, SavedQuery } from '../components';

export interface CopilotApiConfig {
  baseUrl: string;
  wsUrl: string;
  sessionId?: string;
}

export interface CopilotState {
  messages: Message[];
  isLoading: boolean;
  isStreaming: boolean;
  conversationId: string | null;
  queryResult: QueryResultData | null;
  error: Error | null;
  contextItems: ContextItem[];
  conversations: ConversationHistoryItem[];
  savedQueries: SavedQuery[];
}

export interface UseCopilotReturn extends CopilotState {
  sendMessage: (message: string, context?: Record<string, unknown>) => Promise<void>;
  stopGeneration: () => void;
  clearMessages: () => void;
  addContext: (item: Omit<ContextItem, 'id' | 'addedAt'>) => void;
  removeContext: (id: string) => void;
  clearContext: () => void;
  saveQuery: (name: string, query: string) => void;
  deleteQuery: (id: string) => void;
  selectConversation: (id: string) => Promise<void>;
  deleteConversation: (id: string) => void;
  newConversation: () => void;
  nl2sql: (query: string, context?: Record<string, unknown>) => Promise<string | null>;
  summarize: (incidentId: string, incidentData: Record<string, unknown>) => Promise<string | null>;
  recommendPlaybooks: (context: Record<string, unknown>) => Promise<unknown[] | null>;
  findSimilarCases: (context: Record<string, unknown>) => Promise<unknown[] | null>;
}

const generateId = () => `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

export function useCopilot(config: CopilotApiConfig): UseCopilotReturn {
  const [state, setState] = useState<CopilotState>({
    messages: [],
    isLoading: false,
    isStreaming: false,
    conversationId: null,
    queryResult: null,
    error: null,
    contextItems: [],
    conversations: [],
    savedQueries: [],
  });

  const abortControllerRef = useRef<AbortController | null>(null);
  const wsRef = useRef<WebSocket | null>(null);

  // Load saved data from localStorage
  useEffect(() => {
    const savedConversations = localStorage.getItem('copilot-conversations');
    const savedQueries = localStorage.getItem('copilot-saved-queries');

    if (savedConversations) {
      try {
        const parsed = JSON.parse(savedConversations);
        setState((prev) => ({
          ...prev,
          conversations: parsed.map((c: ConversationHistoryItem) => ({
            ...c,
            timestamp: new Date(c.timestamp),
          })),
        }));
      } catch (e) {
        console.error('Failed to parse saved conversations:', e);
      }
    }

    if (savedQueries) {
      try {
        const parsed = JSON.parse(savedQueries);
        setState((prev) => ({
          ...prev,
          savedQueries: parsed.map((q: SavedQuery) => ({
            ...q,
            createdAt: new Date(q.createdAt),
          })),
        }));
      } catch (e) {
        console.error('Failed to parse saved queries:', e);
      }
    }
  }, []);

  // Save conversations to localStorage
  useEffect(() => {
    if (state.conversations.length > 0) {
      localStorage.setItem('copilot-conversations', JSON.stringify(state.conversations));
    }
  }, [state.conversations]);

  // Save queries to localStorage
  useEffect(() => {
    if (state.savedQueries.length > 0) {
      localStorage.setItem('copilot-saved-queries', JSON.stringify(state.savedQueries));
    }
  }, [state.savedQueries]);

  // Cleanup
  useEffect(() => {
    return () => {
      if (wsRef.current) {
        wsRef.current.close();
      }
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
      }
    };
  }, []);

  const sendMessage = useCallback(
    async (message: string, context?: Record<string, unknown>) => {
      const userMessage: Message = {
        id: generateId(),
        role: 'user',
        content: message,
        timestamp: new Date(),
      };

      const assistantMessage: Message = {
        id: generateId(),
        role: 'assistant',
        content: '',
        timestamp: new Date(),
        isStreaming: true,
      };

      setState((prev) => ({
        ...prev,
        messages: [...prev.messages, userMessage, assistantMessage],
        isLoading: true,
        error: null,
      }));

      const controller = new AbortController();
      abortControllerRef.current = controller;

      try {
        const response = await fetch(`${config.baseUrl}/api/v1/chat`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            message,
            conversation_id: state.conversationId,
            context: {
              ...context,
              contextItems: state.contextItems.map((item) => item.data),
            },
            session_id: config.sessionId,
          }),
          signal: controller.signal,
        });

        if (!response.ok) {
          throw new Error(`HTTP ${response.status}`);
        }

        const data = await response.json();

        if (data.success && data.data) {
          const responseData = data.data;
          let content: Message['content'] = responseData.message;

          if (responseData.generated_query) {
            content = [
              { type: 'text', content: responseData.message },
              { type: 'sql', content: responseData.generated_query },
            ];
          }

          setState((prev) => ({
            ...prev,
            messages: prev.messages.map((msg) =>
              msg.id === assistantMessage.id
                ? {
                    ...msg,
                    content,
                    isStreaming: false,
                    queryType: responseData.query_type,
                    confidence: responseData.confidence,
                  }
                : msg
            ),
            conversationId: responseData.conversation_id || prev.conversationId,
            isLoading: false,
          }));

          // Update conversation history
          setState((prev) => {
            const existingIndex = prev.conversations.findIndex(
              (c) => c.id === responseData.conversation_id
            );

            const newConv: ConversationHistoryItem = {
              id: responseData.conversation_id,
              title: message.substring(0, 50),
              preview: typeof content === 'string' ? content.substring(0, 100) : content[0]?.content.substring(0, 100) || '',
              timestamp: new Date(),
              messageCount: prev.messages.length,
            };

            if (existingIndex >= 0) {
              const updated = [...prev.conversations];
              updated[existingIndex] = newConv;
              return { ...prev, conversations: updated };
            }

            return {
              ...prev,
              conversations: [newConv, ...prev.conversations].slice(0, 50),
            };
          });
        } else {
          throw new Error(data.error || 'Unknown error');
        }
      } catch (error) {
        if ((error as Error).name !== 'AbortError') {
          setState((prev) => ({
            ...prev,
            messages: prev.messages.map((msg) =>
              msg.id === assistantMessage.id
                ? { ...msg, role: 'error', content: `Error: ${(error as Error).message}`, isStreaming: false }
                : msg
            ),
            isLoading: false,
            error: error as Error,
          }));
        }
      } finally {
        abortControllerRef.current = null;
      }
    },
    [config.baseUrl, config.sessionId, state.conversationId, state.contextItems]
  );

  const stopGeneration = useCallback(() => {
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
    }
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }
    setState((prev) => ({
      ...prev,
      isLoading: false,
      isStreaming: false,
    }));
  }, []);

  const clearMessages = useCallback(() => {
    setState((prev) => ({
      ...prev,
      messages: [],
      conversationId: null,
      queryResult: null,
    }));
  }, []);

  const addContext = useCallback((item: Omit<ContextItem, 'id' | 'addedAt'>) => {
    const newItem: ContextItem = {
      ...item,
      id: generateId(),
      addedAt: new Date(),
    };
    setState((prev) => ({
      ...prev,
      contextItems: [...prev.contextItems, newItem],
    }));
  }, []);

  const removeContext = useCallback((id: string) => {
    setState((prev) => ({
      ...prev,
      contextItems: prev.contextItems.filter((item) => item.id !== id),
    }));
  }, []);

  const clearContext = useCallback(() => {
    setState((prev) => ({
      ...prev,
      contextItems: [],
    }));
  }, []);

  const saveQuery = useCallback((name: string, query: string) => {
    const newQuery: SavedQuery = {
      id: generateId(),
      name,
      query,
      createdAt: new Date(),
    };
    setState((prev) => ({
      ...prev,
      savedQueries: [newQuery, ...prev.savedQueries],
    }));
  }, []);

  const deleteQuery = useCallback((id: string) => {
    setState((prev) => ({
      ...prev,
      savedQueries: prev.savedQueries.filter((q) => q.id !== id),
    }));
  }, []);

  const selectConversation = useCallback(
    async (id: string) => {
      // In a real implementation, this would fetch messages from the server
      setState((prev) => ({
        ...prev,
        conversationId: id,
      }));
    },
    []
  );

  const deleteConversation = useCallback((id: string) => {
    setState((prev) => ({
      ...prev,
      conversations: prev.conversations.filter((c) => c.id !== id),
    }));
  }, []);

  const newConversation = useCallback(() => {
    setState((prev) => ({
      ...prev,
      messages: [],
      conversationId: null,
      queryResult: null,
    }));
  }, []);

  const nl2sql = useCallback(
    async (query: string, context?: Record<string, unknown>): Promise<string | null> => {
      try {
        const response = await fetch(`${config.baseUrl}/api/v1/nl2sql`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ query, context }),
        });

        if (!response.ok) {
          throw new Error(`HTTP ${response.status}`);
        }

        const data = await response.json();
        if (data.success && data.data) {
          setState((prev) => ({
            ...prev,
            queryResult: {
              columns: [],
              rows: [],
              totalRows: 0,
              query: data.data.sql,
            },
          }));
          return data.data.sql;
        }
        return null;
      } catch (error) {
        setState((prev) => ({ ...prev, error: error as Error }));
        return null;
      }
    },
    [config.baseUrl]
  );

  const summarize = useCallback(
    async (incidentId: string, incidentData: Record<string, unknown>): Promise<string | null> => {
      try {
        const response = await fetch(`${config.baseUrl}/api/v1/summarize`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ incident_id: incidentId, incident_data: incidentData }),
        });

        if (!response.ok) {
          throw new Error(`HTTP ${response.status}`);
        }

        const data = await response.json();
        if (data.success && data.data) {
          return data.data.executive_summary;
        }
        return null;
      } catch (error) {
        setState((prev) => ({ ...prev, error: error as Error }));
        return null;
      }
    },
    [config.baseUrl]
  );

  const recommendPlaybooks = useCallback(
    async (context: Record<string, unknown>): Promise<unknown[] | null> => {
      try {
        const response = await fetch(`${config.baseUrl}/api/v1/recommend/playbooks`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ context }),
        });

        if (!response.ok) {
          throw new Error(`HTTP ${response.status}`);
        }

        const data = await response.json();
        if (data.success && data.data) {
          return data.data.recommendations;
        }
        return null;
      } catch (error) {
        setState((prev) => ({ ...prev, error: error as Error }));
        return null;
      }
    },
    [config.baseUrl]
  );

  const findSimilarCases = useCallback(
    async (context: Record<string, unknown>): Promise<unknown[] | null> => {
      try {
        const response = await fetch(`${config.baseUrl}/api/v1/similar`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ query_context: context }),
        });

        if (!response.ok) {
          throw new Error(`HTTP ${response.status}`);
        }

        const data = await response.json();
        if (data.success && data.data) {
          return data.data.cases;
        }
        return null;
      } catch (error) {
        setState((prev) => ({ ...prev, error: error as Error }));
        return null;
      }
    },
    [config.baseUrl]
  );

  return {
    ...state,
    sendMessage,
    stopGeneration,
    clearMessages,
    addContext,
    removeContext,
    clearContext,
    saveQuery,
    deleteQuery,
    selectConversation,
    deleteConversation,
    newConversation,
    nl2sql,
    summarize,
    recommendPlaybooks,
    findSimilarCases,
  };
}
