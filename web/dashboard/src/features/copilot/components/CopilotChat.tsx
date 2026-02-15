/**
 * CopilotChat - Main chat interface component for Security Copilot.
 * Features: Streaming responses, NL2SQL, context-aware conversations, Korean support.
 */
import { useState, useRef, useEffect, useCallback, useMemo } from 'react';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { ScrollArea } from '@/components/ui/scroll-area';
import { cn } from '@/lib/utils';
import {
  Send,
  Mic,
  MicOff,
  Paperclip,
  Settings,
  Maximize2,
  Minimize2,
  RefreshCw,
  StopCircle,
  Sparkles,
  Database,
  Languages,
} from 'lucide-react';
import { MessageBubble, Message, MessageContent } from './MessageBubble';
import { SuggestionChips, Suggestion, DEFAULT_SUGGESTIONS, KOREAN_SUGGESTIONS } from './SuggestionChips';
import { QueryResult, QueryResultData } from './QueryResult';
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@/components/ui/tooltip';

export interface CopilotConfig {
  apiEndpoint: string;
  wsEndpoint: string;
  sessionId?: string;
  language: 'en' | 'ko' | 'auto';
  streamingEnabled: boolean;
}

interface CopilotChatProps {
  config: CopilotConfig;
  initialMessages?: Message[];
  contextData?: Record<string, unknown>;
  onQueryResult?: (data: QueryResultData) => void;
  onError?: (error: Error) => void;
  className?: string;
  isExpanded?: boolean;
  onToggleExpand?: () => void;
}

const SYSTEM_MESSAGE: Message = {
  id: 'system-welcome',
  role: 'assistant',
  content: [
    {
      type: 'text',
      content:
        'Hello! I\'m Security Copilot, your AI assistant for security analysis. I can help you with:\n\n' +
        '- **Query data** using natural language (NL2SQL)\n' +
        '- **Summarize incidents** and extract key findings\n' +
        '- **Recommend playbooks** based on your current context\n' +
        '- **Find similar cases** from historical data\n\n' +
        'How can I assist you today?',
    },
  ],
  timestamp: new Date(),
};

const KOREAN_SYSTEM_MESSAGE: Message = {
  id: 'system-welcome',
  role: 'assistant',
  content: [
    {
      type: 'text',
      content:
        '안녕하세요! 보안 분석을 위한 AI 어시스턴트 Security Copilot입니다. 다음과 같은 도움을 드릴 수 있습니다:\n\n' +
        '- **데이터 조회** - 자연어로 쿼리 (NL2SQL)\n' +
        '- **인시던트 요약** - 핵심 정보 추출\n' +
        '- **플레이북 추천** - 컨텍스트 기반 추천\n' +
        '- **유사 케이스 검색** - 과거 이력 분석\n\n' +
        '어떻게 도와드릴까요?',
    },
  ],
  timestamp: new Date(),
};

export function CopilotChat({
  config,
  initialMessages = [],
  contextData,
  onQueryResult,
  onError,
  className,
  isExpanded = false,
  onToggleExpand,
}: CopilotChatProps) {
  const [messages, setMessages] = useState<Message[]>(() => {
    const welcomeMsg = config.language === 'ko' ? KOREAN_SYSTEM_MESSAGE : SYSTEM_MESSAGE;
    return initialMessages.length > 0 ? initialMessages : [welcomeMsg];
  });
  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [isStreaming, setIsStreaming] = useState(false);
  const [language, setLanguage] = useState<'en' | 'ko'>(
    config.language === 'auto' ? 'en' : config.language
  );
  const [queryResult, setQueryResult] = useState<QueryResultData | null>(null);
  const [conversationId, setConversationId] = useState<string | null>(null);
  const [abortController, setAbortController] = useState<AbortController | null>(null);

  const scrollRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);
  const wsRef = useRef<WebSocket | null>(null);

  // Auto-scroll to bottom when messages change
  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [messages]);

  // Auto-detect language from input
  useEffect(() => {
    if (config.language === 'auto' && input.length > 0) {
      const koreanRegex = /[\uAC00-\uD7AF\u1100-\u11FF]/;
      if (koreanRegex.test(input)) {
        setLanguage('ko');
      } else {
        setLanguage('en');
      }
    }
  }, [input, config.language]);

  // Cleanup WebSocket on unmount
  useEffect(() => {
    return () => {
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, []);

  const suggestions = useMemo(
    () => (language === 'ko' ? KOREAN_SUGGESTIONS : DEFAULT_SUGGESTIONS),
    [language]
  );

  const connectWebSocket = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      return wsRef.current;
    }

    const ws = new WebSocket(config.wsEndpoint);
    wsRef.current = ws;

    ws.onopen = () => {
      console.log('WebSocket connected');
    };

    ws.onclose = () => {
      console.log('WebSocket disconnected');
      wsRef.current = null;
    };

    ws.onerror = (error) => {
      console.error('WebSocket error:', error);
      onError?.(new Error('WebSocket connection failed'));
    };

    return ws;
  }, [config.wsEndpoint, onError]);

  const sendMessageStreaming = useCallback(
    async (messageText: string) => {
      const ws = connectWebSocket();
      if (!ws || ws.readyState !== WebSocket.OPEN) {
        // Fallback to non-streaming
        await sendMessageRest(messageText);
        return;
      }

      const userMessage: Message = {
        id: `user-${Date.now()}`,
        role: 'user',
        content: messageText,
        timestamp: new Date(),
      };

      const assistantMessage: Message = {
        id: `assistant-${Date.now()}`,
        role: 'assistant',
        content: '',
        timestamp: new Date(),
        isStreaming: true,
      };

      setMessages((prev) => [...prev, userMessage, assistantMessage]);
      setIsStreaming(true);

      let streamedContent = '';

      ws.onmessage = (event) => {
        const data = JSON.parse(event.data);

        if (data.type === 'chunk') {
          streamedContent += data.content;
          setMessages((prev) =>
            prev.map((msg) =>
              msg.id === assistantMessage.id
                ? { ...msg, content: streamedContent }
                : msg
            )
          );
        } else if (data.type === 'done') {
          setMessages((prev) =>
            prev.map((msg) =>
              msg.id === assistantMessage.id
                ? { ...msg, isStreaming: false }
                : msg
            )
          );
          setIsStreaming(false);
          if (data.conversation_id) {
            setConversationId(data.conversation_id);
          }
        } else if (data.type === 'sql') {
          // Handle SQL result
          const sqlContent: MessageContent[] = [
            { type: 'text', content: streamedContent },
            { type: 'sql', content: data.sql },
          ];
          setMessages((prev) =>
            prev.map((msg) =>
              msg.id === assistantMessage.id
                ? { ...msg, content: sqlContent, isStreaming: false }
                : msg
            )
          );

          if (data.results) {
            const resultData: QueryResultData = {
              columns: data.columns || Object.keys(data.results[0] || {}),
              rows: data.results,
              totalRows: data.total_rows || data.results.length,
              executionTime: data.execution_time,
              query: data.sql,
            };
            setQueryResult(resultData);
            onQueryResult?.(resultData);
          }
        }
      };

      ws.send(
        JSON.stringify({
          message: messageText,
          conversation_id: conversationId,
          context: contextData,
          language,
        })
      );
    },
    [connectWebSocket, conversationId, contextData, language, onQueryResult]
  );

  const sendMessageRest = useCallback(
    async (messageText: string) => {
      const controller = new AbortController();
      setAbortController(controller);

      const userMessage: Message = {
        id: `user-${Date.now()}`,
        role: 'user',
        content: messageText,
        timestamp: new Date(),
      };

      const loadingMessage: Message = {
        id: `assistant-${Date.now()}`,
        role: 'assistant',
        content: '',
        timestamp: new Date(),
        isStreaming: true,
      };

      setMessages((prev) => [...prev, userMessage, loadingMessage]);
      setIsLoading(true);

      try {
        const response = await fetch(`${config.apiEndpoint}/api/v1/chat`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            message: messageText,
            conversation_id: conversationId,
            context: contextData,
            session_id: config.sessionId,
          }),
          signal: controller.signal,
        });

        if (!response.ok) {
          throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const data = await response.json();

        if (data.success && data.data) {
          const responseData = data.data;
          let content: string | MessageContent[] = responseData.message;

          // If there's a generated query, include it
          if (responseData.generated_query) {
            content = [
              { type: 'text', content: responseData.message },
              { type: 'sql', content: responseData.generated_query },
            ];
          }

          const assistantMessage: Message = {
            id: loadingMessage.id,
            role: 'assistant',
            content,
            timestamp: new Date(),
            queryType: responseData.query_type,
            confidence: responseData.confidence,
          };

          setMessages((prev) =>
            prev.map((msg) =>
              msg.id === loadingMessage.id ? assistantMessage : msg
            )
          );

          if (responseData.conversation_id) {
            setConversationId(responseData.conversation_id);
          }
        } else {
          throw new Error(data.error || 'Unknown error');
        }
      } catch (error) {
        if ((error as Error).name === 'AbortError') {
          setMessages((prev) =>
            prev.map((msg) =>
              msg.id === loadingMessage.id
                ? { ...msg, content: 'Request cancelled.', isStreaming: false }
                : msg
            )
          );
        } else {
          const errorMessage: Message = {
            id: loadingMessage.id,
            role: 'error',
            content: `Error: ${(error as Error).message}`,
            timestamp: new Date(),
          };
          setMessages((prev) =>
            prev.map((msg) =>
              msg.id === loadingMessage.id ? errorMessage : msg
            )
          );
          onError?.(error as Error);
        }
      } finally {
        setIsLoading(false);
        setAbortController(null);
      }
    },
    [config.apiEndpoint, config.sessionId, conversationId, contextData, onError]
  );

  const handleSend = useCallback(async () => {
    const trimmedInput = input.trim();
    if (!trimmedInput || isLoading || isStreaming) return;

    setInput('');

    if (config.streamingEnabled) {
      await sendMessageStreaming(trimmedInput);
    } else {
      await sendMessageRest(trimmedInput);
    }
  }, [input, isLoading, isStreaming, config.streamingEnabled, sendMessageStreaming, sendMessageRest]);

  const handleSuggestionSelect = useCallback((suggestion: Suggestion) => {
    setInput(suggestion.text);
    inputRef.current?.focus();
  }, []);

  const handleStop = useCallback(() => {
    if (abortController) {
      abortController.abort();
    }
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }
    setIsLoading(false);
    setIsStreaming(false);
  }, [abortController]);

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        handleSend();
      }
    },
    [handleSend]
  );

  const handleClearHistory = useCallback(() => {
    const welcomeMsg = language === 'ko' ? KOREAN_SYSTEM_MESSAGE : SYSTEM_MESSAGE;
    setMessages([{ ...welcomeMsg, id: `system-welcome-${Date.now()}` }]);
    setConversationId(null);
    setQueryResult(null);
  }, [language]);

  const toggleLanguage = useCallback(() => {
    setLanguage((prev) => (prev === 'en' ? 'ko' : 'en'));
  }, []);

  return (
    <TooltipProvider>
      <div
        className={cn(
          'flex flex-col bg-background border border-border rounded-lg overflow-hidden',
          isExpanded ? 'h-full' : 'h-[600px]',
          className
        )}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-4 py-3 border-b border-border bg-muted/30 shrink-0">
          <div className="flex items-center gap-2">
            <Sparkles className="h-5 w-5 text-neon-cyan" />
            <h2 className="font-semibold">Security Copilot</h2>
            <span className="text-xs text-muted-foreground">AI Assistant</span>
          </div>
          <div className="flex items-center gap-1">
            <Tooltip>
              <TooltipTrigger asChild>
                <Button variant="ghost" size="icon" className="h-8 w-8" onClick={toggleLanguage}>
                  <Languages className="h-4 w-4" />
                </Button>
              </TooltipTrigger>
              <TooltipContent>
                {language === 'en' ? 'Switch to Korean' : 'Switch to English'}
              </TooltipContent>
            </Tooltip>
            <Tooltip>
              <TooltipTrigger asChild>
                <Button variant="ghost" size="icon" className="h-8 w-8" onClick={handleClearHistory}>
                  <RefreshCw className="h-4 w-4" />
                </Button>
              </TooltipTrigger>
              <TooltipContent>Clear conversation</TooltipContent>
            </Tooltip>
            {onToggleExpand && (
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button variant="ghost" size="icon" className="h-8 w-8" onClick={onToggleExpand}>
                    {isExpanded ? (
                      <Minimize2 className="h-4 w-4" />
                    ) : (
                      <Maximize2 className="h-4 w-4" />
                    )}
                  </Button>
                </TooltipTrigger>
                <TooltipContent>{isExpanded ? 'Minimize' : 'Expand'}</TooltipContent>
              </Tooltip>
            )}
          </div>
        </div>

        {/* Messages */}
        <ScrollArea className="flex-1">
          <div className="py-4">
            {messages.map((message) => (
              <MessageBubble key={message.id} message={message} />
            ))}
            <div ref={scrollRef} />
          </div>
        </ScrollArea>

        {/* Query Result (if any) */}
        {queryResult && (
          <div className="px-4 py-2 border-t border-border shrink-0">
            <QueryResult data={queryResult} maxHeight="200px" />
          </div>
        )}

        {/* Suggestions */}
        {messages.length <= 2 && (
          <div className="px-4 py-3 border-t border-border shrink-0">
            <SuggestionChips
              suggestions={suggestions}
              onSelect={handleSuggestionSelect}
              title={language === 'ko' ? '빠른 시작' : 'Quick suggestions'}
            />
          </div>
        )}

        {/* Input */}
        <div className="p-4 border-t border-border shrink-0">
          <div className="flex items-end gap-2">
            <div className="flex-1 relative">
              <textarea
                ref={inputRef}
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={handleKeyDown}
                placeholder={
                  language === 'ko'
                    ? '질문을 입력하세요... (예: 오늘 발생한 심각한 경보 보여줘)'
                    : 'Ask a question... (e.g., Show me critical alerts from today)'
                }
                className={cn(
                  'w-full resize-none rounded-lg border border-input bg-background px-4 py-3 pr-12',
                  'text-sm placeholder:text-muted-foreground',
                  'focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent',
                  'min-h-[48px] max-h-[120px]',
                  'transition-all duration-200'
                )}
                rows={1}
                disabled={isLoading || isStreaming}
              />
              <div className="absolute right-2 bottom-2 flex items-center gap-1">
                {(isLoading || isStreaming) && (
                  <Button
                    variant="ghost"
                    size="icon"
                    className="h-8 w-8 text-destructive"
                    onClick={handleStop}
                  >
                    <StopCircle className="h-4 w-4" />
                  </Button>
                )}
              </div>
            </div>
            <Button
              size="icon"
              className="h-12 w-12 shrink-0"
              onClick={handleSend}
              disabled={!input.trim() || isLoading || isStreaming}
            >
              <Send className="h-5 w-5" />
            </Button>
          </div>
          <p className="text-xs text-muted-foreground mt-2 text-center">
            {language === 'ko'
              ? 'Shift+Enter로 줄바꿈, Enter로 전송'
              : 'Shift+Enter for new line, Enter to send'}
          </p>
        </div>
      </div>
    </TooltipProvider>
  );
}
