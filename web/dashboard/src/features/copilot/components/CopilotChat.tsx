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
  mockMode?: boolean; // Enable mock responses when backend is unavailable
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

// Mock responses for demo mode
const MOCK_RESPONSES: Record<string, { text: string; sql?: string; data?: QueryResultData }> = {
  'critical alerts': {
    text: 'Here are the critical alerts from today. I found **5 critical alerts** that require immediate attention.',
    sql: 'SELECT * FROM alerts WHERE severity = \'critical\' AND created_at >= NOW() - INTERVAL \'1 day\' ORDER BY created_at DESC LIMIT 10',
    data: {
      columns: ['id', 'severity', 'source', 'message', 'timestamp'],
      rows: [
        { id: 'ALT-001', severity: 'critical', source: 'Firewall', message: 'Potential DDoS attack detected', timestamp: '2024-01-15 14:30:00' },
        { id: 'ALT-002', severity: 'critical', source: 'IDS', message: 'SQL injection attempt blocked', timestamp: '2024-01-15 14:25:00' },
        { id: 'ALT-003', severity: 'critical', source: 'EDR', message: 'Ransomware behavior detected', timestamp: '2024-01-15 14:20:00' },
        { id: 'ALT-004', severity: 'critical', source: 'SIEM', message: 'Brute force attack on admin account', timestamp: '2024-01-15 14:15:00' },
        { id: 'ALT-005', severity: 'critical', source: 'WAF', message: 'XSS attack pattern detected', timestamp: '2024-01-15 14:10:00' },
      ],
      totalRows: 5,
      executionTime: 0.023,
      query: 'SELECT * FROM alerts WHERE severity = \'critical\'',
    },
  },
  'playbook': {
    text: 'Based on the current context, I recommend the following playbooks:\n\n' +
      '1. **Malware Containment** - Isolate affected endpoints and block malicious IPs\n' +
      '2. **Incident Response** - Collect evidence and notify stakeholders\n' +
      '3. **Threat Hunting** - Search for similar IOCs across the environment\n\n' +
      'Would you like me to execute any of these playbooks?',
  },
  'summarize': {
    text: '## Incident Summary\n\n' +
      '**Incident ID:** INC-2024-0115\n' +
      '**Severity:** Critical\n' +
      '**Status:** In Progress\n\n' +
      '### Key Findings:\n' +
      '- **Attack Vector:** Phishing email with malicious attachment\n' +
      '- **Affected Systems:** 3 workstations, 1 server\n' +
      '- **Data at Risk:** Customer PII (estimated 500 records)\n\n' +
      '### Timeline:\n' +
      '- 14:00 - Initial phishing email received\n' +
      '- 14:15 - User opened attachment\n' +
      '- 14:20 - Malware executed, lateral movement detected\n' +
      '- 14:30 - SIEM alert triggered\n\n' +
      '### Recommended Actions:\n' +
      '1. Isolate affected systems\n' +
      '2. Reset compromised credentials\n' +
      '3. Notify legal and compliance teams',
  },
  'default': {
    text: 'I understand your request. Let me analyze that for you.\n\n' +
      'This is a **demo mode** response. In production, I would:\n' +
      '- Query the security data lake\n' +
      '- Analyze patterns using ML models\n' +
      '- Provide actionable recommendations\n\n' +
      'Try asking about:\n' +
      '- "Show critical alerts"\n' +
      '- "Recommend playbooks"\n' +
      '- "Summarize this incident"',
  },
};

const MOCK_RESPONSES_KO: Record<string, { text: string; sql?: string; data?: QueryResultData }> = {
  '심각한 경보': {
    text: '오늘의 심각한 경보를 조회했습니다. **5건의 심각한 경보**가 즉시 조치가 필요합니다.',
    sql: 'SELECT * FROM alerts WHERE severity = \'critical\' AND created_at >= NOW() - INTERVAL \'1 day\' ORDER BY created_at DESC LIMIT 10',
    data: {
      columns: ['id', 'severity', 'source', 'message', 'timestamp'],
      rows: [
        { id: 'ALT-001', severity: 'critical', source: 'Firewall', message: 'DDoS 공격 감지', timestamp: '2024-01-15 14:30:00' },
        { id: 'ALT-002', severity: 'critical', source: 'IDS', message: 'SQL 인젝션 시도 차단', timestamp: '2024-01-15 14:25:00' },
        { id: 'ALT-003', severity: 'critical', source: 'EDR', message: '랜섬웨어 행위 감지', timestamp: '2024-01-15 14:20:00' },
        { id: 'ALT-004', severity: 'critical', source: 'SIEM', message: '관리자 계정 무차별 대입 공격', timestamp: '2024-01-15 14:15:00' },
        { id: 'ALT-005', severity: 'critical', source: 'WAF', message: 'XSS 공격 패턴 감지', timestamp: '2024-01-15 14:10:00' },
      ],
      totalRows: 5,
      executionTime: 0.023,
      query: 'SELECT * FROM alerts WHERE severity = \'critical\'',
    },
  },
  '플레이북': {
    text: '현재 상황에 맞는 플레이북을 추천드립니다:\n\n' +
      '1. **악성코드 격리** - 영향받은 엔드포인트 격리 및 악성 IP 차단\n' +
      '2. **인시던트 대응** - 증거 수집 및 이해관계자 알림\n' +
      '3. **위협 헌팅** - 환경 전체에서 유사 IOC 검색\n\n' +
      '이 중 어떤 플레이북을 실행할까요?',
  },
  '요약': {
    text: '## 인시던트 요약\n\n' +
      '**인시던트 ID:** INC-2024-0115\n' +
      '**심각도:** 심각\n' +
      '**상태:** 진행 중\n\n' +
      '### 주요 발견 사항:\n' +
      '- **공격 벡터:** 악성 첨부파일이 포함된 피싱 이메일\n' +
      '- **영향받은 시스템:** 워크스테이션 3대, 서버 1대\n' +
      '- **위험에 처한 데이터:** 고객 개인정보 (약 500건)\n\n' +
      '### 권장 조치:\n' +
      '1. 영향받은 시스템 격리\n' +
      '2. 침해된 자격 증명 재설정\n' +
      '3. 법무 및 컴플라이언스 팀에 알림',
  },
  'default': {
    text: '요청을 이해했습니다. 분석을 진행하겠습니다.\n\n' +
      '현재 **데모 모드**로 실행 중입니다. 실제 환경에서는:\n' +
      '- 보안 데이터 레이크를 쿼리하고\n' +
      '- ML 모델로 패턴을 분석하며\n' +
      '- 실행 가능한 권장 사항을 제공합니다.\n\n' +
      '다음과 같은 질문을 해보세요:\n' +
      '- "심각한 경보 보여줘"\n' +
      '- "플레이북 추천해줘"\n' +
      '- "이 인시던트 요약해줘"',
  },
};

function getMockResponse(
  message: string,
  language: 'en' | 'ko',
  contextData?: Record<string, unknown>
): { text: string; sql?: string; data?: QueryResultData } {
  const lowerMessage = message.toLowerCase();
  const defaultResponse = { text: 'I understand your request. How can I help you further?' };

  // If we have alert context, generate context-aware responses
  if (contextData?.alertId) {
    const alertId = contextData.alertId as string;
    const alertTitle = contextData.alertTitle as string || 'Unknown Alert';
    const alertDescription = contextData.alertDescription as string || contextData.description as string || '';
    const severity = contextData.severity as string || 'unknown';
    const status = contextData.status as string || 'unknown';
    const source = contextData.source as string || 'Unknown';
    const target = contextData.target as string || '';
    const fields = contextData.fields as Record<string, unknown> || {};
    // Handle both naming conventions (mitreTactics/mitreTechniques and tactic/technique)
    const mitreTactics = contextData.mitreTactics as string[] || (contextData.tactic ? [contextData.tactic as string] : []);
    const mitreTechniques = contextData.mitreTechniques as string[] || (contextData.technique ? [contextData.technique as string] : []);

    // Check for summarize/incident keywords
    if (lowerMessage.includes('summarize') || lowerMessage.includes('summary') ||
        lowerMessage.includes('incident') || lowerMessage.includes('요약') ||
        lowerMessage.includes('인시던트')) {
      if (language === 'ko') {
        return {
          text: `## 인시던트 요약\n\n` +
            `**Alert ID:** ${alertId}\n` +
            `**제목:** ${alertTitle}\n` +
            `**심각도:** ${severity.toUpperCase()}\n` +
            `**상태:** ${status}\n` +
            `**소스:** ${source}\n` +
            (target ? `**대상:** ${target}\n` : '') +
            (mitreTechniques.length > 0 ? `**MITRE ATT&CK:** ${mitreTechniques.join(', ')}\n` : '') +
            (alertDescription ? `\n### 설명\n${alertDescription}\n` : '') +
            `\n### 주요 발견 사항:\n` +
            `- 해당 이벤트는 ${source}에서 탐지되었습니다\n` +
            `- 심각도 **${severity.toUpperCase()}** 수준의 보안 위협으로 분류됩니다\n` +
            (target ? `- 대상 시스템/사용자: ${target}\n` : '') +
            (fields.src_ip ? `- 출발지 IP: ${fields.src_ip}\n` : '') +
            (fields.dst_ip ? `- 목적지 IP: ${fields.dst_ip}\n` : '') +
            (fields.user ? `- 관련 사용자: ${fields.user}\n` : '') +
            (fields.hostname ? `- 호스트: ${fields.hostname}\n` : '') +
            `\n### 권장 조치:\n` +
            `1. 해당 이벤트의 상세 로그를 확인하세요\n` +
            `2. 관련 자산의 취약점 여부를 점검하세요\n` +
            `3. 필요시 플레이북을 실행하여 대응하세요`,
        };
      } else {
        return {
          text: `## Incident Summary\n\n` +
            `**Alert ID:** ${alertId}\n` +
            `**Title:** ${alertTitle}\n` +
            `**Severity:** ${severity.toUpperCase()}\n` +
            `**Status:** ${status}\n` +
            `**Source:** ${source}\n` +
            (target ? `**Target:** ${target}\n` : '') +
            (mitreTechniques.length > 0 ? `**MITRE ATT&CK:** ${mitreTechniques.join(', ')}\n` : '') +
            (alertDescription ? `\n### Description\n${alertDescription}\n` : '') +
            `\n### Key Findings:\n` +
            `- This event was detected from ${source}\n` +
            `- Classified as **${severity.toUpperCase()}** severity security threat\n` +
            (target ? `- Target system/user: ${target}\n` : '') +
            (fields.src_ip ? `- Source IP: ${fields.src_ip}\n` : '') +
            (fields.dst_ip ? `- Destination IP: ${fields.dst_ip}\n` : '') +
            (fields.user ? `- Related User: ${fields.user}\n` : '') +
            (fields.hostname ? `- Host: ${fields.hostname}\n` : '') +
            `\n### Recommended Actions:\n` +
            `1. Review detailed logs for this event\n` +
            `2. Check for vulnerabilities on related assets\n` +
            `3. Execute relevant playbooks if needed`,
        };
      }
    }

    // Check for playbook/recommend keywords
    if (lowerMessage.includes('playbook') || lowerMessage.includes('recommend') ||
        lowerMessage.includes('플레이북') || lowerMessage.includes('추천')) {
      if (language === 'ko') {
        return {
          text: `**${alertTitle}** 이벤트에 대해 다음 플레이북을 추천합니다:\n\n` +
            `1. **IP Reputation Check** - 관련 IP의 평판 조회\n` +
            `2. **Block IP on Firewall** - 악성 IP 차단\n` +
            (severity === 'critical' || severity === 'high'
              ? `3. **Isolate Endpoint** - 영향받은 엔드포인트 격리\n` +
                `4. **Send Slack Alert** - 보안 팀에 알림 전송\n`
              : `3. **Create Jira Ticket** - 추적을 위한 티켓 생성\n`) +
            `\n이 중 어떤 플레이북을 실행할까요? Quick Actions에서 직접 실행할 수도 있습니다.`,
        };
      } else {
        return {
          text: `Based on **${alertTitle}**, I recommend these playbooks:\n\n` +
            `1. **IP Reputation Check** - Check reputation of related IPs\n` +
            `2. **Block IP on Firewall** - Block malicious IP addresses\n` +
            (severity === 'critical' || severity === 'high'
              ? `3. **Isolate Endpoint** - Isolate affected endpoints\n` +
                `4. **Send Slack Alert** - Notify security team\n`
              : `3. **Create Jira Ticket** - Create ticket for tracking\n`) +
            `\nWould you like to execute any of these? You can also run them from Quick Actions.`,
        };
      }
    }

    // Check for analysis/investigate keywords
    if (lowerMessage.includes('analyze') || lowerMessage.includes('investigate') ||
        lowerMessage.includes('분석') || lowerMessage.includes('조사')) {
      if (language === 'ko') {
        return {
          text: `## ${alertTitle} 분석 결과\n\n` +
            `### 이벤트 상세\n` +
            `- **Alert ID:** ${alertId}\n` +
            `- **심각도:** ${severity.toUpperCase()}\n` +
            `- **상태:** ${status}\n` +
            `- **탐지 소스:** ${source}\n\n` +
            (mitreTactics.length > 0 ? `### MITRE ATT&CK 매핑\n` +
              `- **전술:** ${mitreTactics.join(', ')}\n` +
              `- **기법:** ${mitreTechniques.join(', ')}\n\n` : '') +
            `### 관련 지표 (IoC)\n` +
            (fields.src_ip ? `- 출발지 IP: \`${fields.src_ip}\`\n` : '') +
            (fields.dst_ip ? `- 목적지 IP: \`${fields.dst_ip}\`\n` : '') +
            (fields.hash ? `- 파일 해시: \`${fields.hash}\`\n` : '') +
            (fields.domain ? `- 도메인: \`${fields.domain}\`\n` : '') +
            `\n### 분석 권장사항\n` +
            `1. TI(Threat Intelligence) 소스에서 IoC 조회\n` +
            `2. 관련 시스템에서 유사 활동 검색\n` +
            `3. 타임라인 분석을 통한 공격 경로 파악`,
        };
      } else {
        return {
          text: `## Analysis: ${alertTitle}\n\n` +
            `### Event Details\n` +
            `- **Alert ID:** ${alertId}\n` +
            `- **Severity:** ${severity.toUpperCase()}\n` +
            `- **Status:** ${status}\n` +
            `- **Detection Source:** ${source}\n\n` +
            (mitreTactics.length > 0 ? `### MITRE ATT&CK Mapping\n` +
              `- **Tactics:** ${mitreTactics.join(', ')}\n` +
              `- **Techniques:** ${mitreTechniques.join(', ')}\n\n` : '') +
            `### Indicators of Compromise (IoC)\n` +
            (fields.src_ip ? `- Source IP: \`${fields.src_ip}\`\n` : '') +
            (fields.dst_ip ? `- Destination IP: \`${fields.dst_ip}\`\n` : '') +
            (fields.hash ? `- File Hash: \`${fields.hash}\`\n` : '') +
            (fields.domain ? `- Domain: \`${fields.domain}\`\n` : '') +
            `\n### Recommended Analysis Steps\n` +
            `1. Query IoCs against Threat Intelligence sources\n` +
            `2. Search for similar activity on related systems\n` +
            `3. Perform timeline analysis to understand attack path`,
        };
      }
    }

    // Default context-aware response
    if (language === 'ko') {
      return {
        text: `**${alertTitle}** 이벤트에 대해 도움을 드리겠습니다.\n\n` +
          `현재 분석 중인 이벤트:\n` +
          `- **ID:** ${alertId}\n` +
          `- **심각도:** ${severity.toUpperCase()}\n` +
          `- **소스:** ${source}\n\n` +
          `다음 질문을 해보세요:\n` +
          `- "이 인시던트 요약해줘"\n` +
          `- "플레이북 추천해줘"\n` +
          `- "이 이벤트 분석해줘"`,
      };
    } else {
      return {
        text: `I'll help you with **${alertTitle}**.\n\n` +
          `Current event under analysis:\n` +
          `- **ID:** ${alertId}\n` +
          `- **Severity:** ${severity.toUpperCase()}\n` +
          `- **Source:** ${source}\n\n` +
          `Try asking:\n` +
          `- "Summarize this incident"\n` +
          `- "Recommend playbooks"\n` +
          `- "Analyze this event"`,
      };
    }
  }

  // Fallback to generic responses when no context
  // Check for critical/alert keywords (both languages)
  if (lowerMessage.includes('critical') || lowerMessage.includes('alert') ||
      lowerMessage.includes('심각') || lowerMessage.includes('경보')) {
    const response = language === 'ko' ? MOCK_RESPONSES_KO['심각한 경보'] : MOCK_RESPONSES['critical alerts'];
    return response || defaultResponse;
  }

  // Check for playbook/recommend keywords
  if (lowerMessage.includes('playbook') || lowerMessage.includes('recommend') ||
      lowerMessage.includes('플레이북') || lowerMessage.includes('추천')) {
    const response = language === 'ko' ? MOCK_RESPONSES_KO['플레이북'] : MOCK_RESPONSES['playbook'];
    return response || defaultResponse;
  }

  // Check for summarize/incident keywords
  if (lowerMessage.includes('summarize') || lowerMessage.includes('summary') ||
      lowerMessage.includes('incident') || lowerMessage.includes('요약') ||
      lowerMessage.includes('인시던트')) {
    const response = language === 'ko' ? MOCK_RESPONSES_KO['요약'] : MOCK_RESPONSES['summarize'];
    return response || defaultResponse;
  }

  // Default response
  const response = language === 'ko' ? MOCK_RESPONSES_KO['default'] : MOCK_RESPONSES['default'];
  return response || defaultResponse;
}

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
        const response = await fetch(`${config.apiEndpoint}/v1/chat`, {
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
          const errorMessage = (error as Error).message;
          console.error('API error:', errorMessage);

          // Show error message to user instead of silently falling back to mock
          const errorResponse: Message = {
            id: loadingMessage.id,
            role: 'assistant',
            content: `**Connection Error**\n\nUnable to connect to the AI backend service.\n\n**Error:** ${errorMessage}\n\n**Troubleshooting:**\n- Ensure the copilot service is running\n- Check network connectivity\n- Verify API endpoint configuration\n\nPlease contact your administrator if the issue persists.`,
            timestamp: new Date(),
            isStreaming: false,
          };

          setMessages((prev) =>
            prev.map((msg) =>
              msg.id === loadingMessage.id ? errorResponse : msg
            )
          );

          onError?.(new Error(`API connection failed: ${errorMessage}`));
        }
      } finally {
        setIsLoading(false);
        setAbortController(null);
      }
    },
    [config.apiEndpoint, config.sessionId, conversationId, contextData, onError, language, onQueryResult]
  );

  // Mock mode message handler
  const sendMessageMock = useCallback(
    async (messageText: string) => {
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

      // Simulate network delay
      await new Promise((resolve) => setTimeout(resolve, 800 + Math.random() * 700));

      const mockResponse = getMockResponse(messageText, language, contextData);

      let content: string | MessageContent[] = mockResponse.text;
      if (mockResponse.sql) {
        content = [
          { type: 'text', content: mockResponse.text },
          { type: 'sql', content: mockResponse.sql },
        ];
      }

      const assistantMessage: Message = {
        id: loadingMessage.id,
        role: 'assistant',
        content,
        timestamp: new Date(),
        queryType: mockResponse.sql ? 'search' : 'chat',
        confidence: 0.95,
      };

      setMessages((prev) =>
        prev.map((msg) =>
          msg.id === loadingMessage.id ? assistantMessage : msg
        )
      );

      if (mockResponse.data) {
        setQueryResult(mockResponse.data);
        onQueryResult?.(mockResponse.data);
      }

      setIsLoading(false);
    },
    [language, contextData, onQueryResult]
  );

  const handleSend = useCallback(async () => {
    const trimmedInput = input.trim();
    if (!trimmedInput || isLoading || isStreaming) return;

    setInput('');

    // Use mock mode if enabled
    if (config.mockMode) {
      await sendMessageMock(trimmedInput);
      return;
    }

    if (config.streamingEnabled) {
      await sendMessageStreaming(trimmedInput);
    } else {
      await sendMessageRest(trimmedInput);
    }
  }, [input, isLoading, isStreaming, config.mockMode, config.streamingEnabled, sendMessageMock, sendMessageStreaming, sendMessageRest]);

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
