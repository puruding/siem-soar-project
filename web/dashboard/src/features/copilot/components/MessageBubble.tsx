/**
 * MessageBubble - Chat message display component with support for different message types.
 */
import { memo } from 'react';
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar';
import { Badge } from '@/components/ui/badge';
import { cn } from '@/lib/utils';
import {
  Bot,
  User,
  AlertTriangle,
  Database,
  FileText,
  Loader2,
  Copy,
  Check,
} from 'lucide-react';
import { useState } from 'react';

export type MessageRole = 'user' | 'assistant' | 'system' | 'error';

export interface MessageContent {
  type: 'text' | 'sql' | 'code' | 'summary' | 'recommendation';
  content: string;
  language?: string;
  metadata?: Record<string, unknown>;
}

export interface Message {
  id: string;
  role: MessageRole;
  content: string | MessageContent[];
  timestamp: Date;
  isStreaming?: boolean;
  queryType?: string;
  confidence?: number;
}

interface MessageBubbleProps {
  message: Message;
  className?: string;
}

function MessageBubbleComponent({ message, className }: MessageBubbleProps) {
  const [copied, setCopied] = useState(false);
  const isUser = message.role === 'user';
  const isError = message.role === 'error';
  const isSystem = message.role === 'system';

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const renderAvatar = () => {
    if (isUser) {
      return (
        <Avatar className="h-8 w-8 shrink-0">
          <AvatarImage src="/avatars/user.png" alt="User" />
          <AvatarFallback className="bg-primary/20 text-primary">
            <User className="h-4 w-4" />
          </AvatarFallback>
        </Avatar>
      );
    }

    return (
      <Avatar className="h-8 w-8 shrink-0">
        <AvatarFallback
          className={cn(
            'bg-gradient-to-br',
            isError
              ? 'from-destructive/20 to-destructive/10 text-destructive'
              : 'from-neon-cyan/20 to-neon-purple/20 text-neon-cyan'
          )}
        >
          {isError ? (
            <AlertTriangle className="h-4 w-4" />
          ) : (
            <Bot className="h-4 w-4" />
          )}
        </AvatarFallback>
      </Avatar>
    );
  };

  const renderContent = () => {
    if (typeof message.content === 'string') {
      return (
        <div className="prose prose-sm prose-invert max-w-none">
          <p className="whitespace-pre-wrap break-words leading-relaxed">
            {message.content}
            {message.isStreaming && (
              <span className="inline-block w-2 h-4 ml-0.5 bg-neon-cyan animate-pulse" />
            )}
          </p>
        </div>
      );
    }

    return (
      <div className="space-y-3">
        {message.content.map((block, index) => (
          <div key={index}>
            {block.type === 'text' && (
              <p className="whitespace-pre-wrap break-words leading-relaxed">
                {block.content}
              </p>
            )}
            {block.type === 'sql' && (
              <div className="relative group">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2">
                    <Database className="h-4 w-4 text-neon-cyan" />
                    <span className="text-xs font-medium text-muted-foreground">
                      Generated SQL
                    </span>
                  </div>
                  <button
                    onClick={() => copyToClipboard(block.content)}
                    className="opacity-0 group-hover:opacity-100 transition-opacity p-1 hover:bg-muted rounded"
                  >
                    {copied ? (
                      <Check className="h-4 w-4 text-neon-green" />
                    ) : (
                      <Copy className="h-4 w-4 text-muted-foreground" />
                    )}
                  </button>
                </div>
                <pre className="bg-background/50 border border-border rounded-lg p-3 overflow-x-auto">
                  <code className="text-sm font-mono text-neon-cyan">
                    {block.content}
                  </code>
                </pre>
              </div>
            )}
            {block.type === 'code' && (
              <div className="relative group">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs font-medium text-muted-foreground">
                    {block.language || 'Code'}
                  </span>
                  <button
                    onClick={() => copyToClipboard(block.content)}
                    className="opacity-0 group-hover:opacity-100 transition-opacity p-1 hover:bg-muted rounded"
                  >
                    {copied ? (
                      <Check className="h-4 w-4 text-neon-green" />
                    ) : (
                      <Copy className="h-4 w-4 text-muted-foreground" />
                    )}
                  </button>
                </div>
                <pre className="bg-background/50 border border-border rounded-lg p-3 overflow-x-auto">
                  <code className="text-sm font-mono">{block.content}</code>
                </pre>
              </div>
            )}
            {block.type === 'summary' && (
              <div className="bg-muted/30 border border-border rounded-lg p-4">
                <div className="flex items-center gap-2 mb-2">
                  <FileText className="h-4 w-4 text-neon-purple" />
                  <span className="text-sm font-medium">Summary</span>
                </div>
                <p className="text-sm leading-relaxed">{block.content}</p>
              </div>
            )}
            {block.type === 'recommendation' && (
              <div className="bg-neon-green/5 border border-neon-green/20 rounded-lg p-4">
                <div className="flex items-center gap-2 mb-2">
                  <AlertTriangle className="h-4 w-4 text-neon-green" />
                  <span className="text-sm font-medium text-neon-green">
                    Recommendation
                  </span>
                </div>
                <p className="text-sm leading-relaxed">{block.content}</p>
              </div>
            )}
          </div>
        ))}
      </div>
    );
  };

  if (isSystem) {
    return (
      <div
        className={cn(
          'flex justify-center py-2',
          className
        )}
      >
        <div className="px-4 py-1.5 bg-muted/30 rounded-full text-xs text-muted-foreground">
          {typeof message.content === 'string' ? message.content : ''}
        </div>
      </div>
    );
  }

  return (
    <div
      className={cn(
        'flex gap-3 px-4 py-3 animate-fade-in',
        isUser ? 'flex-row-reverse' : 'flex-row',
        className
      )}
    >
      {renderAvatar()}

      <div
        className={cn(
          'flex flex-col gap-1 max-w-[80%]',
          isUser ? 'items-end' : 'items-start'
        )}
      >
        <div
          className={cn(
            'rounded-2xl px-4 py-2.5 text-sm',
            isUser
              ? 'bg-primary text-primary-foreground rounded-br-md'
              : isError
                ? 'bg-destructive/10 border border-destructive/20 text-destructive rounded-bl-md'
                : 'bg-muted/50 border border-border rounded-bl-md'
          )}
        >
          {message.isStreaming && !message.content ? (
            <div className="flex items-center gap-2">
              <Loader2 className="h-4 w-4 animate-spin" />
              <span className="text-muted-foreground">Thinking...</span>
            </div>
          ) : (
            renderContent()
          )}
        </div>

        <div className="flex items-center gap-2 px-1">
          <span className="text-xs text-muted-foreground">
            {formatTime(message.timestamp)}
          </span>
          {message.queryType && (
            <Badge variant="outline" className="text-xs py-0">
              {message.queryType}
            </Badge>
          )}
          {message.confidence !== undefined && (
            <span className="text-xs text-muted-foreground">
              {Math.round(message.confidence * 100)}% confidence
            </span>
          )}
        </div>
      </div>
    </div>
  );
}

function formatTime(date: Date): string {
  return new Intl.DateTimeFormat('ko-KR', {
    hour: '2-digit',
    minute: '2-digit',
  }).format(date);
}

export const MessageBubble = memo(MessageBubbleComponent);
