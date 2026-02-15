/**
 * CopilotSidebar - Side panel for context, history, and quick actions.
 */
import { memo, useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Separator } from '@/components/ui/separator';
import { cn } from '@/lib/utils';
import {
  History,
  Bookmark,
  Trash2,
  ChevronRight,
  Clock,
  MessageSquare,
  AlertCircle,
  FileText,
  Database,
  Shield,
  X,
  Plus,
  Search,
} from 'lucide-react';
import { Input } from '@/components/ui/input';

export interface ConversationHistoryItem {
  id: string;
  title: string;
  preview: string;
  timestamp: Date;
  messageCount: number;
}

export interface ContextItem {
  id: string;
  type: 'alert' | 'case' | 'event' | 'query_result' | 'playbook';
  title: string;
  data: Record<string, unknown>;
  addedAt: Date;
}

export interface SavedQuery {
  id: string;
  name: string;
  query: string;
  createdAt: Date;
}

interface CopilotSidebarProps {
  conversations: ConversationHistoryItem[];
  contextItems: ContextItem[];
  savedQueries: SavedQuery[];
  currentConversationId?: string;
  onSelectConversation: (id: string) => void;
  onNewConversation: () => void;
  onDeleteConversation: (id: string) => void;
  onRemoveContext: (id: string) => void;
  onClearContext: () => void;
  onSelectSavedQuery: (query: SavedQuery) => void;
  onDeleteSavedQuery: (id: string) => void;
  className?: string;
}

const contextTypeIcons = {
  alert: AlertCircle,
  case: FileText,
  event: Database,
  query_result: Search,
  playbook: Shield,
};

const contextTypeLabels = {
  alert: 'Alert',
  case: 'Case',
  event: 'Event',
  query_result: 'Query',
  playbook: 'Playbook',
};

function CopilotSidebarComponent({
  conversations,
  contextItems,
  savedQueries,
  currentConversationId,
  onSelectConversation,
  onNewConversation,
  onDeleteConversation,
  onRemoveContext,
  onClearContext,
  onSelectSavedQuery,
  onDeleteSavedQuery,
  className,
}: CopilotSidebarProps) {
  const [searchQuery, setSearchQuery] = useState('');
  const [activeTab, setActiveTab] = useState('history');

  const filteredConversations = conversations.filter(
    (conv) =>
      conv.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      conv.preview.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const filteredQueries = savedQueries.filter(
    (q) =>
      q.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      q.query.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const formatRelativeTime = (date: Date): string => {
    const now = new Date();
    const diff = now.getTime() - date.getTime();
    const minutes = Math.floor(diff / 60000);
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);

    if (minutes < 1) return 'Just now';
    if (minutes < 60) return `${minutes}m ago`;
    if (hours < 24) return `${hours}h ago`;
    if (days < 7) return `${days}d ago`;
    return date.toLocaleDateString('ko-KR');
  };

  return (
    <div className={cn('flex flex-col h-full', className)}>
      {/* Header */}
      <div className="p-4 border-b border-border shrink-0">
        <div className="flex items-center justify-between mb-3">
          <h2 className="font-semibold">Copilot</h2>
          <Button variant="outline" size="sm" onClick={onNewConversation}>
            <Plus className="h-4 w-4 mr-1" />
            New Chat
          </Button>
        </div>
        <div className="relative">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="pl-8 h-9"
          />
        </div>
      </div>

      {/* Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab} className="flex-1 flex flex-col min-h-0">
        <div className="px-2 pt-2 shrink-0">
          <TabsList className="w-full grid grid-cols-3">
            <TabsTrigger value="history" className="text-xs">
              <History className="h-3.5 w-3.5 mr-1" />
              History
            </TabsTrigger>
            <TabsTrigger value="context" className="text-xs">
              <FileText className="h-3.5 w-3.5 mr-1" />
              Context
              {contextItems.length > 0 && (
                <Badge variant="secondary" className="ml-1 px-1 py-0 text-[10px]">
                  {contextItems.length}
                </Badge>
              )}
            </TabsTrigger>
            <TabsTrigger value="saved" className="text-xs">
              <Bookmark className="h-3.5 w-3.5 mr-1" />
              Saved
            </TabsTrigger>
          </TabsList>
        </div>

        {/* History Tab */}
        <TabsContent value="history" className="flex-1 m-0 mt-2 min-h-0">
          <ScrollArea className="h-full px-2">
            {filteredConversations.length > 0 ? (
              <div className="space-y-1 pb-4">
                {filteredConversations.map((conv) => (
                  <div
                    key={conv.id}
                    className={cn(
                      'group flex items-start gap-2 p-2.5 rounded-lg cursor-pointer transition-colors',
                      currentConversationId === conv.id
                        ? 'bg-primary/10 border border-primary/30'
                        : 'hover:bg-muted/50'
                    )}
                    onClick={() => onSelectConversation(conv.id)}
                  >
                    <MessageSquare className="h-4 w-4 mt-0.5 shrink-0 text-muted-foreground" />
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium truncate">{conv.title}</p>
                      <p className="text-xs text-muted-foreground truncate mt-0.5">
                        {conv.preview}
                      </p>
                      <div className="flex items-center gap-2 mt-1 text-xs text-muted-foreground">
                        <Clock className="h-3 w-3" />
                        {formatRelativeTime(conv.timestamp)}
                        <span className="text-[10px]">{conv.messageCount} messages</span>
                      </div>
                    </div>
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        onDeleteConversation(conv.id);
                      }}
                      className="opacity-0 group-hover:opacity-100 p-1 hover:bg-destructive/10 rounded transition-all"
                    >
                      <Trash2 className="h-3.5 w-3.5 text-muted-foreground hover:text-destructive" />
                    </button>
                  </div>
                ))}
              </div>
            ) : (
              <div className="flex flex-col items-center justify-center h-32 text-muted-foreground">
                <MessageSquare className="h-8 w-8 mb-2 opacity-30" />
                <p className="text-sm">No conversations</p>
                <p className="text-xs">Start a new chat to begin</p>
              </div>
            )}
          </ScrollArea>
        </TabsContent>

        {/* Context Tab */}
        <TabsContent value="context" className="flex-1 m-0 mt-2 min-h-0">
          <div className="px-2">
            {contextItems.length > 0 && (
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs text-muted-foreground">
                  {contextItems.length} item{contextItems.length !== 1 ? 's' : ''} in context
                </span>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={onClearContext}
                  className="h-7 text-xs text-muted-foreground hover:text-destructive"
                >
                  Clear all
                </Button>
              </div>
            )}
          </div>
          <ScrollArea className="h-full px-2">
            {contextItems.length > 0 ? (
              <div className="space-y-2 pb-4">
                {contextItems.map((item) => {
                  const IconComponent = contextTypeIcons[item.type];
                  return (
                    <div
                      key={item.id}
                      className="group flex items-start gap-2 p-2.5 rounded-lg bg-muted/30 border border-border"
                    >
                      <div className="p-1.5 rounded bg-muted shrink-0">
                        <IconComponent className="h-3.5 w-3.5 text-muted-foreground" />
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <p className="text-sm font-medium truncate">{item.title}</p>
                          <Badge variant="outline" className="text-[10px] px-1 py-0">
                            {contextTypeLabels[item.type]}
                          </Badge>
                        </div>
                        <p className="text-xs text-muted-foreground mt-0.5">
                          Added {formatRelativeTime(item.addedAt)}
                        </p>
                      </div>
                      <button
                        onClick={() => onRemoveContext(item.id)}
                        className="opacity-0 group-hover:opacity-100 p-1 hover:bg-destructive/10 rounded transition-all"
                      >
                        <X className="h-3.5 w-3.5 text-muted-foreground hover:text-destructive" />
                      </button>
                    </div>
                  );
                })}
              </div>
            ) : (
              <div className="flex flex-col items-center justify-center h-32 text-muted-foreground">
                <FileText className="h-8 w-8 mb-2 opacity-30" />
                <p className="text-sm">No context items</p>
                <p className="text-xs text-center px-4">
                  View an alert or case to add context
                </p>
              </div>
            )}
          </ScrollArea>
        </TabsContent>

        {/* Saved Queries Tab */}
        <TabsContent value="saved" className="flex-1 m-0 mt-2 min-h-0">
          <ScrollArea className="h-full px-2">
            {filteredQueries.length > 0 ? (
              <div className="space-y-1 pb-4">
                {filteredQueries.map((query) => (
                  <div
                    key={query.id}
                    className="group flex items-start gap-2 p-2.5 rounded-lg hover:bg-muted/50 cursor-pointer transition-colors"
                    onClick={() => onSelectSavedQuery(query)}
                  >
                    <Database className="h-4 w-4 mt-0.5 shrink-0 text-neon-cyan" />
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium truncate">{query.name}</p>
                      <p className="text-xs text-muted-foreground font-mono truncate mt-0.5">
                        {query.query}
                      </p>
                    </div>
                    <div className="flex items-center gap-1">
                      <ChevronRight className="h-4 w-4 text-muted-foreground opacity-0 group-hover:opacity-100 transition-opacity" />
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onDeleteSavedQuery(query.id);
                        }}
                        className="opacity-0 group-hover:opacity-100 p-1 hover:bg-destructive/10 rounded transition-all"
                      >
                        <Trash2 className="h-3.5 w-3.5 text-muted-foreground hover:text-destructive" />
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="flex flex-col items-center justify-center h-32 text-muted-foreground">
                <Bookmark className="h-8 w-8 mb-2 opacity-30" />
                <p className="text-sm">No saved queries</p>
                <p className="text-xs">Save queries from chat results</p>
              </div>
            )}
          </ScrollArea>
        </TabsContent>
      </Tabs>

      {/* Footer */}
      <div className="p-3 border-t border-border shrink-0">
        <div className="flex items-center gap-2 text-xs text-muted-foreground">
          <Shield className="h-3.5 w-3.5" />
          <span>Security Copilot v0.2.0</span>
        </div>
      </div>
    </div>
  );
}

export const CopilotSidebar = memo(CopilotSidebarComponent);
