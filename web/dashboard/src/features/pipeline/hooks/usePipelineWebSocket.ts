import { useEffect, useRef, useCallback, useState } from 'react';
import { usePipelineStore } from '../stores/pipelineStore';
import {
  PipelineEvent,
  Classification,
  ApprovalInfo,
  AuditLog,
  PipelineStats,
} from '../types/pipeline';
import { fetchInitialPipelineData, PipelineStatus, ThroughputData, PipelineErrorsResponse } from '../api/pipelineApi';

interface WebSocketMessage {
  type: 'pipeline_event' | 'event' | 'classification' | 'playbook' | 'execution' | 'approval' | 'audit' | 'stats';
  action?: 'create' | 'update' | 'delete';
  stage?: 'event_receive' | 'classification' | 'playbook_select' | 'flow_execution';
  alert_id?: string;
  data?: Record<string, unknown>;
  payload?: unknown;
  timestamp: string;
}

export interface InitialPipelineData {
  status: PipelineStatus | null;
  throughput: ThroughputData | null;
  errors: PipelineErrorsResponse | null;
  isLoading: boolean;
  error: string | null;
}

export const usePipelineWebSocket = (tenantId: string) => {
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectAttempts = useRef(0);
  const maxReconnectAttempts = 5;

  // Initial data loading state
  const [initialData, setInitialData] = useState<InitialPipelineData>({
    status: null,
    throughput: null,
    errors: null,
    isLoading: true,
    error: null,
  });

  const {
    setConnectionStatus,
    addEvent,
    updateEvent,
    addClassification,
    addApproval,
    updateApproval,
    addAuditLog,
    setStats,
  } = usePipelineStore();

  // Fetch initial data from REST API
  const loadInitialData = useCallback(async () => {
    setInitialData((prev) => ({ ...prev, isLoading: true, error: null }));

    try {
      const { status, throughput, errors } = await fetchInitialPipelineData();

      setInitialData({
        status: status.success ? status.data ?? null : null,
        throughput: throughput.success ? throughput.data ?? null : null,
        errors: errors.success ? errors.data ?? null : null,
        isLoading: false,
        error: null,
      });

      // If we got status data, convert to stats format and update store
      if (status.success && status.data) {
        const pipelineStats: PipelineStats = {
          total_events: status.data.stages.reduce((sum, s) => sum + s.inputEps, 0),
          processed_events: status.data.stages.reduce((sum, s) => sum + s.outputEps, 0),
          auto_classified: 0, // Will be updated via WebSocket
          automation_rate: 100 - status.data.errorRate,
          avg_processing_ms: status.data.stages.reduce((sum, s) => sum + s.lagMs, 0) / status.data.stages.length,
        };
        setStats(pipelineStats);
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to load initial pipeline data';
      setInitialData((prev) => ({
        ...prev,
        isLoading: false,
        error: errorMessage,
      }));
    }
  }, [setStats]);

  const handleMessage = useCallback(
    (message: WebSocketMessage) => {
      // Handle pipeline_event from Pipeline Orchestrator
      if (message.type === 'pipeline_event' && message.stage && message.alert_id && message.data) {
        const eventId = message.alert_id;
        const data = message.data;

        switch (message.stage) {
          case 'event_receive': {
            const event: PipelineEvent = {
              id: eventId,
              tenant_id: 'default',
              raw_log: '',
              source: String(data.source || 'Detection'),
              severity: String(data.severity || 'medium') as 'critical' | 'high' | 'medium' | 'low',
              stage: 'event_receive',
              created_at: message.timestamp,
            };
            addEvent(event);
            addAuditLog({
              id: `audit-${Date.now()}`,
              event_type: 'event_receive',
              actor_type: 'SYSTEM',
              actor_id: 'detection-service',
              message: `Alert received: ${data.source}`,
              created_at: message.timestamp,
            });
            break;
          }

          case 'classification': {
            updateEvent(eventId, { stage: 'classification' });
            const classification: Classification = {
              id: `cls-${Date.now()}`,
              event_id: eventId,
              label: String(data.label || 'Unknown'),
              confidence: Number(data.confidence) || 0.85,
              method: String(data.method || 'RULE_BASED') as 'SIGMA' | 'TI_IOC' | 'HYBRID' | 'RULE_BASED',
              matched_rules: (data.matched_rules as string[]) || [],
              matched_iocs: (data.matched_iocs as string[]) || [],
              mitre_tactics: (data.mitre_tactics as string[]) || [],
              mitre_techniques: (data.mitre_techniques as string[]) || [],
              processing_time_ms: Number(data.processing_time_ms) || 10,
            };
            addClassification(classification);
            addAuditLog({
              id: `audit-${Date.now()}`,
              event_type: 'classification',
              actor_type: 'AI',
              actor_id: 'rule-classifier',
              message: `Classified: ${classification.label} (${Math.round(classification.confidence * 100)}%)`,
              created_at: message.timestamp,
            });
            break;
          }

          case 'playbook_select': {
            updateEvent(eventId, {
              stage: 'playbook_select',
              playbook_match: {
                playbook_id: String(data.playbook_id || ''),
                playbook_name: String(data.playbook_name || ''),
                match_score: Number(data.match_score) || 0.9,
                trigger_tags: (data.trigger_tags as string[]) || [],
                step_count: Number(data.step_count) || 3,
              },
            });
            addAuditLog({
              id: `audit-${Date.now()}`,
              event_type: 'playbook_match',
              actor_type: 'SOAR',
              actor_id: 'playbook-matcher',
              message: `Playbook matched: ${data.playbook_name} (${data.step_count} steps)`,
              created_at: message.timestamp,
            });
            break;
          }

          case 'flow_execution': {
            updateEvent(eventId, {
              stage: 'flow_execution',
              execution: {
                execution_id: String(data.execution_id || ''),
                status: String(data.status || 'PENDING') as 'PENDING' | 'RUNNING' | 'WAITING_APPROVAL' | 'COMPLETED' | 'FAILED',
                current_step: Number(data.current_step) || 0,
                total_steps: Number(data.total_steps) || 3,
              },
            });
            addAuditLog({
              id: `audit-${Date.now()}`,
              event_type: 'execution',
              actor_type: 'SOAR',
              actor_id: 'temporal-engine',
              message: `Playbook execution: ${data.status}`,
              created_at: message.timestamp,
            });
            break;
          }
        }
        return;
      }

      // Handle legacy message types
      switch (message.type) {
        case 'event':
          if (message.action === 'create') {
            addEvent(message.payload as PipelineEvent);
          } else if (message.action === 'update') {
            const payload = message.payload as PipelineEvent;
            updateEvent(payload.id, payload);
          }
          break;

        case 'classification':
          addClassification(message.payload as Classification);
          break;

        case 'approval':
          if (message.action === 'create') {
            addApproval(message.payload as ApprovalInfo);
          } else if (message.action === 'update') {
            const payload = message.payload as ApprovalInfo;
            updateApproval(payload.approval_id, payload.status);
          }
          break;

        case 'audit':
          addAuditLog(message.payload as AuditLog);
          break;

        case 'stats':
          setStats(message.payload as PipelineStats);
          break;

        // playbook and execution types are handled via event updates
        default:
          break;
      }
    },
    [addEvent, updateEvent, addClassification, addApproval, updateApproval, addAuditLog, setStats]
  );

  const connect = useCallback(() => {
    // Clean up existing connection before creating a new one
    if (wsRef.current) {
      wsRef.current.onclose = null;
      wsRef.current.close();
    }

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws/pipeline`;

    setConnectionStatus('connecting');
    wsRef.current = new WebSocket(wsUrl);

    wsRef.current.onopen = () => {
      setConnectionStatus('connected');
      reconnectAttempts.current = 0;

      // Subscribe to tenant-specific pipeline events
      wsRef.current?.send(
        JSON.stringify({
          types: ['event', 'classification', 'playbook', 'execution', 'approval', 'audit', 'stats'],
          tenant_id: tenantId,
        })
      );
    };

    wsRef.current.onmessage = (event) => {
      try {
        const message: WebSocketMessage = JSON.parse(event.data as string);
        handleMessage(message);
      } catch {
        // Ignore malformed messages
      }
    };

    wsRef.current.onerror = () => {
      setConnectionStatus('error');
    };

    wsRef.current.onclose = () => {
      setConnectionStatus('disconnected');
      scheduleReconnect();
    };
  }, [tenantId, setConnectionStatus, handleMessage]); // eslint-disable-line react-hooks/exhaustive-deps

  const scheduleReconnect = useCallback(() => {
    if (reconnectAttempts.current < maxReconnectAttempts) {
      const delay = Math.min(1000 * Math.pow(2, reconnectAttempts.current), 30000);
      reconnectAttempts.current += 1;
      setTimeout(connect, delay);
    }
  }, [connect]);

  const disconnect = useCallback(() => {
    if (wsRef.current) {
      wsRef.current.onclose = null; // prevent reconnect on intentional close
      wsRef.current.close();
      wsRef.current = null;
    }
    setConnectionStatus('disconnected');
  }, [setConnectionStatus]);

  useEffect(() => {
    // Load initial data from REST API before connecting to WebSocket
    loadInitialData().then(() => {
      connect();
    });
    return () => {
      disconnect();
    };
  }, [connect, disconnect, loadInitialData]);

  return {
    isConnected: usePipelineStore((s) => s.isConnected),
    connectionStatus: usePipelineStore((s) => s.connectionStatus),
    reconnect: connect,
    disconnect,
    // Initial data from REST API
    initialData,
    refreshInitialData: loadInitialData,
  };
};
