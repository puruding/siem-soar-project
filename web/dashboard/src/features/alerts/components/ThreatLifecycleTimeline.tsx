import { useState } from 'react';
import {
  Database,
  Filter,
  Layers,
  Brain,
  Play,
  FolderPlus,
  CheckCircle,
  Clock,
  Minus,
  ChevronDown,
} from 'lucide-react';
import { Card, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { cn, formatTimestamp, formatRelativeTime } from '@/lib/utils';

// ============================================================================
// Types & Enums
// ============================================================================

export enum LifecycleStageType {
  COLLECTION = 'collection',
  RULE_MATCHING = 'rule_matching',
  ML_GROUPING = 'ml_grouping',
  ML_CLASSIFICATION = 'ml_classification',
  SOAR_EXECUTION = 'soar_execution',
  CASE_CREATED = 'case_created',
}

export interface LifecycleStageData {
  stage: LifecycleStageType;
  status: 'completed' | 'in_progress' | 'pending' | 'skipped';
  timestamp?: Date;
  duration?: string;
  title: string;
  summary: string;
  details: Record<string, any>;
  scrollTarget?: string;
}

interface ThreatLifecycleTimelineProps {
  alert: {
    id: string;
    timestamp: string;
    detection_reason?: {
      rule_description: string;
      rule_conditions: Record<string, any>;
      rule_threshold: number;
      rule_window_minutes: number;
      rule_aggregate_by: string[];
      rule_tags: string[];
      matched_count: number;
      classification_method: string;
      classification_confidence: number;
      ml_model?: { model_name: string; model_version: string } | null;
      ml_analysis?: {
        anomaly_score: number | null;
        threat_category: string;
        risk_factors: { factor: string; weight: number; triggered: boolean }[];
        false_positive_likelihood: number;
      } | null;
    };
    mitre_tactics: string[];
    mitre_techniques: string[];
    rule_id: string;
    rule_name: string;
    fields?: Record<string, any>;
  };
  groupedInfo?: {
    eventCount: number;
    firstEventTime?: string;
    lastEventTime?: string;
  };
  soarStatus?: {
    playbookName: string;
    playbookId: string;
    status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled' | 'paused' | 'waiting_approval';
    progress: number;
    startTime?: string;
  } | null;
  caseId?: string;
  caseAssignee?: string;
  onStageClick?: (stage: LifecycleStageType, scrollTarget?: string) => void;
}

// ============================================================================
// Stage Configuration
// ============================================================================

const stageConfig = {
  [LifecycleStageType.COLLECTION]: {
    icon: Database,
    color: 'from-cyan-400 to-cyan-600',
    bgColor: 'bg-cyan-500/10',
    borderColor: 'border-cyan-500/30',
    textColor: 'text-cyan-400',
    accentColor: '#22d3ee',
  },
  [LifecycleStageType.RULE_MATCHING]: {
    icon: Filter,
    color: 'from-blue-400 to-blue-600',
    bgColor: 'bg-blue-500/10',
    borderColor: 'border-blue-500/30',
    textColor: 'text-blue-400',
    accentColor: '#60a5fa',
  },
  [LifecycleStageType.ML_GROUPING]: {
    icon: Layers,
    color: 'from-purple-400 to-purple-600',
    bgColor: 'bg-purple-500/10',
    borderColor: 'border-purple-500/30',
    textColor: 'text-purple-400',
    accentColor: '#a78bfa',
  },
  [LifecycleStageType.ML_CLASSIFICATION]: {
    icon: Brain,
    color: 'from-pink-400 to-pink-600',
    bgColor: 'bg-pink-500/10',
    borderColor: 'border-pink-500/30',
    textColor: 'text-pink-400',
    accentColor: '#f472b6',
  },
  [LifecycleStageType.SOAR_EXECUTION]: {
    icon: Play,
    color: 'from-orange-400 to-orange-600',
    bgColor: 'bg-orange-500/10',
    borderColor: 'border-orange-500/30',
    textColor: 'text-orange-400',
    accentColor: '#fb923c',
  },
  [LifecycleStageType.CASE_CREATED]: {
    icon: FolderPlus,
    color: 'from-green-400 to-green-600',
    bgColor: 'bg-green-500/10',
    borderColor: 'border-green-500/30',
    textColor: 'text-green-400',
    accentColor: '#4ade80',
  },
};

// ============================================================================
// Helper Functions
// ============================================================================

export function buildLifecycleStages(props: ThreatLifecycleTimelineProps): LifecycleStageData[] {
  const { alert, groupedInfo, soarStatus, caseId, caseAssignee } = props;
  const stages: LifecycleStageData[] = [];

  // Stage 1: Collection
  const collectionTime = new Date(alert.timestamp);
  const eventCount = groupedInfo?.eventCount || 1;
  const timeWindow = alert.detection_reason?.rule_window_minutes || 0;

  stages.push({
    stage: LifecycleStageType.COLLECTION,
    status: 'completed',
    timestamp: collectionTime,
    duration: '+0ms',
    title: 'Event Collection',
    summary: `Collected ${eventCount} event${eventCount > 1 ? 's' : ''} over ${timeWindow}m window`,
    details: {
      eventCount,
      firstEvent: groupedInfo?.firstEventTime || alert.timestamp,
      lastEvent: groupedInfo?.lastEventTime || alert.timestamp,
      timeWindow: `${timeWindow} minutes`,
    },
    scrollTarget: 'grouped-events',
  });

  // Stage 2: Rule Matching
  const ruleTime = new Date(collectionTime.getTime() + 50);
  const matchedCount = alert.detection_reason?.matched_count || eventCount;
  const threshold = alert.detection_reason?.rule_threshold || 1;

  stages.push({
    stage: LifecycleStageType.RULE_MATCHING,
    status: 'completed',
    timestamp: ruleTime,
    duration: '+50ms',
    title: 'Rule Matching',
    summary: `Matched ${matchedCount} events against "${alert.rule_name}" (threshold: ${threshold})`,
    details: {
      ruleId: alert.rule_id,
      ruleName: alert.rule_name,
      ruleDescription: alert.detection_reason?.rule_description || '',
      matchedCount,
      threshold,
      conditions: alert.detection_reason?.rule_conditions || {},
      tags: alert.detection_reason?.rule_tags || [],
    },
    scrollTarget: 'detection-details',
  });

  // Stage 3: ML Grouping
  const groupingTime = new Date(ruleTime.getTime() + 120);
  const aggregateBy = alert.detection_reason?.rule_aggregate_by || [];
  const classificationMethod = alert.detection_reason?.classification_method || 'rule-based';

  stages.push({
    stage: LifecycleStageType.ML_GROUPING,
    status: 'completed',
    timestamp: groupingTime,
    duration: '+120ms',
    title: 'ML Grouping',
    summary: `Grouped by ${aggregateBy.length > 0 ? aggregateBy.join(', ') : 'default'} using ${classificationMethod}`,
    details: {
      aggregateBy,
      classificationMethod,
      groupSize: eventCount,
      mitreTactics: alert.mitre_tactics || [],
      mitreTechniques: alert.mitre_techniques || [],
    },
    scrollTarget: 'detection-details',
  });

  // Stage 4: ML Classification
  const classificationTime = new Date(groupingTime.getTime() + 300);
  const mlModel = alert.detection_reason?.ml_model;
  const mlAnalysis = alert.detection_reason?.ml_analysis;
  const confidence = alert.detection_reason?.classification_confidence || 0;

  const hasML = mlModel && mlAnalysis;
  stages.push({
    stage: LifecycleStageType.ML_CLASSIFICATION,
    status: hasML ? 'completed' : 'skipped',
    timestamp: hasML ? classificationTime : undefined,
    duration: hasML ? '+300ms' : undefined,
    title: 'ML Classification',
    summary: hasML
      ? `Classified as ${mlAnalysis.threat_category} (${(confidence * 100).toFixed(0)}% confidence)`
      : 'ML classification skipped (rule-based detection)',
    details: hasML
      ? {
          modelName: mlModel.model_name,
          modelVersion: mlModel.model_version,
          threatCategory: mlAnalysis.threat_category,
          confidence: (confidence * 100).toFixed(1) + '%',
          anomalyScore: mlAnalysis.anomaly_score,
          fpLikelihood: ((mlAnalysis.false_positive_likelihood || 0) * 100).toFixed(1) + '%',
          riskFactors: mlAnalysis.risk_factors || [],
        }
      : {},
    scrollTarget: hasML ? 'ml-analysis' : undefined,
  });

  // Stage 5: SOAR Execution
  const soarTime = soarStatus?.startTime
    ? new Date(soarStatus.startTime)
    : new Date(classificationTime.getTime() + 500);

  const soarDuration =
    soarStatus?.startTime && hasML
      ? `+${Math.round((soarTime.getTime() - classificationTime.getTime()) / 1000) * 1000}ms`
      : '+500ms';

  stages.push({
    stage: LifecycleStageType.SOAR_EXECUTION,
    status: soarStatus
      ? soarStatus.status === 'completed'
        ? 'completed'
        : soarStatus.status === 'failed'
          ? 'completed'
          : 'in_progress'
      : 'pending',
    timestamp: soarStatus ? soarTime : undefined,
    duration: soarStatus ? soarDuration : undefined,
    title: 'SOAR Execution',
    summary: soarStatus
      ? `Running "${soarStatus.playbookName}" (${soarStatus.progress}% complete)`
      : 'Pending playbook execution',
    details: soarStatus
      ? {
          playbookName: soarStatus.playbookName,
          playbookId: soarStatus.playbookId,
          status: soarStatus.status,
          progress: soarStatus.progress + '%',
          startTime: soarStatus.startTime,
        }
      : {},
    scrollTarget: soarStatus ? 'soar-playbook' : undefined,
  });

  // Stage 6: Case Created
  if (caseId) {
    const caseTime = new Date(
      soarStatus?.startTime ? new Date(soarStatus.startTime).getTime() + 1000 : soarTime.getTime() + 1000
    );

    stages.push({
      stage: LifecycleStageType.CASE_CREATED,
      status: 'completed',
      timestamp: caseTime,
      duration: '+1s',
      title: 'Case Created',
      summary: caseAssignee ? `Assigned to ${caseAssignee}` : 'Case created successfully',
      details: {
        caseId,
        assignee: caseAssignee,
        createdAt: caseTime.toISOString(),
      },
      scrollTarget: 'case-details',
    });
  }

  return stages;
}

// ============================================================================
// Stage Component
// ============================================================================

interface StageItemProps {
  stage: LifecycleStageData;
  isLast: boolean;
  onClick?: () => void;
}

function StageItem({ stage, isLast, onClick }: StageItemProps) {
  const [expanded, setExpanded] = useState(false);
  const config = stageConfig[stage.stage];
  const Icon = config.icon;

  const hasDetails = Object.keys(stage.details).length > 0;
  const isClickable = onClick !== undefined && stage.scrollTarget !== undefined;

  return (
    <div className="relative group">
      {/* Connector Line */}
      {!isLast && (
        <div
          className={cn(
            'absolute left-8 top-16 h-full w-0.5',
            stage.status === 'completed'
              ? `bg-gradient-to-b ${config.color}`
              : stage.status === 'in_progress'
                ? 'bg-gradient-to-b from-blue-500/50 to-transparent animate-pulse'
                : 'bg-border'
          )}
        />
      )}

      {/* Stage Card */}
      <div
        className={cn(
          'flex items-start gap-4 p-4 rounded-lg border transition-all duration-300',
          'hover:shadow-lg hover:shadow-primary/5',
          config.bgColor,
          config.borderColor,
          isClickable && 'cursor-pointer hover:scale-[1.02]',
          stage.status === 'in_progress' && 'animate-pulse'
        )}
        onClick={isClickable ? onClick : undefined}
      >
        {/* Icon */}
        <div className="relative flex-shrink-0">
          <div
            className={cn(
              'relative z-10 w-16 h-16 rounded-xl border-2 flex items-center justify-center transition-transform duration-300',
              config.borderColor,
              config.bgColor,
              'group-hover:scale-110'
            )}
          >
            <Icon className={cn('w-8 h-8', config.textColor)} />

            {/* Status Indicator */}
            <div className="absolute -top-1 -right-1 w-5 h-5 rounded-full border-2 border-card bg-card flex items-center justify-center">
              {stage.status === 'completed' && <CheckCircle className="w-3 h-3 text-green-400" />}
              {stage.status === 'in_progress' && (
                <div className="w-3 h-3 rounded-full bg-blue-400 animate-ping" />
              )}
              {stage.status === 'pending' && <Clock className="w-3 h-3 text-muted-foreground" />}
              {stage.status === 'skipped' && <Minus className="w-3 h-3 text-muted-foreground" />}
            </div>
          </div>

          {/* Glow Effect */}
          {stage.status === 'completed' && (
            <div
              className="absolute inset-0 rounded-xl blur-xl opacity-0 group-hover:opacity-30 transition-opacity duration-300"
              style={{ backgroundColor: config.accentColor }}
            />
          )}
        </div>

        {/* Content */}
        <div className="flex-1 min-w-0 pt-1">
          {/* Header */}
          <div className="flex items-start justify-between gap-4 mb-2">
            <div>
              <h3 className={cn('text-lg font-semibold', config.textColor)}>{stage.title}</h3>
              {stage.timestamp && (
                <div className="flex items-center gap-2 mt-1">
                  <span className="text-xs text-muted-foreground">{formatTimestamp(stage.timestamp)}</span>
                  {stage.duration && (
                    <Badge variant="outline" className="text-2xs h-5 bg-muted/50">
                      {stage.duration}
                    </Badge>
                  )}
                </div>
              )}
            </div>

            {/* Status Badge */}
            <Badge
              variant={
                stage.status === 'completed'
                  ? 'success'
                  : stage.status === 'in_progress'
                    ? 'warning'
                    : stage.status === 'skipped'
                      ? 'secondary'
                      : 'secondary'
              }
              className="text-2xs shrink-0"
            >
              {stage.status.replace('_', ' ')}
            </Badge>
          </div>

          {/* Summary */}
          <p className="text-sm text-muted-foreground mb-3">{stage.summary}</p>

          {/* Details Toggle */}
          {hasDetails && (
            <button
              onClick={(e) => {
                e.stopPropagation();
                setExpanded(!expanded);
              }}
              className={cn(
                'flex items-center gap-2 text-xs font-medium transition-colors',
                config.textColor,
                'hover:opacity-80'
              )}
            >
              <ChevronDown
                className={cn('w-4 h-4 transition-transform', expanded && 'rotate-180')}
              />
              {expanded ? 'Hide' : 'Show'} Details
            </button>
          )}

          {/* Expanded Details */}
          {expanded && hasDetails && (
            <div className={cn('mt-3 p-3 rounded-lg border', config.borderColor, 'bg-card/50')}>
              <dl className="grid grid-cols-1 gap-2 text-xs">
                {Object.entries(stage.details).map(([key, value]) => (
                  <div key={key} className="flex justify-between gap-4">
                    <dt className="text-muted-foreground font-medium">
                      {key
                        .replace(/([A-Z])/g, ' $1')
                        .replace(/^./, (str) => str.toUpperCase())
                        .trim()}
                      :
                    </dt>
                    <dd className={cn('font-mono text-right', config.textColor)}>
                      {Array.isArray(value)
                        ? value.length > 0
                          ? value.join(', ')
                          : '—'
                        : typeof value === 'object'
                          ? JSON.stringify(value, null, 2)
                          : String(value)}
                    </dd>
                  </div>
                ))}
              </dl>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ============================================================================
// Main Component
// ============================================================================

export function ThreatLifecycleTimeline(props: ThreatLifecycleTimelineProps) {
  const { onStageClick } = props;
  const stages = buildLifecycleStages(props);

  const handleStageClick = (stage: LifecycleStageData) => {
    if (stage.scrollTarget && onStageClick) {
      onStageClick(stage.stage, stage.scrollTarget);
    }
  };

  return (
    <Card className="overflow-hidden border-border/50 bg-card/50 backdrop-blur">
      <CardContent className="p-6">
        {/* Header */}
        <div className="mb-6">
          <h2 className="text-xl font-bold mb-2">Threat Lifecycle Timeline</h2>
          <p className="text-sm text-muted-foreground">
            Track the complete detection and response pipeline from event collection to case creation
          </p>
        </div>

        {/* Timeline */}
        <div className="space-y-4">
          {stages.map((stage, index) => (
            <StageItem
              key={stage.stage}
              stage={stage}
              isLast={index === stages.length - 1}
              onClick={
                stage.scrollTarget && onStageClick
                  ? () => handleStageClick(stage)
                  : undefined
              }
            />
          ))}
        </div>

        {/* Summary Footer */}
        <div className="mt-6 pt-4 border-t border-border/50 flex items-center justify-between text-xs text-muted-foreground">
          <span>
            {stages.filter((s) => s.status === 'completed').length} of {stages.length} stages completed
          </span>
          {stages.some((s) => s.status === 'in_progress') && (
            <Badge variant="warning" className="text-2xs animate-pulse">
              Processing
            </Badge>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
