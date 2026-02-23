import { useState, useMemo, useCallback, useEffect } from 'react';
import type { SigmaRule, AttackTactic, AttackTechnique, RuleTestResult, AlertAggregation } from '../types';
import { ATTACK_TACTICS } from '../types';
import {
  rulesApi,
  type Rule,
  type RuleListParams,
  type CreateRuleRequest,
  type UpdateRuleRequest,
  type RuleStats,
} from '../api/rulesApi';

// Transform API Rule to SigmaRule for UI
function transformApiRuleToSigmaRule(rule: Rule): SigmaRule {
  return {
    id: rule.id,
    title: rule.name,
    description: rule.description,
    status: rule.status === 'enabled' ? 'active' : 'disabled',
    severity: rule.severity,
    author: rule.author,
    references: [],
    tags: rule.tags,
    logsources: {},
    rawYaml: rule.content,
    attack: {
      tactics: rule.mitreTactics.map((id) => {
        const tactic = ATTACK_TACTICS.find((t) => t.id === id);
        return { id, name: tactic?.name || id };
      }),
      techniques: rule.mitreTechniques.map((fullId) => {
        const parts = fullId.split('.');
        const techId = parts[0] || fullId;
        const subtechnique = parts.length > 1 ? parts[1] : undefined;
        return { id: techId, name: fullId, subtechnique };
      }),
    },
    enabled: rule.status === 'enabled',
    lastTriggered: rule.lastHitAt ? new Date(rule.lastHitAt) : undefined,
    triggerCount: rule.hitCount,
    version: 1,
    createdAt: new Date(rule.createdAt),
    updatedAt: new Date(rule.updatedAt),
  };
}

// Transform SigmaRule to API Rule for requests
function transformSigmaRuleToCreateRequest(rule: Partial<SigmaRule>): CreateRuleRequest {
  return {
    name: rule.title || 'Untitled Rule',
    description: rule.description || '',
    severity: rule.severity === 'informational' ? 'low' : (rule.severity || 'medium'),
    content: rule.rawYaml || '',
    author: rule.author || 'SOC Team',
    tags: rule.tags || [],
    mitreTactics: rule.attack?.tactics.map((t) => t.id) || [],
    mitreTechniques: rule.attack?.techniques.map((t) =>
      t.subtechnique ? `${t.id}.${t.subtechnique}` : t.id
    ) || [],
  };
}

function transformSigmaRuleToUpdateRequest(rule: Partial<SigmaRule>): UpdateRuleRequest {
  const request: UpdateRuleRequest = {};
  if (rule.title !== undefined) request.name = rule.title;
  if (rule.description !== undefined) request.description = rule.description;
  if (rule.severity !== undefined) {
    request.severity = rule.severity === 'informational' ? 'low' : rule.severity;
  }
  if (rule.rawYaml !== undefined) request.content = rule.rawYaml;
  if (rule.author !== undefined) request.author = rule.author;
  if (rule.tags !== undefined) request.tags = rule.tags;
  if (rule.attack?.tactics !== undefined) {
    request.mitreTactics = rule.attack.tactics.map((t) => t.id);
  }
  if (rule.attack?.techniques !== undefined) {
    request.mitreTechniques = rule.attack.techniques.map((t) =>
      t.subtechnique ? `${t.id}.${t.subtechnique}` : t.id
    );
  }
  return request;
}

const TECHNIQUES_BY_TACTIC: Record<string, AttackTechnique[]> = {
  TA0001: [
    { id: 'T1566', name: 'Phishing', subtechnique: '001' },
    { id: 'T1190', name: 'Exploit Public-Facing Application' },
    { id: 'T1133', name: 'External Remote Services' },
    { id: 'T1078', name: 'Valid Accounts' },
    { id: 'T1189', name: 'Drive-by Compromise' },
    { id: 'T1091', name: 'Replication Through Removable Media' },
    { id: 'T1595', name: 'Active Scanning' },
    { id: 'T1589', name: 'Gather Victim Identity Information' },
  ],
  TA0002: [
    { id: 'T1059', name: 'Command and Scripting Interpreter', subtechnique: '001' },
    { id: 'T1047', name: 'Windows Management Instrumentation' },
    { id: 'T1053', name: 'Scheduled Task/Job' },
    { id: 'T1204', name: 'User Execution' },
    { id: 'T1569', name: 'System Services' },
    { id: 'T1106', name: 'Native API' },
    { id: 'T1203', name: 'Exploitation for Client Execution' },
    { id: 'T1609', name: 'Container Administration Command' },
  ],
  TA0003: [
    { id: 'T1053', name: 'Scheduled Task/Job', subtechnique: '005' },
    { id: 'T1547', name: 'Boot or Logon Autostart Execution' },
    { id: 'T1543', name: 'Create or Modify System Process' },
    { id: 'T1136', name: 'Create Account' },
    { id: 'T1546', name: 'Event Triggered Execution' },
    { id: 'T1137', name: 'Office Application Startup' },
    { id: 'T1505', name: 'Server Software Component' },
    { id: 'T1542', name: 'Pre-OS Boot' },
  ],
  TA0004: [
    { id: 'T1548', name: 'Abuse Elevation Control Mechanism', subtechnique: '002' },
    { id: 'T1068', name: 'Exploitation for Privilege Escalation' },
    { id: 'T1134', name: 'Access Token Manipulation' },
    { id: 'T1078', name: 'Valid Accounts' },
    { id: 'T1055', name: 'Process Injection' },
    { id: 'T1484', name: 'Domain Policy Modification' },
    { id: 'T1611', name: 'Escape to Host' },
  ],
  TA0005: [
    { id: 'T1562', name: 'Impair Defenses', subtechnique: '001' },
    { id: 'T1070', name: 'Indicator Removal' },
    { id: 'T1027', name: 'Obfuscated Files or Information' },
    { id: 'T1055', name: 'Process Injection' },
    { id: 'T1036', name: 'Masquerading' },
    { id: 'T1218', name: 'System Binary Proxy Execution' },
    { id: 'T1222', name: 'File and Directory Permissions Modification' },
    { id: 'T1564', name: 'Hide Artifacts' },
  ],
  TA0006: [
    { id: 'T1003', name: 'OS Credential Dumping', subtechnique: '001' },
    { id: 'T1110', name: 'Brute Force' },
    { id: 'T1555', name: 'Credentials from Password Stores' },
    { id: 'T1558', name: 'Steal or Forge Kerberos Tickets' },
    { id: 'T1552', name: 'Unsecured Credentials' },
    { id: 'T1056', name: 'Input Capture' },
    { id: 'T1556', name: 'Modify Authentication Process' },
    { id: 'T1557', name: 'Adversary-in-the-Middle' },
  ],
  TA0007: [
    { id: 'T1135', name: 'Network Share Discovery' },
    { id: 'T1046', name: 'Network Service Discovery' },
    { id: 'T1082', name: 'System Information Discovery' },
    { id: 'T1087', name: 'Account Discovery' },
    { id: 'T1083', name: 'File and Directory Discovery' },
    { id: 'T1057', name: 'Process Discovery' },
    { id: 'T1018', name: 'Remote System Discovery' },
    { id: 'T1518', name: 'Software Discovery' },
  ],
  TA0008: [
    { id: 'T1021', name: 'Remote Services', subtechnique: '002' },
    { id: 'T1570', name: 'Lateral Tool Transfer' },
    { id: 'T1080', name: 'Taint Shared Content' },
    { id: 'T1091', name: 'Replication Through Removable Media' },
    { id: 'T1563', name: 'Remote Service Session Hijacking' },
    { id: 'T1550', name: 'Use Alternate Authentication Material' },
  ],
  TA0009: [
    { id: 'T1560', name: 'Archive Collected Data', subtechnique: '001' },
    { id: 'T1005', name: 'Data from Local System' },
    { id: 'T1114', name: 'Email Collection' },
    { id: 'T1039', name: 'Data from Network Shared Drive' },
    { id: 'T1119', name: 'Automated Collection' },
    { id: 'T1056', name: 'Input Capture' },
    { id: 'T1113', name: 'Screen Capture' },
    { id: 'T1125', name: 'Video Capture' },
  ],
  TA0010: [
    { id: 'T1567', name: 'Exfiltration Over Web Service', subtechnique: '002' },
    { id: 'T1048', name: 'Exfiltration Over Alternative Protocol' },
    { id: 'T1041', name: 'Exfiltration Over C2 Channel' },
    { id: 'T1052', name: 'Exfiltration Over Physical Medium' },
    { id: 'T1020', name: 'Automated Exfiltration' },
    { id: 'T1537', name: 'Transfer Data to Cloud Account' },
  ],
  TA0040: [
    { id: 'T1486', name: 'Data Encrypted for Impact' },
    { id: 'T1489', name: 'Service Stop' },
    { id: 'T1485', name: 'Data Destruction' },
    { id: 'T1490', name: 'Inhibit System Recovery' },
    { id: 'T1491', name: 'Defacement' },
    { id: 'T1498', name: 'Network Denial of Service' },
    { id: 'T1499', name: 'Endpoint Denial of Service' },
    { id: 'T1529', name: 'System Shutdown/Reboot' },
  ],
};

export interface UseRulesOptions {
  autoFetch?: boolean;
  initialFilters?: {
    search?: string;
    status?: string;
    severity?: string;
    tactic?: string;
  };
}

export function useRules(options: UseRulesOptions = {}) {
  const { autoFetch = true, initialFilters } = options;

  const [rules, setRules] = useState<SigmaRule[]>([]);
  const [selectedRule, setSelectedRule] = useState<SigmaRule | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [filters, setFilters] = useState({
    search: initialFilters?.search || '',
    status: initialFilters?.status || 'all',
    severity: initialFilters?.severity || 'all',
    tactic: initialFilters?.tactic || 'all',
  });

  // Fetch rules from API
  const fetchRules = useCallback(async () => {
    setLoading(true);
    setError(null);

    try {
      const params: RuleListParams = {};
      if (filters.status !== 'all') {
        params.status = filters.status === 'active' ? 'enabled' : 'disabled';
      }
      if (filters.severity !== 'all') {
        params.severity = filters.severity as 'low' | 'medium' | 'high' | 'critical';
      }
      if (filters.tactic !== 'all') {
        params.tactic = filters.tactic;
      }
      if (filters.search) {
        params.search = filters.search;
      }

      const response = await rulesApi.list(params);

      if (response.success && response.data) {
        const transformedRules = response.data.rules.map(transformApiRuleToSigmaRule);
        setRules(transformedRules);
      } else {
        setError(response.error?.message || 'Failed to fetch rules');
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
    } finally {
      setLoading(false);
    }
  }, [filters]);

  // Auto-fetch on mount and filter changes
  useEffect(() => {
    if (autoFetch) {
      fetchRules();
    }
  }, [autoFetch, fetchRules]);

  // Filtering is done server-side by the API
  const filteredRules = useMemo(() => rules, [rules]);

  const updateRule = useCallback(async (ruleId: string, updates: Partial<SigmaRule>) => {
    setLoading(true);
    try {
      const updateData = transformSigmaRuleToUpdateRequest(updates);
      const response = await rulesApi.update(ruleId, updateData);

      if (response.success && response.data) {
        const updatedRule = transformApiRuleToSigmaRule(response.data);
        setRules((prev) =>
          prev.map((rule) => (rule.id === ruleId ? updatedRule : rule))
        );
        return updatedRule;
      } else {
        setError(response.error?.message || 'Failed to update rule');
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
    } finally {
      setLoading(false);
    }
  }, []);

  const toggleRuleEnabled = useCallback(async (ruleId: string) => {
    const rule = rules.find((r) => r.id === ruleId);
    if (!rule) return;

    setLoading(true);
    try {
      const response = rule.enabled
        ? await rulesApi.disable(ruleId)
        : await rulesApi.enable(ruleId);

      if (response.success && response.data) {
        const updatedRule = transformApiRuleToSigmaRule(response.data);
        setRules((prev) =>
          prev.map((r) => (r.id === ruleId ? updatedRule : r))
        );
      } else {
        setError(response.error?.message || 'Failed to toggle rule');
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
    } finally {
      setLoading(false);
    }
  }, [rules]);

  const deleteRule = useCallback(async (ruleId: string) => {
    setLoading(true);
    try {
      const response = await rulesApi.delete(ruleId);

      if (response.success) {
        setRules((prev) => prev.filter((rule) => rule.id !== ruleId));
        if (selectedRule?.id === ruleId) {
          setSelectedRule(null);
        }
      } else {
        setError(response.error?.message || 'Failed to delete rule');
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
    } finally {
      setLoading(false);
    }
  }, [selectedRule]);

  const createRule = useCallback(async (ruleData: Partial<SigmaRule>) => {
    setLoading(true);
    try {
      const createData = transformSigmaRuleToCreateRequest(ruleData);
      const response = await rulesApi.create(createData);

      if (response.success && response.data) {
        const newRule = transformApiRuleToSigmaRule(response.data);
        setRules((prev) => [newRule, ...prev]);
        return newRule;
      } else {
        setError(response.error?.message || 'Failed to create rule');
        return null;
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
      return null;
    } finally {
      setLoading(false);
    }
  }, []);

  const testRule = useCallback(async (ruleId: string, testEvents: object[]): Promise<RuleTestResult> => {
    setLoading(true);
    try {
      const response = await rulesApi.testById(
        ruleId,
        testEvents as Record<string, unknown>[]
      );

      if (response.success && response.data) {
        return {
          success: response.data.success,
          matchedEvents: response.data.matchedEvents,
          totalEvents: response.data.totalEvents,
          matches: response.data.matches.map((m) => ({
            eventIndex: m.eventIndex,
            matchedConditions: m.matchedConditions,
          })),
          executionTime: response.data.executionTime,
          error: response.data.error,
        };
      } else {
        return {
          success: false,
          matchedEvents: 0,
          totalEvents: testEvents.length,
          matches: [],
          executionTime: 0,
          error: response.error?.message || 'Failed to test rule',
        };
      }
    } catch (err) {
      return {
        success: false,
        matchedEvents: 0,
        totalEvents: testEvents.length,
        matches: [],
        executionTime: 0,
        error: err instanceof Error ? err.message : 'An error occurred',
      };
    } finally {
      setLoading(false);
    }
  }, []);

  const testRuleContent = useCallback(async (
    ruleContent: string,
    testEvents: object[]
  ): Promise<RuleTestResult> => {
    setLoading(true);
    try {
      const response = await rulesApi.test({
        ruleContent,
        sampleEvents: testEvents as Record<string, unknown>[],
      });

      if (response.success && response.data) {
        return {
          success: response.data.success,
          matchedEvents: response.data.matchedEvents,
          totalEvents: response.data.totalEvents,
          matches: response.data.matches.map((m) => ({
            eventIndex: m.eventIndex,
            matchedConditions: m.matchedConditions,
          })),
          executionTime: response.data.executionTime,
          error: response.data.error,
        };
      } else {
        return {
          success: false,
          matchedEvents: 0,
          totalEvents: testEvents.length,
          matches: [],
          executionTime: 0,
          error: response.error?.message || 'Failed to test rule',
        };
      }
    } catch (err) {
      return {
        success: false,
        matchedEvents: 0,
        totalEvents: testEvents.length,
        matches: [],
        executionTime: 0,
        error: err instanceof Error ? err.message : 'An error occurred',
      };
    } finally {
      setLoading(false);
    }
  }, []);

  const getRuleStats = useCallback(async (ruleId: string): Promise<RuleStats | null> => {
    setLoading(true);
    try {
      const response = await rulesApi.getStats(ruleId);

      if (response.success && response.data) {
        return response.data;
      } else {
        setError(response.error?.message || 'Failed to get rule stats');
        return null;
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
      return null;
    } finally {
      setLoading(false);
    }
  }, []);

  const clearError = useCallback(() => {
    setError(null);
  }, []);

  const refetch = useCallback(() => {
    fetchRules();
  }, [fetchRules]);

  return {
    rules,
    filteredRules,
    selectedRule,
    setSelectedRule,
    filters,
    setFilters,
    loading,
    error,
    clearError,
    updateRule,
    toggleRuleEnabled,
    deleteRule,
    createRule,
    testRule,
    testRuleContent,
    getRuleStats,
    refetch,
  };
}

export function useAttackMatrix() {
  const [selectedTechnique, setSelectedTechnique] = useState<string | null>(null);
  const { rules } = useRules({ autoFetch: true });

  // Build a map of technique IDs to rules
  const techniqueRulesMap = useMemo(() => {
    const map = new Map<string, SigmaRule[]>();
    rules.forEach((rule) => {
      rule.attack.techniques.forEach((technique) => {
        const key = technique.subtechnique
          ? `${technique.id}.${technique.subtechnique}`
          : technique.id;
        const existing = map.get(key) || [];
        map.set(key, [...existing, rule]);
      });
    });
    return map;
  }, [rules]);

  // Get all techniques with their rule counts
  const matrixData = useMemo(() => {
    return ATTACK_TACTICS.map((tactic) => {
      const techniques = TECHNIQUES_BY_TACTIC[tactic.id] || [];
      return {
        tactic,
        techniques: techniques.map((technique) => {
          const key = technique.subtechnique
            ? `${technique.id}.${technique.subtechnique}`
            : technique.id;
          const associatedRules = techniqueRulesMap.get(key) || [];
          return {
            ...technique,
            ruleCount: associatedRules.length,
            rules: associatedRules,
          };
        }),
      };
    });
  }, [techniqueRulesMap]);

  const getRulesForTechnique = useCallback(
    (techniqueId: string) => {
      return techniqueRulesMap.get(techniqueId) || [];
    },
    [techniqueRulesMap]
  );

  return {
    matrixData,
    selectedTechnique,
    setSelectedTechnique,
    getRulesForTechnique,
    tactics: ATTACK_TACTICS,
  };
}
