import type { Node, Edge } from '@xyflow/react';

// API Configuration
const API_BASE_URL = import.meta.env.VITE_API_URL || '/api/v1';

// Types matching backend model
export interface PlaybookDeployRequest {
  id: string;
  name: string;
  display_name: string;
  description: string;
  category: string;
  enabled: boolean;
  version: number;
  trigger: {
    type: string;
    conditions?: Array<{
      field: string;
      operator: string;
      value: unknown;
    }>;
  };
  steps: Array<{
    id: string;
    name: string;
    type: string;
    description?: string;
    action?: {
      connector: string;
      action: string;
      parameters?: Record<string, unknown>;
    };
    approval?: {
      approvers: string[];
      timeout: string;
      message: string;
    };
  }>;
  variables?: Array<{
    name: string;
    type: string;
    value?: unknown;
  }>;
}

export interface PlaybookDeployResponse {
  id: string;
  message: string;
  version: number;
  workflow_id?: string;
}

export interface PlaybookExecuteRequest {
  inputs?: Record<string, unknown>;
  trigger_type: string;
  alert_id?: string;
}

export interface PlaybookExecuteResponse {
  execution_id: string;
  workflow_id: string;
  status: string;
  message: string;
}

export interface PlaybookListResponse {
  playbooks: Array<{
    id: string;
    name: string;
    display_name: string;
    description: string;
    category: string;
    enabled: boolean;
    version: number;
    created_at: string;
    updated_at: string;
  }>;
}

// Helper to convert frontend nodes/edges to backend steps
export function convertNodesToSteps(nodes: Node[], edges: Edge[]): PlaybookDeployRequest['steps'] {
  // Build execution order using BFS from trigger nodes
  const triggerNodes = nodes.filter((n) => n.type === 'trigger');
  const executionOrder: Node[] = [];
  const visited = new Set<string>();
  const queue: Node[] = [...triggerNodes];

  while (queue.length > 0) {
    const current = queue.shift()!;
    if (visited.has(current.id)) continue;
    visited.add(current.id);
    executionOrder.push(current);

    const outgoingEdges = edges.filter((e) => e.source === current.id);
    for (const edge of outgoingEdges) {
      const targetNode = nodes.find((n) => n.id === edge.target);
      if (targetNode && !visited.has(targetNode.id)) {
        queue.push(targetNode);
      }
    }
  }

  return executionOrder.map((node) => {
    const data = node.data as Record<string, unknown>;
    const step: PlaybookDeployRequest['steps'][0] = {
      id: node.id,
      name: (data.label as string) || node.id,
      type: mapNodeTypeToStepType(node.type || 'action'),
      description: data.description as string | undefined,
    };

    // Add type-specific configuration
    if (node.type === 'action' || node.type === 'integration') {
      step.action = {
        connector: (data.actionType as string) || (data.integrationType as string) || 'custom',
        action: (data.actionType as string) || 'execute',
        parameters: data.parameters as Record<string, unknown>,
      };
    }

    if (node.type === 'approval') {
      step.approval = {
        approvers: (data.approverRoles as string[]) || ['SOC Manager'],
        timeout: `${(data.timeout as number) || 3600}s`,
        message: (data.description as string) || 'Manual approval required',
      };
    }

    return step;
  });
}

function mapNodeTypeToStepType(nodeType: string): string {
  const mapping: Record<string, string> = {
    trigger: 'action',
    action: 'action',
    decision: 'condition',
    integration: 'action',
    loop: 'loop',
    parallel: 'parallel',
    wait: 'wait',
    approval: 'approval',
  };
  return mapping[nodeType] || 'action';
}

// API Functions
export async function deployPlaybook(request: PlaybookDeployRequest): Promise<PlaybookDeployResponse> {
  const response = await fetch(`${API_BASE_URL}/playbooks`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(request),
  });

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Failed to deploy playbook: ${error}`);
  }

  return response.json();
}

export async function executePlaybook(
  playbookId: string,
  request: PlaybookExecuteRequest
): Promise<PlaybookExecuteResponse> {
  const response = await fetch(`${API_BASE_URL}/playbooks/${playbookId}/execute`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(request),
  });

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Failed to execute playbook: ${error}`);
  }

  return response.json();
}

export async function listPlaybooks(): Promise<PlaybookListResponse> {
  const response = await fetch(`${API_BASE_URL}/playbooks`, {
    method: 'GET',
    headers: {
      'Content-Type': 'application/json',
    },
  });

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Failed to list playbooks: ${error}`);
  }

  return response.json();
}

export async function getPlaybook(playbookId: string): Promise<PlaybookDeployRequest> {
  const response = await fetch(`${API_BASE_URL}/playbooks/${playbookId}`, {
    method: 'GET',
    headers: {
      'Content-Type': 'application/json',
    },
  });

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Failed to get playbook: ${error}`);
  }

  return response.json();
}

// ============================================================================
// Playbook Save/Update/Delete API Functions
// ============================================================================

export interface PlaybookSaveRequest {
  id?: string;
  name: string;
  display_name: string;
  description: string;
  category: string;
  status: string;
  trigger_type: string;
  enabled: boolean;
  tags?: string[];
  nodes: unknown[];
  edges: unknown[];
  variables: unknown[];
}

export interface PlaybookSaveResponse {
  id: string;
  message: string;
  version?: number;
}

export interface PlaybookData {
  id: string;
  name: string;
  display_name: string;
  description: string;
  category: string;
  version: number;
  trigger_type: string;
  enabled: boolean;
  tags: string[];
  definition: {
    nodes: unknown[];
    edges: unknown[];
    variables: unknown[];
  };
  created_at: string;
  updated_at: string;
}

/**
 * Save a new playbook to the database
 */
export async function savePlaybook(request: PlaybookSaveRequest): Promise<PlaybookSaveResponse> {
  const response = await fetch(`${API_BASE_URL}/playbooks`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(request),
  });

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Failed to save playbook: ${error}`);
  }

  return response.json();
}

/**
 * Update an existing playbook in the database
 */
export async function updatePlaybook(
  playbookId: string,
  request: PlaybookSaveRequest
): Promise<PlaybookSaveResponse> {
  const response = await fetch(`${API_BASE_URL}/playbooks/${playbookId}`, {
    method: 'PUT',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(request),
  });

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Failed to update playbook: ${error}`);
  }

  return response.json();
}

/**
 * Delete a playbook from the database
 */
export async function deletePlaybook(playbookId: string): Promise<{ message: string }> {
  const response = await fetch(`${API_BASE_URL}/playbooks/${playbookId}`, {
    method: 'DELETE',
    headers: {
      'Content-Type': 'application/json',
    },
  });

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Failed to delete playbook: ${error}`);
  }

  return response.json();
}

/**
 * Get a playbook with full definition (nodes, edges, variables)
 */
export async function getPlaybookWithDefinition(playbookId: string): Promise<PlaybookData | null> {
  try {
    const response = await fetch(`${API_BASE_URL}/playbooks/${playbookId}`, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
      },
    });

    if (!response.ok) {
      if (response.status === 404) {
        return null;
      }
      throw new Error(`Failed to get playbook`);
    }

    return response.json();
  } catch {
    return null;
  }
}

/**
 * List all playbooks with their definitions
 */
export async function listPlaybooksWithDefinitions(): Promise<PlaybookData[]> {
  try {
    const response = await fetch(`${API_BASE_URL}/playbooks`, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
      },
    });

    if (!response.ok) {
      return [];
    }

    const data = await response.json();
    return data.playbooks || [];
  } catch {
    return [];
  }
}

/**
 * Check if the API is available
 */
export async function checkApiHealth(): Promise<boolean> {
  try {
    const response = await fetch(`${API_BASE_URL.replace('/api/v1', '')}/health`, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
      },
    });
    return response.ok;
  } catch {
    return false;
  }
}
