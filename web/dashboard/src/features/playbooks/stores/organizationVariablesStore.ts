import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import type { PlaybookVariable } from '../components/VariablePanel';

interface OrganizationVariablesState {
  variables: PlaybookVariable[];
  addVariable: (variable: Omit<PlaybookVariable, 'id'>) => void;
  updateVariable: (id: string, updates: Partial<PlaybookVariable>) => void;
  deleteVariable: (id: string) => void;
}

// Initial mock data (moved from PlaybookEditor.tsx)
const initialVariables: PlaybookVariable[] = [
  {
    id: 'org-var-1',
    name: 'org_soc_email',
    type: 'string',
    scope: 'organization',
    value: 'soc@example.com',
    description: 'SOC team email address',
  },
  {
    id: 'org-var-2',
    name: 'org_security_email',
    type: 'string',
    scope: 'organization',
    value: 'security@example.com',
    description: 'Security team email address',
  },
  {
    id: 'org-var-3',
    name: 'org_slack_channel',
    type: 'string',
    scope: 'organization',
    value: '#security-alerts',
    description: 'Default Slack channel for security alerts',
  },
  {
    id: 'org-var-4',
    name: 'org_severity_threshold',
    type: 'string',
    scope: 'organization',
    value: 'high',
    description: 'Organization default severity threshold for triggering responses',
  },
  {
    id: 'org-var-5',
    name: 'org_max_retries',
    type: 'number',
    scope: 'organization',
    value: 3,
    description: 'Default maximum retry attempts for actions',
  },
  {
    id: 'org-var-6',
    name: 'org_api_timeout',
    type: 'number',
    scope: 'organization',
    value: 30,
    description: 'Default API timeout in seconds',
  },
  {
    id: 'org-var-7',
    name: 'org_incident_prefix',
    type: 'string',
    scope: 'organization',
    value: 'INC-',
    description: 'Incident ID prefix used across all playbooks',
  },
];

export const useOrganizationVariables = create<OrganizationVariablesState>()(
  persist(
    (set) => ({
      variables: initialVariables,
      addVariable: (variable) =>
        set((state) => ({
          variables: [
            ...state.variables,
            { ...variable, id: `org-${Date.now()}`, scope: 'organization' },
          ],
        })),
      updateVariable: (id, updates) =>
        set((state) => ({
          variables: state.variables.map((v) => (v.id === id ? { ...v, ...updates } : v)),
        })),
      deleteVariable: (id) =>
        set((state) => ({
          variables: state.variables.filter((v) => v.id !== id),
        })),
    }),
    { name: 'organization-variables' }
  )
);
