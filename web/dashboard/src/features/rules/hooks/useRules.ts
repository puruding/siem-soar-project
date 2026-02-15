import { useState, useMemo, useCallback } from 'react';
import type { SigmaRule, AttackTactic, AttackTechnique, RuleTestResult } from '../types';
import { ATTACK_TACTICS } from '../types';

// Mock Sigma rules with ATT&CK mappings
const mockSigmaRules: SigmaRule[] = [
  {
    id: 'rule-001',
    title: 'Ransomware File Extension Creation',
    description: 'Detects the creation of files with known ransomware extensions',
    status: 'active',
    severity: 'critical',
    author: 'SOC Team',
    references: ['https://attack.mitre.org/techniques/T1486/'],
    tags: ['ransomware', 'malware', 'endpoint'],
    logsources: { category: 'file_event', product: 'windows' },
    rawYaml: `title: Ransomware File Extension Creation
status: active
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|endswith:
            - '.encrypted'
            - '.locked'
            - '.crypted'
    condition: selection
level: critical`,
    attack: {
      tactics: [{ id: 'TA0040', name: 'Impact' }],
      techniques: [{ id: 'T1486', name: 'Data Encrypted for Impact' }],
    },
    enabled: true,
    lastTriggered: new Date(Date.now() - 1000 * 60 * 30),
    triggerCount: 47,
    version: 3,
    createdAt: new Date(Date.now() - 1000 * 60 * 60 * 24 * 30),
    updatedAt: new Date(Date.now() - 1000 * 60 * 60 * 24 * 2),
  },
  {
    id: 'rule-002',
    title: 'Suspicious PowerShell Encoded Command',
    description: 'Detects PowerShell execution with encoded commands, commonly used by attackers',
    status: 'active',
    severity: 'high',
    author: 'SOC Team',
    references: ['https://attack.mitre.org/techniques/T1059/001/'],
    tags: ['powershell', 'execution', 'obfuscation'],
    logsources: { category: 'process_creation', product: 'windows' },
    rawYaml: `title: Suspicious PowerShell Encoded Command
status: active
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\powershell.exe'
        CommandLine|contains:
            - '-enc'
            - '-EncodedCommand'
            - '-e '
    condition: selection
level: high`,
    attack: {
      tactics: [{ id: 'TA0002', name: 'Execution' }],
      techniques: [{ id: 'T1059', name: 'Command and Scripting Interpreter', subtechnique: '001' }],
    },
    enabled: true,
    lastTriggered: new Date(Date.now() - 1000 * 60 * 15),
    triggerCount: 234,
    version: 5,
    createdAt: new Date(Date.now() - 1000 * 60 * 60 * 24 * 60),
    updatedAt: new Date(Date.now() - 1000 * 60 * 60 * 24 * 5),
  },
  {
    id: 'rule-003',
    title: 'Credential Dumping via Mimikatz',
    description: 'Detects Mimikatz credential dumping tool execution',
    status: 'active',
    severity: 'critical',
    author: 'SOC Team',
    references: ['https://attack.mitre.org/techniques/T1003/001/'],
    tags: ['mimikatz', 'credential-theft', 'lateral-movement'],
    logsources: { category: 'process_creation', product: 'windows' },
    rawYaml: `title: Credential Dumping via Mimikatz
status: active
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'sekurlsa::logonpasswords'
            - 'lsadump::'
            - 'privilege::debug'
    condition: selection
level: critical`,
    attack: {
      tactics: [{ id: 'TA0006', name: 'Credential Access' }],
      techniques: [{ id: 'T1003', name: 'OS Credential Dumping', subtechnique: '001' }],
    },
    enabled: true,
    lastTriggered: new Date(Date.now() - 1000 * 60 * 60 * 2),
    triggerCount: 12,
    version: 2,
    createdAt: new Date(Date.now() - 1000 * 60 * 60 * 24 * 45),
    updatedAt: new Date(Date.now() - 1000 * 60 * 60 * 24 * 10),
  },
  {
    id: 'rule-004',
    title: 'Phishing Document Execution',
    description: 'Detects execution of Office applications spawning suspicious child processes',
    status: 'active',
    severity: 'high',
    author: 'SOC Team',
    references: ['https://attack.mitre.org/techniques/T1566/001/'],
    tags: ['phishing', 'office', 'macro'],
    logsources: { category: 'process_creation', product: 'windows' },
    rawYaml: `title: Phishing Document Execution
status: active
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith:
            - '\\WINWORD.EXE'
            - '\\EXCEL.EXE'
            - '\\POWERPNT.EXE'
        Image|endswith:
            - '\\cmd.exe'
            - '\\powershell.exe'
            - '\\wscript.exe'
    condition: selection
level: high`,
    attack: {
      tactics: [{ id: 'TA0001', name: 'Initial Access' }],
      techniques: [{ id: 'T1566', name: 'Phishing', subtechnique: '001' }],
    },
    enabled: true,
    lastTriggered: new Date(Date.now() - 1000 * 60 * 45),
    triggerCount: 89,
    version: 4,
    createdAt: new Date(Date.now() - 1000 * 60 * 60 * 24 * 90),
    updatedAt: new Date(Date.now() - 1000 * 60 * 60 * 24 * 7),
  },
  {
    id: 'rule-005',
    title: 'Scheduled Task Creation for Persistence',
    description: 'Detects creation of scheduled tasks commonly used for persistence',
    status: 'active',
    severity: 'medium',
    author: 'SOC Team',
    references: ['https://attack.mitre.org/techniques/T1053/005/'],
    tags: ['persistence', 'scheduled-task', 'windows'],
    logsources: { category: 'process_creation', product: 'windows' },
    rawYaml: `title: Scheduled Task Creation for Persistence
status: active
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\schtasks.exe'
        CommandLine|contains: '/create'
    condition: selection
level: medium`,
    attack: {
      tactics: [{ id: 'TA0003', name: 'Persistence' }],
      techniques: [{ id: 'T1053', name: 'Scheduled Task/Job', subtechnique: '005' }],
    },
    enabled: true,
    lastTriggered: new Date(Date.now() - 1000 * 60 * 120),
    triggerCount: 156,
    version: 2,
    createdAt: new Date(Date.now() - 1000 * 60 * 60 * 24 * 120),
    updatedAt: new Date(Date.now() - 1000 * 60 * 60 * 24 * 30),
  },
  {
    id: 'rule-006',
    title: 'UAC Bypass via Event Viewer',
    description: 'Detects UAC bypass using Event Viewer registry manipulation',
    status: 'active',
    severity: 'high',
    author: 'SOC Team',
    references: ['https://attack.mitre.org/techniques/T1548/002/'],
    tags: ['uac-bypass', 'privilege-escalation', 'registry'],
    logsources: { category: 'registry_set', product: 'windows' },
    rawYaml: `title: UAC Bypass via Event Viewer
status: active
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|contains: 'mscfile\\shell\\open\\command'
    condition: selection
level: high`,
    attack: {
      tactics: [{ id: 'TA0004', name: 'Privilege Escalation' }],
      techniques: [{ id: 'T1548', name: 'Abuse Elevation Control Mechanism', subtechnique: '002' }],
    },
    enabled: true,
    lastTriggered: new Date(Date.now() - 1000 * 60 * 60 * 4),
    triggerCount: 8,
    version: 1,
    createdAt: new Date(Date.now() - 1000 * 60 * 60 * 24 * 15),
    updatedAt: new Date(Date.now() - 1000 * 60 * 60 * 24 * 15),
  },
  {
    id: 'rule-007',
    title: 'AMSI Bypass Attempt',
    description: 'Detects attempts to bypass Windows Antimalware Scan Interface',
    status: 'active',
    severity: 'high',
    author: 'SOC Team',
    references: ['https://attack.mitre.org/techniques/T1562/001/'],
    tags: ['amsi', 'defense-evasion', 'powershell'],
    logsources: { category: 'process_creation', product: 'windows' },
    rawYaml: `title: AMSI Bypass Attempt
status: active
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'AmsiInitFailed'
            - 'amsi.dll'
            - 'AmsiScanBuffer'
    condition: selection
level: high`,
    attack: {
      tactics: [{ id: 'TA0005', name: 'Defense Evasion' }],
      techniques: [{ id: 'T1562', name: 'Impair Defenses', subtechnique: '001' }],
    },
    enabled: true,
    lastTriggered: new Date(Date.now() - 1000 * 60 * 60 * 8),
    triggerCount: 23,
    version: 3,
    createdAt: new Date(Date.now() - 1000 * 60 * 60 * 24 * 50),
    updatedAt: new Date(Date.now() - 1000 * 60 * 60 * 24 * 3),
  },
  {
    id: 'rule-008',
    title: 'Remote Desktop Protocol Brute Force',
    description: 'Detects multiple failed RDP login attempts indicating brute force',
    status: 'active',
    severity: 'medium',
    author: 'SOC Team',
    references: ['https://attack.mitre.org/techniques/T1110/'],
    tags: ['rdp', 'brute-force', 'authentication'],
    logsources: { service: 'security', product: 'windows' },
    rawYaml: `title: Remote Desktop Protocol Brute Force
status: active
logsource:
    service: security
    product: windows
detection:
    selection:
        EventID: 4625
        LogonType: 10
    condition: selection | count() by TargetUserName > 5
level: medium`,
    attack: {
      tactics: [{ id: 'TA0006', name: 'Credential Access' }],
      techniques: [{ id: 'T1110', name: 'Brute Force' }],
    },
    enabled: true,
    lastTriggered: new Date(Date.now() - 1000 * 60 * 5),
    triggerCount: 567,
    version: 2,
    createdAt: new Date(Date.now() - 1000 * 60 * 60 * 24 * 180),
    updatedAt: new Date(Date.now() - 1000 * 60 * 60 * 24 * 14),
  },
  {
    id: 'rule-009',
    title: 'Network Share Discovery',
    description: 'Detects network share enumeration commonly used for lateral movement',
    status: 'active',
    severity: 'low',
    author: 'SOC Team',
    references: ['https://attack.mitre.org/techniques/T1135/'],
    tags: ['discovery', 'network', 'lateral-movement'],
    logsources: { category: 'process_creation', product: 'windows' },
    rawYaml: `title: Network Share Discovery
status: active
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\net.exe'
        CommandLine|contains: 'view'
    condition: selection
level: low`,
    attack: {
      tactics: [{ id: 'TA0007', name: 'Discovery' }],
      techniques: [{ id: 'T1135', name: 'Network Share Discovery' }],
    },
    enabled: true,
    lastTriggered: new Date(Date.now() - 1000 * 60 * 180),
    triggerCount: 1234,
    version: 1,
    createdAt: new Date(Date.now() - 1000 * 60 * 60 * 24 * 200),
    updatedAt: new Date(Date.now() - 1000 * 60 * 60 * 24 * 200),
  },
  {
    id: 'rule-010',
    title: 'PsExec Remote Execution',
    description: 'Detects PsExec usage for remote command execution',
    status: 'active',
    severity: 'medium',
    author: 'SOC Team',
    references: ['https://attack.mitre.org/techniques/T1021/002/'],
    tags: ['psexec', 'lateral-movement', 'remote-execution'],
    logsources: { category: 'process_creation', product: 'windows' },
    rawYaml: `title: PsExec Remote Execution
status: active
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\\psexec.exe'
            - '\\psexec64.exe'
    condition: selection
level: medium`,
    attack: {
      tactics: [{ id: 'TA0008', name: 'Lateral Movement' }],
      techniques: [{ id: 'T1021', name: 'Remote Services', subtechnique: '002' }],
    },
    enabled: true,
    lastTriggered: new Date(Date.now() - 1000 * 60 * 90),
    triggerCount: 78,
    version: 2,
    createdAt: new Date(Date.now() - 1000 * 60 * 60 * 24 * 150),
    updatedAt: new Date(Date.now() - 1000 * 60 * 60 * 24 * 45),
  },
  {
    id: 'rule-011',
    title: 'Suspicious Archive Collection',
    description: 'Detects creation of archive files that may indicate data collection',
    status: 'testing',
    severity: 'medium',
    author: 'SOC Team',
    references: ['https://attack.mitre.org/techniques/T1560/001/'],
    tags: ['collection', 'archive', 'exfiltration-prep'],
    logsources: { category: 'process_creation', product: 'windows' },
    rawYaml: `title: Suspicious Archive Collection
status: testing
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\\7z.exe'
            - '\\rar.exe'
            - '\\zip.exe'
        CommandLine|contains:
            - 'password'
            - '-p'
    condition: selection
level: medium`,
    attack: {
      tactics: [{ id: 'TA0009', name: 'Collection' }],
      techniques: [{ id: 'T1560', name: 'Archive Collected Data', subtechnique: '001' }],
    },
    enabled: true,
    lastTriggered: new Date(Date.now() - 1000 * 60 * 60 * 12),
    triggerCount: 34,
    version: 1,
    createdAt: new Date(Date.now() - 1000 * 60 * 60 * 24 * 7),
    updatedAt: new Date(Date.now() - 1000 * 60 * 60 * 24 * 1),
  },
  {
    id: 'rule-012',
    title: 'Data Exfiltration via Cloud Storage',
    description: 'Detects uploads to cloud storage services that may indicate exfiltration',
    status: 'active',
    severity: 'high',
    author: 'SOC Team',
    references: ['https://attack.mitre.org/techniques/T1567/002/'],
    tags: ['exfiltration', 'cloud', 'data-theft'],
    logsources: { category: 'proxy', product: 'generic' },
    rawYaml: `title: Data Exfiltration via Cloud Storage
status: active
logsource:
    category: proxy
    product: generic
detection:
    selection:
        c-uri|contains:
            - 'dropbox.com/upload'
            - 'drive.google.com/upload'
            - 'onedrive.live.com/upload'
    filter:
        bytes_out: '>10000000'
    condition: selection and filter
level: high`,
    attack: {
      tactics: [{ id: 'TA0010', name: 'Exfiltration' }],
      techniques: [{ id: 'T1567', name: 'Exfiltration Over Web Service', subtechnique: '002' }],
    },
    enabled: true,
    lastTriggered: new Date(Date.now() - 1000 * 60 * 60 * 6),
    triggerCount: 15,
    version: 2,
    createdAt: new Date(Date.now() - 1000 * 60 * 60 * 24 * 60),
    updatedAt: new Date(Date.now() - 1000 * 60 * 60 * 24 * 8),
  },
  {
    id: 'rule-013',
    title: 'WMI Remote Command Execution',
    description: 'Detects WMI being used for remote command execution',
    status: 'active',
    severity: 'medium',
    author: 'SOC Team',
    references: ['https://attack.mitre.org/techniques/T1047/'],
    tags: ['wmi', 'execution', 'lateral-movement'],
    logsources: { category: 'process_creation', product: 'windows' },
    rawYaml: `title: WMI Remote Command Execution
status: active
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\wmic.exe'
        CommandLine|contains:
            - '/node:'
            - 'process call create'
    condition: selection
level: medium`,
    attack: {
      tactics: [
        { id: 'TA0002', name: 'Execution' },
        { id: 'TA0008', name: 'Lateral Movement' },
      ],
      techniques: [{ id: 'T1047', name: 'Windows Management Instrumentation' }],
    },
    enabled: true,
    lastTriggered: new Date(Date.now() - 1000 * 60 * 240),
    triggerCount: 45,
    version: 3,
    createdAt: new Date(Date.now() - 1000 * 60 * 60 * 24 * 100),
    updatedAt: new Date(Date.now() - 1000 * 60 * 60 * 24 * 20),
  },
  {
    id: 'rule-014',
    title: 'Suspicious DNS Query to Dynamic DNS',
    description: 'Detects DNS queries to dynamic DNS providers often used by malware',
    status: 'draft',
    severity: 'low',
    author: 'SOC Team',
    references: ['https://attack.mitre.org/techniques/T1071/004/'],
    tags: ['dns', 'c2', 'dynamic-dns'],
    logsources: { category: 'dns', product: 'generic' },
    rawYaml: `title: Suspicious DNS Query to Dynamic DNS
status: draft
logsource:
    category: dns
    product: generic
detection:
    selection:
        query|endswith:
            - '.duckdns.org'
            - '.no-ip.org'
            - '.ddns.net'
    condition: selection
level: low`,
    attack: {
      tactics: [{ id: 'TA0011', name: 'Command and Control' }],
      techniques: [{ id: 'T1071', name: 'Application Layer Protocol', subtechnique: '004' }],
    },
    enabled: false,
    triggerCount: 0,
    version: 1,
    createdAt: new Date(Date.now() - 1000 * 60 * 60 * 24 * 2),
    updatedAt: new Date(Date.now() - 1000 * 60 * 60 * 24 * 2),
  },
  {
    id: 'rule-015',
    title: 'Service Stop for Disruption',
    description: 'Detects stopping of critical services which may indicate ransomware or sabotage',
    status: 'active',
    severity: 'high',
    author: 'SOC Team',
    references: ['https://attack.mitre.org/techniques/T1489/'],
    tags: ['impact', 'service-stop', 'ransomware'],
    logsources: { category: 'process_creation', product: 'windows' },
    rawYaml: `title: Service Stop for Disruption
status: active
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\sc.exe'
        CommandLine|contains: 'stop'
    filter:
        CommandLine|contains:
            - 'vss'
            - 'sql'
            - 'backup'
    condition: selection and filter
level: high`,
    attack: {
      tactics: [{ id: 'TA0040', name: 'Impact' }],
      techniques: [{ id: 'T1489', name: 'Service Stop' }],
    },
    enabled: true,
    lastTriggered: new Date(Date.now() - 1000 * 60 * 60 * 24),
    triggerCount: 5,
    version: 2,
    createdAt: new Date(Date.now() - 1000 * 60 * 60 * 24 * 40),
    updatedAt: new Date(Date.now() - 1000 * 60 * 60 * 24 * 12),
  },
  {
    id: 'rule-016',
    title: 'Linux Privilege Escalation via Sudo',
    description: 'Detects suspicious sudo usage that may indicate privilege escalation',
    status: 'active',
    severity: 'medium',
    author: 'SOC Team',
    references: ['https://attack.mitre.org/techniques/T1548/003/'],
    tags: ['linux', 'sudo', 'privilege-escalation'],
    logsources: { category: 'process_creation', product: 'linux' },
    rawYaml: `title: Linux Privilege Escalation via Sudo
status: active
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image: '/usr/bin/sudo'
        CommandLine|contains:
            - 'NOPASSWD'
            - '/bin/bash'
            - '/bin/sh'
    condition: selection
level: medium`,
    attack: {
      tactics: [{ id: 'TA0004', name: 'Privilege Escalation' }],
      techniques: [{ id: 'T1548', name: 'Abuse Elevation Control Mechanism', subtechnique: '003' }],
    },
    enabled: true,
    lastTriggered: new Date(Date.now() - 1000 * 60 * 60 * 3),
    triggerCount: 67,
    version: 1,
    createdAt: new Date(Date.now() - 1000 * 60 * 60 * 24 * 25),
    updatedAt: new Date(Date.now() - 1000 * 60 * 60 * 24 * 25),
  },
];

// Common techniques by tactic for ATT&CK matrix
const TECHNIQUES_BY_TACTIC: Record<string, AttackTechnique[]> = {
  TA0001: [
    { id: 'T1566', name: 'Phishing', subtechnique: '001' },
    { id: 'T1190', name: 'Exploit Public-Facing Application' },
    { id: 'T1133', name: 'External Remote Services' },
    { id: 'T1078', name: 'Valid Accounts' },
  ],
  TA0002: [
    { id: 'T1059', name: 'Command and Scripting Interpreter', subtechnique: '001' },
    { id: 'T1047', name: 'Windows Management Instrumentation' },
    { id: 'T1053', name: 'Scheduled Task/Job' },
    { id: 'T1204', name: 'User Execution' },
  ],
  TA0003: [
    { id: 'T1053', name: 'Scheduled Task/Job', subtechnique: '005' },
    { id: 'T1547', name: 'Boot or Logon Autostart Execution' },
    { id: 'T1543', name: 'Create or Modify System Process' },
    { id: 'T1136', name: 'Create Account' },
  ],
  TA0004: [
    { id: 'T1548', name: 'Abuse Elevation Control Mechanism', subtechnique: '002' },
    { id: 'T1068', name: 'Exploitation for Privilege Escalation' },
    { id: 'T1134', name: 'Access Token Manipulation' },
  ],
  TA0005: [
    { id: 'T1562', name: 'Impair Defenses', subtechnique: '001' },
    { id: 'T1070', name: 'Indicator Removal' },
    { id: 'T1027', name: 'Obfuscated Files or Information' },
    { id: 'T1055', name: 'Process Injection' },
  ],
  TA0006: [
    { id: 'T1003', name: 'OS Credential Dumping', subtechnique: '001' },
    { id: 'T1110', name: 'Brute Force' },
    { id: 'T1555', name: 'Credentials from Password Stores' },
    { id: 'T1558', name: 'Steal or Forge Kerberos Tickets' },
  ],
  TA0007: [
    { id: 'T1135', name: 'Network Share Discovery' },
    { id: 'T1046', name: 'Network Service Discovery' },
    { id: 'T1082', name: 'System Information Discovery' },
    { id: 'T1087', name: 'Account Discovery' },
  ],
  TA0008: [
    { id: 'T1021', name: 'Remote Services', subtechnique: '002' },
    { id: 'T1570', name: 'Lateral Tool Transfer' },
    { id: 'T1080', name: 'Taint Shared Content' },
  ],
  TA0009: [
    { id: 'T1560', name: 'Archive Collected Data', subtechnique: '001' },
    { id: 'T1005', name: 'Data from Local System' },
    { id: 'T1114', name: 'Email Collection' },
    { id: 'T1039', name: 'Data from Network Shared Drive' },
  ],
  TA0010: [
    { id: 'T1567', name: 'Exfiltration Over Web Service', subtechnique: '002' },
    { id: 'T1048', name: 'Exfiltration Over Alternative Protocol' },
    { id: 'T1041', name: 'Exfiltration Over C2 Channel' },
  ],
  TA0040: [
    { id: 'T1486', name: 'Data Encrypted for Impact' },
    { id: 'T1489', name: 'Service Stop' },
    { id: 'T1485', name: 'Data Destruction' },
    { id: 'T1490', name: 'Inhibit System Recovery' },
  ],
};

export function useRules() {
  const [rules, setRules] = useState<SigmaRule[]>(mockSigmaRules);
  const [selectedRule, setSelectedRule] = useState<SigmaRule | null>(null);
  const [filters, setFilters] = useState({
    search: '',
    status: 'all',
    severity: 'all',
    tactic: 'all',
  });

  const filteredRules = useMemo(() => {
    return rules.filter((rule) => {
      // Search filter
      if (
        filters.search &&
        !rule.title.toLowerCase().includes(filters.search.toLowerCase()) &&
        !rule.id.toLowerCase().includes(filters.search.toLowerCase()) &&
        !rule.description.toLowerCase().includes(filters.search.toLowerCase())
      ) {
        return false;
      }

      // Status filter
      if (filters.status !== 'all' && rule.status !== filters.status) {
        return false;
      }

      // Severity filter
      if (filters.severity !== 'all' && rule.severity !== filters.severity) {
        return false;
      }

      // Tactic filter
      if (
        filters.tactic !== 'all' &&
        !rule.attack.tactics.some((t) => t.id === filters.tactic)
      ) {
        return false;
      }

      return true;
    });
  }, [rules, filters]);

  const updateRule = useCallback((ruleId: string, updates: Partial<SigmaRule>) => {
    setRules((prev) =>
      prev.map((rule) =>
        rule.id === ruleId
          ? { ...rule, ...updates, updatedAt: new Date(), version: rule.version + 1 }
          : rule
      )
    );
  }, []);

  const toggleRuleEnabled = useCallback((ruleId: string) => {
    setRules((prev) =>
      prev.map((rule) =>
        rule.id === ruleId
          ? { ...rule, enabled: !rule.enabled, updatedAt: new Date() }
          : rule
      )
    );
  }, []);

  const deleteRule = useCallback((ruleId: string) => {
    setRules((prev) => prev.filter((rule) => rule.id !== ruleId));
    if (selectedRule?.id === ruleId) {
      setSelectedRule(null);
    }
  }, [selectedRule]);

  const createRule = useCallback((ruleData: Partial<SigmaRule>) => {
    const newRule: SigmaRule = {
      id: `rule-${Date.now()}`,
      title: ruleData.title || 'Untitled Rule',
      description: ruleData.description || '',
      status: ruleData.status || 'draft',
      severity: ruleData.severity || 'medium',
      author: ruleData.author || 'SOC Team',
      references: ruleData.references || [],
      tags: ruleData.tags || [],
      logsources: ruleData.logsources || {},
      rawYaml: ruleData.rawYaml || '',
      attack: ruleData.attack || { tactics: [], techniques: [] },
      enabled: ruleData.enabled ?? false,
      lastTriggered: ruleData.lastTriggered,
      triggerCount: ruleData.triggerCount || 0,
      version: 1,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    setRules((prev) => [newRule, ...prev]);
    return newRule;
  }, []);

  const testRule = useCallback(async (ruleId: string, testEvents: object[]): Promise<RuleTestResult> => {
    // Simulate rule testing
    await new Promise((resolve) => setTimeout(resolve, 1500));

    const matchedCount = Math.floor(Math.random() * testEvents.length);
    const matches = Array.from({ length: matchedCount }, (_, i) => ({
      eventIndex: i,
      matchedConditions: ['selection'],
    }));

    return {
      success: true,
      matchedEvents: matchedCount,
      totalEvents: testEvents.length,
      matches,
      executionTime: Math.floor(Math.random() * 500) + 100,
    };
  }, []);

  return {
    rules,
    filteredRules,
    selectedRule,
    setSelectedRule,
    filters,
    setFilters,
    updateRule,
    toggleRuleEnabled,
    deleteRule,
    createRule,
    testRule,
  };
}

export function useAttackMatrix() {
  const [selectedTechnique, setSelectedTechnique] = useState<string | null>(null);
  const [rules] = useState<SigmaRule[]>(mockSigmaRules);

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
