# SIEM/SOAR Platform User Guide

## Introduction

Welcome to the SIEM/SOAR Platform User Guide. This guide covers how to use the platform for security monitoring, alert investigation, and incident response.

## Getting Started

### Logging In

1. Navigate to `https://siem.example.com`
2. Enter your credentials (SSO or local account)
3. Complete MFA if enabled
4. You'll land on the Dashboard

### Dashboard Overview

The dashboard provides at-a-glance visibility into your security posture:

- **Alert Summary**: Count of alerts by severity
- **Event Trends**: Event volume over time
- **Active Cases**: Open investigations
- **System Health**: Service status indicators

## Working with Alerts

### Viewing Alerts

Navigate to **Alerts** in the main menu to see all alerts.

**Filters available:**
- Severity: Low, Medium, High, Critical
- Status: New, Investigating, Resolved, Closed
- Source: Detection Engine, EDR, WAF, etc.
- Time Range: Last hour, 24 hours, 7 days, custom

### Alert Details

Click an alert to view details:

- **Summary**: Title, description, severity
- **Indicators**: IPs, domains, hashes involved
- **Timeline**: When events occurred
- **Related Alerts**: Correlated alerts
- **MITRE ATT&CK**: Mapped tactics and techniques

### Triaging Alerts

1. Open the alert
2. Review the details and related events
3. Use the AI assistant for investigation help:
   - Click **"Investigate with AI"**
   - Review suggested actions
4. Update status:
   - **Investigating**: You're working on it
   - **False Positive**: Mark and provide reason
   - **Resolved**: Issue addressed
   - **Escalate**: Create a case

### Using AI Triage

The platform includes AI-powered triage to help prioritize:

1. Select alerts to triage
2. Click **"AI Triage"**
3. Review prioritized list with explanations
4. Accept or override AI recommendations

## Query & Search

### Natural Language Queries

Ask questions in plain English:

**Examples:**
- "Show me failed logins in the last hour"
- "What are the top 10 source IPs for SSH attacks?"
- "Find all events from IP 192.168.1.100"

The system converts your question to SQL and returns results.

### Advanced Queries

For complex searches, use SQL directly:

```sql
SELECT
    src_ip,
    count(*) as attempts
FROM events
WHERE event_type = 'auth_failure'
    AND timestamp >= now() - INTERVAL 1 HOUR
GROUP BY src_ip
HAVING attempts > 5
ORDER BY attempts DESC
```

### Saved Searches

Save frequently used queries:

1. Run your query
2. Click **"Save Query"**
3. Give it a name and description
4. Access later from **Saved Searches**

## Case Management

### Creating a Case

Cases track investigations through resolution.

1. From an alert, click **"Create Case"**
2. Or go to **Cases** → **New Case**
3. Fill in:
   - Title: Descriptive name
   - Severity: Impact level
   - Description: What happened
   - Related Alerts: Link relevant alerts

### Working a Case

**Timeline**: Document your investigation
- Add notes with findings
- Upload evidence (screenshots, logs)
- Track actions taken

**Evidence Collection**:
- Click **"Add Evidence"**
- Upload files or link external resources
- Evidence is automatically hashed and timestamped

**Collaboration**:
- Assign to team members
- Add collaborators
- Use @mentions in notes

### Closing a Case

1. Document resolution in notes
2. Set status to **Resolved** or **Closed**
3. Select resolution type:
   - True Positive
   - False Positive
   - Benign
4. Write resolution summary
5. Click **Close Case**

## Playbooks & Automation

### Running a Playbook

Playbooks automate response actions.

**Manual Execution:**
1. From an alert or case, click **"Run Playbook"**
2. Select appropriate playbook
3. Review and confirm parameters
4. Click **Execute**
5. Monitor execution progress

**Automatic Execution:**
Playbooks can trigger automatically based on:
- Alert conditions
- Schedules
- API calls

### Monitoring Executions

View playbook runs:

1. Go to **SOAR** → **Executions**
2. See status: Running, Completed, Failed
3. Click to view step-by-step progress
4. Review action outputs

### Approvals

Some actions require human approval:

1. You'll receive notification
2. Review the proposed action
3. Click **Approve** or **Reject**
4. Optionally add comment

## AI Copilot

### Getting Help

The AI Copilot assists with:

- Explaining alerts
- Suggesting investigation steps
- Answering security questions
- Generating detection rules

**How to use:**
1. Click the **Copilot** button (or press `/`)
2. Ask your question
3. Review the response
4. Follow suggested actions

### Example Interactions

**Explain an alert:**
> "Can you explain this malware alert?"

**Investigation guidance:**
> "What should I check for this suspicious login?"

**Generate a rule:**
> "Create a rule to detect PowerShell downloading files"

## Reports & Analytics

### Built-in Reports

Access from **Reports** menu:

- **Executive Summary**: High-level security posture
- **Alert Trends**: Volume and patterns over time
- **MTTR Report**: Mean time to respond/resolve
- **Top Threats**: Most common attack types

### Custom Reports

1. Go to **Reports** → **Create Report**
2. Select data sources and metrics
3. Configure visualizations
4. Set schedule (optional)
5. Save and share

### Exporting Data

Export options:
- PDF for presentations
- CSV for spreadsheets
- JSON for integrations

## Settings & Preferences

### User Settings

Customize your experience:

- **Notifications**: Email, Slack, webhook
- **Dashboard**: Default widgets
- **Time Zone**: Display preference
- **Theme**: Light/dark mode

### API Keys

Generate API keys for integrations:

1. Go to **Settings** → **API Keys**
2. Click **Generate New Key**
3. Copy and store securely
4. Use in API requests

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `/` | Open Copilot |
| `g a` | Go to Alerts |
| `g c` | Go to Cases |
| `g d` | Go to Dashboard |
| `n` | New (context-sensitive) |
| `?` | Show shortcuts |

## Getting Help

### In-App Help

- Click **?** for contextual help
- Use Copilot for questions
- Access documentation via Help menu

### Support

- Email: support@example.com
- Slack: #siem-support
- Documentation: https://docs.siem.example.com

---

*Last Updated: January 2024*
