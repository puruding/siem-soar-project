# SOAR Playbooks Index

**Total Playbooks:** 50
**Last Updated:** 2026-02-04

---

## 1. Enrichment (7 playbooks)

| # | Playbook | Description | Severity |
|---|----------|-------------|----------|
| 1 | cve_enrichment.yaml | Enrich CVE information from NVD/MITRE | Medium |
| 2 | domain_enrichment.yaml | Enrich domain reputation and WHOIS | Medium |
| 3 | email_enrichment.yaml | Enrich email sender and headers | Low |
| 4 | hash_enrichment.yaml | Check file hash reputation | High |
| 5 | ip_enrichment.yaml | Enrich IP geolocation and reputation | Medium |
| 6 | url_enrichment.yaml | Check URL reputation and analysis | Medium |
| 7 | user_enrichment.yaml | Enrich user context from AD/HR | Low |

---

## 2. Containment (5 playbooks)

| # | Playbook | Description | Severity |
|---|----------|-------------|----------|
| 1 | block_domain.yaml | Block malicious domain in DNS/firewall | High |
| 2 | block_ip.yaml | Block malicious IP in firewall | High |
| 3 | disable_user.yaml | Disable compromised user account | High |
| 4 | isolate_host.yaml | Isolate infected endpoint from network | Critical |
| 5 | quarantine_file.yaml | Quarantine malicious file | High |

---

## 3. Notification (10 playbooks)

| # | Playbook | Description | Severity | Trigger |
|---|----------|-------------|----------|---------|
| 1 | alert_notification.yaml | Send multi-channel alert notifications | Medium | Alert |
| 2 | incident_report.yaml | Generate and distribute incident reports | Medium | Manual |
| 3 | escalation.yaml | Escalate incidents to management | High | SLA |
| 4 | daily_summary.yaml | Daily security summary report | Low | Cron (9am daily) |
| 5 | weekly_report.yaml | Weekly security metrics report | Low | Cron (9am Mon) |
| 6 | sla_breach.yaml | Alert on SLA breaches | High | SLA Breach |
| 7 | executive_summary.yaml | Monthly executive summary | Low | Cron (10am 1st) |
| 8 | on_call_alert.yaml | Page on-call team for critical alerts | Critical | Alert |
| 9 | compliance_alert.yaml | Alert compliance team on violations | High | Alert |
| 10 | threat_brief.yaml | Daily threat intelligence briefing | Medium | Cron (8am daily) |

---

## 4. Remediation (10 playbooks)

| # | Playbook | Description | Severity |
|---|----------|-------------|----------|
| 1 | malware_cleanup.yaml | Remove malware and restore system | High |
| 2 | account_recovery.yaml | Recover compromised user accounts | High |
| 3 | password_reset.yaml | Force password reset for affected users | Medium |
| 4 | system_restore.yaml | Restore system from backup | High |
| 5 | patch_deployment.yaml | Deploy security patches | High |
| 6 | backup_restore.yaml | Restore data from backup | High |
| 7 | certificate_renewal.yaml | Renew expiring/compromised certificates | Medium |
| 8 | service_restart.yaml | Restart services after updates | Low |
| 9 | config_rollback.yaml | Rollback configuration changes | High |
| 10 | data_recovery.yaml | Recover encrypted or deleted data | Critical |

---

## 5. Investigation (10 playbooks)

| # | Playbook | Description | Severity |
|---|----------|-------------|----------|
| 1 | phishing_investigation.yaml | Investigate phishing emails | Medium |
| 2 | malware_analysis.yaml | Analyze malware in sandbox | High |
| 3 | data_breach_investigation.yaml | Investigate data breaches | Critical |
| 4 | insider_threat.yaml | Investigate insider threat indicators | High |
| 5 | brute_force_investigation.yaml | Investigate brute force attacks | High |
| 6 | lateral_movement.yaml | Investigate lateral movement | Critical |
| 7 | c2_detection.yaml | Detect C2 communications | Critical |
| 8 | privilege_escalation.yaml | Investigate privilege escalation | High |
| 9 | data_exfiltration.yaml | Investigate data exfiltration | Critical |
| 10 | ransomware_investigation.yaml | Investigate ransomware infection | Critical |

---

## 6. Compliance (8 playbooks)

| # | Playbook | Description | Severity | Regulation |
|---|----------|-------------|----------|------------|
| 1 | gdpr_breach.yaml | GDPR breach notification (72h deadline) | Critical | GDPR |
| 2 | pci_incident.yaml | PCI-DSS incident response | High | PCI-DSS |
| 3 | hipaa_violation.yaml | HIPAA violation and breach notification | Critical | HIPAA |
| 4 | sox_audit.yaml | SOX compliance audit response | Medium | SOX |
| 5 | iso27001_review.yaml | ISO 27001 compliance review | Low | ISO 27001 |
| 6 | evidence_collection.yaml | Collect and preserve digital evidence | High | Legal |
| 7 | chain_of_custody.yaml | Maintain chain of custody | High | Legal |
| 8 | regulatory_report.yaml | Generate regulatory reports | Medium | Multi |

---

## Playbook Categories Summary

| Category | Count | Average Severity | Auto-triggered |
|----------|-------|------------------|----------------|
| Enrichment | 7 | Medium | Yes (on alert) |
| Containment | 5 | High | Yes (on detection) |
| Notification | 10 | Medium | Mixed (alert/cron) |
| Remediation | 10 | High | Manual/Automated |
| Investigation | 10 | High | Manual |
| Compliance | 8 | High | Mixed |
| **Total** | **50** | **High** | **60%** |

---

## Severity Distribution

- **Critical:** 7 playbooks (14%)
- **High:** 24 playbooks (48%)
- **Medium:** 14 playbooks (28%)
- **Low:** 5 playbooks (10%)

---

## Trigger Types

- **Alert-triggered:** 15 playbooks (30%)
- **Manual:** 20 playbooks (40%)
- **Scheduled (cron):** 5 playbooks (10%)
- **SLA/Event-triggered:** 5 playbooks (10%)
- **Auto-detection:** 5 playbooks (10%)

---

## Integration Coverage

### External Systems
- **EDR:** 8 playbooks (CrowdStrike, Carbon Black, SentinelOne)
- **Active Directory:** 6 playbooks
- **Email Security:** 4 playbooks
- **Threat Intelligence:** 12 playbooks (VirusTotal, ThreatConnect, MISP)
- **Firewall:** 5 playbooks (Palo Alto, Cisco, pfSense)
- **Sandbox:** 3 playbooks (Cuckoo, Joe Sandbox)
- **Backup:** 3 playbooks (Veeam, Commvault)
- **Ticketing:** 5 playbooks (Jira, ServiceNow)
- **Communication:** 10 playbooks (Slack, Teams, PagerDuty, Email, SMS)

---

## Usage Guidelines

### Running a Playbook

```bash
# Via CLI
soar-cli run enrichment/ip_enrichment.yaml --input '{"ip": "192.168.1.100"}'

# Via API
curl -X POST http://localhost:8080/api/v1/playbooks/execute \
  -H "Content-Type: application/json" \
  -d '{
    "playbook": "enrichment/ip_enrichment",
    "inputs": {"ip": "192.168.1.100"}
  }'

# Via Web UI
Navigate to Playbooks → Select playbook → Click "Execute"
```

### Scheduling a Playbook

```yaml
# Add to playbook YAML
trigger:
  type: schedule
  cron: "0 9 * * *"  # 9am daily
```

### Creating Custom Playbooks

1. Copy existing playbook as template
2. Modify steps and actions
3. Validate with `soar-cli validate playbook.yaml`
4. Test in non-production environment
5. Deploy to production

---

## Metrics

Track playbook effectiveness:

- **Execution count:** Number of times executed
- **Success rate:** Percentage of successful executions
- **Average duration:** Time to complete
- **Error rate:** Percentage of failures
- **Impact:** Incidents resolved, threats blocked

---

## Support

- **Documentation:** `/docs/playbooks/`
- **Examples:** `/examples/playbooks/`
- **API Reference:** `/docs/api/playbooks.md`
- **Community:** https://community.company.com/soar
- **Support:** soar-support@company.com

---

**Generated:** 2026-02-04
**Version:** 1.0
**Status:** Production Ready
