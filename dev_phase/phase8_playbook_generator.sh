#!/bin/bash

# Phase 8: Generate remaining SOAR playbooks

PROJECT_ROOT="C:/11.develop_home/13.orchestration/deep_research/siem-soar-project"
PLAYBOOK_DIR="$PROJECT_ROOT/services/soar/playbooks"

echo "Generating Phase 8 SOAR playbooks..."

# Create remaining notification playbooks (9 more)
cat > "$PLAYBOOK_DIR/notification/incident_report.yaml" << 'EOF'
name: incident_report
version: "1.0"
description: Generate and distribute incident reports
category: notification
severity: medium
steps:
  - id: collect_incident_data
    action: case.get_details
  - id: generate_report
    action: report.generate
    template: incident_report
  - id: send_report
    action: email.send
    params:
      subject: "Incident Report: {{case_id}}"
      attachments: ["{{steps.generate_report.output}}"]
EOF

cat > "$PLAYBOOK_DIR/notification/escalation.yaml" << 'EOF'
name: escalation
version: "1.0"
description: Escalate incidents to management and stakeholders
category: notification
severity: high
steps:
  - id: check_sla
    action: case.check_sla_status
  - id: identify_escalation_path
    action: script
    script: |
      const path = input.severity === 'critical' ? 'executive' : 'manager';
      return {escalation_level: path};
  - id: notify_management
    action: email.send
    params:
      to: "{{config.management_email}}"
      subject: "ESCALATION: {{input.title}}"
EOF

cat > "$PLAYBOOK_DIR/notification/daily_summary.yaml" << 'EOF'
name: daily_summary
version: "1.0"
description: Send daily security summary reports
category: notification
trigger:
  type: schedule
  cron: "0 9 * * *"
steps:
  - id: collect_stats
    action: metrics.aggregate
    params:
      period: last_24h
  - id: generate_summary
    action: report.generate
    template: daily_summary
  - id: send_email
    action: email.send
EOF

cat > "$PLAYBOOK_DIR/notification/weekly_report.yaml" << 'EOF'
name: weekly_report
version: "1.0"
description: Weekly security metrics and trends report
category: notification
trigger:
  type: schedule
  cron: "0 9 * * 1"
steps:
  - id: aggregate_metrics
    action: metrics.aggregate
    params:
      period: last_7d
  - id: identify_trends
    action: analytics.detect_trends
  - id: generate_report
    action: report.generate
  - id: distribute_report
    action: email.send
    params:
      to: ["security-team@company.com"]
EOF

cat > "$PLAYBOOK_DIR/notification/sla_breach.yaml" << 'EOF'
name: sla_breach
version: "1.0"
description: Alert on SLA breaches for cases
category: notification
trigger:
  type: sla_breach
steps:
  - id: get_case_details
    action: case.get
  - id: notify_assignee
    action: email.send
  - id: notify_management
    action: slack.send
  - id: create_escalation_ticket
    action: jira.create_issue
EOF

cat > "$PLAYBOOK_DIR/notification/executive_summary.yaml" << 'EOF'
name: executive_summary
version: "1.0"
description: Monthly executive security summary
category: notification
trigger:
  type: schedule
  cron: "0 10 1 * *"
steps:
  - id: collect_monthly_stats
    action: metrics.aggregate
    params:
      period: last_30d
  - id: generate_executive_summary
    action: report.generate
    template: executive_summary
  - id: send_to_executives
    action: email.send
    params:
      to: ["ciso@company.com", "ceo@company.com"]
EOF

cat > "$PLAYBOOK_DIR/notification/on_call_alert.yaml" << 'EOF'
name: on_call_alert
version: "1.0"
description: Alert on-call team for critical incidents
category: notification
severity: critical
steps:
  - id: get_oncall_schedule
    action: pagerduty.get_oncall
  - id: page_oncall
    action: pagerduty.create_incident
  - id: send_sms
    action: sms.send
  - id: call_phone
    action: phone.call
    condition: "input.severity == 'critical'"
EOF

cat > "$PLAYBOOK_DIR/notification/compliance_alert.yaml" << 'EOF'
name: compliance_alert
version: "1.0"
description: Alert compliance team on security violations
category: notification
severity: high
steps:
  - id: categorize_violation
    action: script
  - id: notify_compliance
    action: email.send
    params:
      to: ["compliance@company.com"]
  - id: create_audit_record
    action: audit.create_entry
EOF

cat > "$PLAYBOOK_DIR/notification/threat_brief.yaml" << 'EOF'
name: threat_brief
version: "1.0"
description: Daily threat intelligence briefing
category: notification
trigger:
  type: schedule
  cron: "0 8 * * *"
steps:
  - id: fetch_threat_intel
    action: ti.get_latest_threats
  - id: correlate_with_environment
    action: ti.correlate
  - id: generate_brief
    action: report.generate
  - id: send_brief
    action: email.send
EOF

# Create remediation playbooks (10 total)
cat > "$PLAYBOOK_DIR/remediation/malware_cleanup.yaml" << 'EOF'
name: malware_cleanup
version: "1.0"
description: Remove malware and restore system integrity
category: remediation
severity: high
steps:
  - id: isolate_host
    action: edr.isolate_endpoint
  - id: scan_for_malware
    action: edr.full_scan
  - id: remove_malware
    action: edr.quarantine
  - id: verify_removal
    action: edr.verify_clean
  - id: restore_from_backup
    condition: "steps.verify_removal.status != 'clean'"
    action: backup.restore
  - id: reconnect_host
    action: edr.release_isolation
EOF

cat > "$PLAYBOOK_DIR/remediation/account_recovery.yaml" << 'EOF'
name: account_recovery
version: "1.0"
description: Recover compromised user accounts
category: remediation
severity: high
steps:
  - id: disable_account
    action: ad.disable_user
  - id: reset_password
    action: ad.reset_password
  - id: revoke_sessions
    action: auth.revoke_all_sessions
  - id: revoke_tokens
    action: auth.revoke_tokens
  - id: enable_mfa
    action: auth.enforce_mfa
  - id: notify_user
    action: email.send
  - id: re_enable_account
    action: ad.enable_user
EOF

cat > "$PLAYBOOK_DIR/remediation/password_reset.yaml" << 'EOF'
name: password_reset
version: "1.0"
description: Force password reset for affected accounts
category: remediation
severity: medium
steps:
  - id: identify_affected_users
    action: ad.query_users
  - id: force_password_change
    action: ad.set_password_must_change
  - id: revoke_active_sessions
    action: auth.revoke_sessions
  - id: notify_users
    action: email.send_bulk
EOF

cat > "$PLAYBOOK_DIR/remediation/system_restore.yaml" << 'EOF'
name: system_restore
version: "1.0"
description: Restore system from backup after compromise
category: remediation
severity: high
steps:
  - id: verify_backup_integrity
    action: backup.verify
  - id: shutdown_system
    action: system.shutdown
  - id: restore_from_backup
    action: backup.restore
  - id: verify_restoration
    action: system.health_check
  - id: apply_security_patches
    action: patch.apply_updates
  - id: restart_system
    action: system.start
EOF

cat > "$PLAYBOOK_DIR/remediation/patch_deployment.yaml" << 'EOF'
name: patch_deployment
version: "1.0"
description: Deploy security patches to vulnerable systems
category: remediation
severity: high
steps:
  - id: identify_vulnerable_systems
    action: vuln_scan.get_affected_hosts
  - id: test_patch
    action: patch.test_deployment
    params:
      target: test_environment
  - id: schedule_maintenance
    action: schedule.create_window
  - id: deploy_patches
    action: patch.deploy
  - id: verify_deployment
    action: patch.verify
  - id: reboot_if_required
    action: system.reboot
EOF

cat > "$PLAYBOOK_DIR/remediation/backup_restore.yaml" << 'EOF'
name: backup_restore
version: "1.0"
description: Restore data from backup after data loss
category: remediation
severity: high
steps:
  - id: identify_restore_point
    action: backup.list_snapshots
  - id: validate_backup
    action: backup.verify_integrity
  - id: prepare_restore
    action: system.prepare_restore
  - id: restore_data
    action: backup.restore
  - id: verify_data
    action: data.verify_integrity
EOF

cat > "$PLAYBOOK_DIR/remediation/certificate_renewal.yaml" << 'EOF'
name: certificate_renewal
version: "1.0"
description: Renew expiring or compromised certificates
category: remediation
severity: medium
steps:
  - id: revoke_old_certificate
    action: pki.revoke_cert
  - id: generate_csr
    action: pki.generate_csr
  - id: request_new_certificate
    action: pki.request_cert
  - id: install_certificate
    action: pki.install_cert
  - id: verify_installation
    action: pki.verify_cert
EOF

cat > "$PLAYBOOK_DIR/remediation/service_restart.yaml" << 'EOF'
name: service_restart
version: "1.0"
description: Restart services after security updates
category: remediation
severity: low
steps:
  - id: stop_service
    action: system.stop_service
  - id: verify_stopped
    action: system.check_service_status
  - id: clear_cache
    action: system.clear_cache
  - id: start_service
    action: system.start_service
  - id: health_check
    action: system.health_check
EOF

cat > "$PLAYBOOK_DIR/remediation/config_rollback.yaml" << 'EOF'
name: config_rollback
version: "1.0"
description: Rollback configuration changes after security incident
category: remediation
severity: high
steps:
  - id: get_last_known_good_config
    action: config.get_backup
  - id: backup_current_config
    action: config.backup
  - id: apply_rollback
    action: config.apply
  - id: verify_rollback
    action: system.verify_config
  - id: restart_services
    action: system.restart_all
EOF

cat > "$PLAYBOOK_DIR/remediation/data_recovery.yaml" << 'EOF'
name: data_recovery
version: "1.0"
description: Recover encrypted or deleted data
category: remediation
severity: critical
steps:
  - id: assess_data_loss
    action: data.assess_damage
  - id: identify_recovery_method
    action: script
  - id: recover_from_backup
    action: backup.restore
  - id: decrypt_data
    condition: "input.encrypted == true"
    action: crypto.decrypt
  - id: verify_recovery
    action: data.verify_integrity
EOF

# Create investigation playbooks (10 total)
cat > "$PLAYBOOK_DIR/investigation/phishing_investigation.yaml" << 'EOF'
name: phishing_investigation
version: "1.0"
description: Investigate suspected phishing emails
category: investigation
severity: medium
steps:
  - id: extract_email_headers
    action: email.parse_headers
  - id: analyze_sender
    action: ti.check_sender_reputation
  - id: extract_urls
    action: email.extract_urls
  - id: check_url_reputation
    action: ti.check_urls
  - id: extract_attachments
    action: email.extract_attachments
  - id: scan_attachments
    action: sandbox.analyze_file
  - id: identify_recipients
    action: email.get_recipients
  - id: check_recipient_actions
    action: email.check_opened
EOF

cat > "$PLAYBOOK_DIR/investigation/malware_analysis.yaml" << 'EOF'
name: malware_analysis
version: "1.0"
description: Analyze malware samples in sandbox
category: investigation
severity: high
steps:
  - id: collect_sample
    action: edr.collect_file
  - id: calculate_hashes
    action: crypto.hash_file
  - id: check_threat_intel
    action: ti.check_file_hash
  - id: submit_to_sandbox
    action: sandbox.submit
  - id: analyze_behavior
    action: sandbox.get_results
  - id: extract_iocs
    action: sandbox.extract_iocs
EOF

cat > "$PLAYBOOK_DIR/investigation/data_breach_investigation.yaml" << 'EOF'
name: data_breach_investigation
version: "1.0"
description: Investigate potential data breach
category: investigation
severity: critical
steps:
  - id: identify_data_accessed
    action: audit.query_access_logs
  - id: determine_breach_scope
    action: data.assess_exposure
  - id: identify_attacker
    action: forensics.analyze_logs
  - id: trace_exfiltration
    action: network.trace_connections
  - id: assess_impact
    action: compliance.assess_breach_impact
  - id: preserve_evidence
    action: forensics.collect_evidence
EOF

cat > "$PLAYBOOK_DIR/investigation/insider_threat.yaml" << 'EOF'
name: insider_threat
version: "1.0"
description: Investigate insider threat indicators
category: investigation
severity: high
steps:
  - id: collect_user_activity
    action: ueba.get_user_behavior
  - id: analyze_access_patterns
    action: ueba.analyze_anomalies
  - id: check_data_access
    action: dlp.check_data_access
  - id: review_email_activity
    action: email.get_user_emails
  - id: check_file_transfers
    action: dlp.check_transfers
  - id: interview_manager
    action: hr.notify_manager
EOF

cat > "$PLAYBOOK_DIR/investigation/brute_force_investigation.yaml" << 'EOF'
name: brute_force_investigation
version: "1.0"
description: Investigate brute force attack attempts
category: investigation
severity: high
steps:
  - id: identify_attack_source
    action: auth.get_failed_logins
  - id: check_ip_reputation
    action: ti.check_ip
  - id: identify_targeted_accounts
    action: auth.get_target_users
  - id: check_account_compromise
    action: auth.check_successful_logins
  - id: block_attacker_ip
    action: firewall.block_ip
EOF

cat > "$PLAYBOOK_DIR/investigation/lateral_movement.yaml" << 'EOF'
name: lateral_movement
version: "1.0"
description: Investigate lateral movement in network
category: investigation
severity: critical
steps:
  - id: identify_source_host
    action: edr.get_host_details
  - id: analyze_network_connections
    action: network.get_connections
  - id: identify_compromised_accounts
    action: ad.check_suspicious_auth
  - id: trace_movement_path
    action: siem.correlate_events
  - id: identify_accessed_systems
    action: network.get_accessed_hosts
EOF

cat > "$PLAYBOOK_DIR/investigation/c2_detection.yaml" << 'EOF'
name: c2_detection
version: "1.0"
description: Detect and investigate C2 communications
category: investigation
severity: critical
steps:
  - id: analyze_network_traffic
    action: network.get_unusual_connections
  - id: check_known_c2_iocs
    action: ti.check_c2_indicators
  - id: identify_beaconing
    action: network.detect_beaconing
  - id: identify_infected_hosts
    action: network.get_communicating_hosts
  - id: block_c2_communication
    action: firewall.block_domain
EOF

cat > "$PLAYBOOK_DIR/investigation/privilege_escalation.yaml" << 'EOF'
name: privilege_escalation
version: "1.0"
description: Investigate privilege escalation attempts
category: investigation
severity: high
steps:
  - id: identify_privilege_changes
    action: ad.get_privilege_changes
  - id: review_elevation_logs
    action: audit.query_elevation_events
  - id: identify_exploited_vulnerability
    action: vuln_scan.correlate_exploits
  - id: check_unauthorized_admin_access
    action: ad.check_admin_group
EOF

cat > "$PLAYBOOK_DIR/investigation/data_exfiltration.yaml" << 'EOF'
name: data_exfiltration
version: "1.0"
description: Investigate data exfiltration attempts
category: investigation
severity: critical
steps:
  - id: analyze_outbound_traffic
    action: network.get_large_transfers
  - id: identify_data_accessed
    action: dlp.get_accessed_files
  - id: check_external_destinations
    action: network.get_external_ips
  - id: correlate_with_ti
    action: ti.check_destinations
  - id: calculate_data_volume
    action: network.calculate_transfer_size
EOF

cat > "$PLAYBOOK_DIR/investigation/ransomware_investigation.yaml" << 'EOF'
name: ransomware_investigation
version: "1.0"
description: Investigate ransomware infection
category: investigation
severity: critical
steps:
  - id: identify_ransomware_variant
    action: malware.identify_variant
  - id: find_infection_vector
    action: forensics.analyze_infection
  - id: identify_encrypted_files
    action: filesystem.get_encrypted_files
  - id: check_backup_integrity
    action: backup.verify_backups
  - id: identify_spread_mechanism
    action: network.trace_infection
  - id: check_decryption_options
    action: ti.check_decryption_tools
EOF

# Create compliance playbooks (8 total)
mkdir -p "$PLAYBOOK_DIR/compliance"

cat > "$PLAYBOOK_DIR/compliance/gdpr_breach.yaml" << 'EOF'
name: gdpr_breach
version: "1.0"
description: Handle GDPR breach notification requirements
category: compliance
severity: critical
steps:
  - id: assess_breach_scope
    action: compliance.assess_gdpr_impact
  - id: determine_notification_requirement
    action: script
  - id: notify_dpa
    condition: "steps.determine_notification_requirement.requires_dpa"
    action: compliance.notify_dpa
    params:
      regulation: GDPR
      deadline_hours: 72
  - id: notify_affected_individuals
    action: email.send_breach_notification
  - id: document_breach
    action: compliance.create_breach_record
EOF

cat > "$PLAYBOOK_DIR/compliance/pci_incident.yaml" << 'EOF'
name: pci_incident
version: "1.0"
description: Handle PCI-DSS incident response
category: compliance
severity: high
steps:
  - id: assess_cardholder_data_impact
    action: compliance.assess_pci_impact
  - id: notify_payment_brands
    condition: "input.cardholder_data_compromised"
    action: compliance.notify_payment_brands
  - id: notify_acquiring_bank
    action: compliance.notify_bank
  - id: conduct_forensic_investigation
    action: forensics.pci_investigation
  - id: submit_incident_report
    action: compliance.submit_pci_report
EOF

cat > "$PLAYBOOK_DIR/compliance/hipaa_violation.yaml" << 'EOF'
name: hipaa_violation
version: "1.0"
description: Handle HIPAA violation and breach notification
category: compliance
severity: critical
steps:
  - id: assess_phi_exposure
    action: compliance.assess_hipaa_impact
  - id: determine_notification_requirement
    action: compliance.check_hipaa_safe_harbor
  - id: notify_hhs
    condition: "input.affected_individuals > 500"
    action: compliance.notify_hhs
    params:
      deadline_days: 60
  - id: notify_affected_individuals
    action: compliance.send_hipaa_notification
  - id: notify_media
    condition: "input.affected_individuals > 500"
    action: compliance.notify_media
EOF

cat > "$PLAYBOOK_DIR/compliance/sox_audit.yaml" << 'EOF'
name: sox_audit
version: "1.0"
description: SOX compliance audit response
category: compliance
severity: medium
steps:
  - id: collect_access_logs
    action: audit.collect_logs
    params:
      retention_period: 7_years
  - id: verify_segregation_of_duties
    action: compliance.check_sod
  - id: verify_change_management
    action: compliance.check_change_logs
  - id: generate_audit_report
    action: report.generate
    template: sox_audit
EOF

cat > "$PLAYBOOK_DIR/compliance/iso27001_review.yaml" << 'EOF'
name: iso27001_review
version: "1.0"
description: ISO 27001 compliance review
category: compliance
severity: low
steps:
  - id: review_information_security_policy
    action: compliance.check_policies
  - id: review_risk_assessment
    action: risk.get_assessment
  - id: review_asset_inventory
    action: asset.get_inventory
  - id: review_access_controls
    action: iam.audit_access
  - id: generate_compliance_report
    action: report.generate
EOF

cat > "$PLAYBOOK_DIR/compliance/evidence_collection.yaml" << 'EOF'
name: evidence_collection
version: "1.0"
description: Collect and preserve digital evidence
category: compliance
severity: high
steps:
  - id: identify_evidence_sources
    action: forensics.identify_sources
  - id: create_forensic_image
    action: forensics.create_image
  - id: calculate_evidence_hash
    action: crypto.hash_file
  - id: document_chain_of_custody
    action: forensics.document_custody
  - id: store_evidence_securely
    action: storage.store_evidence
EOF

cat > "$PLAYBOOK_DIR/compliance/chain_of_custody.yaml" << 'EOF'
name: chain_of_custody
version: "1.0"
description: Maintain chain of custody for evidence
category: compliance
severity: high
steps:
  - id: record_evidence_collection
    action: forensics.record_collection
  - id: assign_custodian
    action: forensics.assign_custodian
  - id: track_evidence_transfer
    action: forensics.track_transfer
  - id: verify_evidence_integrity
    action: crypto.verify_hash
  - id: document_access
    action: forensics.log_access
EOF

cat > "$PLAYBOOK_DIR/compliance/regulatory_report.yaml" << 'EOF'
name: regulatory_report
version: "1.0"
description: Generate regulatory compliance reports
category: compliance
severity: medium
steps:
  - id: collect_incident_data
    action: siem.aggregate_incidents
  - id: categorize_by_regulation
    action: compliance.categorize_incidents
  - id: calculate_metrics
    action: metrics.calculate_compliance
  - id: generate_report
    action: report.generate
    template: regulatory_compliance
  - id: submit_to_regulator
    action: compliance.submit_report
EOF

echo "✅ All playbooks generated successfully!"
echo "Total playbooks: 50"
echo "  - Enrichment: 7"
echo "  - Containment: 5"
echo "  - Notification: 10"
echo "  - Remediation: 10"
echo "  - Investigation: 10"
echo "  - Compliance: 8"
