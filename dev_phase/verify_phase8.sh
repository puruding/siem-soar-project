#!/bin/bash

# Phase 8 Verification Script

PROJECT_ROOT="C:/11.develop_home/13.orchestration/deep_research/siem-soar-project"

echo "========================================="
echo "Phase 8 Verification"
echo "========================================="
echo ""

# Case Service Files
echo "1. Case Service Components:"
echo "----------------------------"
case_files=(
  "services/case/internal/repository/case_repo.go"
  "services/case/internal/service/case_service.go"
  "services/case/internal/handler/case_handler.go"
)

for file in "${case_files[@]}"; do
  if [ -f "$PROJECT_ROOT/$file" ]; then
    size=$(stat -f%z "$PROJECT_ROOT/$file" 2>/dev/null || stat -c%s "$PROJECT_ROOT/$file" 2>/dev/null)
    echo "✅ $file ($(($size / 1024)) KB)"
  else
    echo "❌ MISSING: $file"
  fi
done
echo ""

# Approval Workflow Files
echo "2. Approval Workflow Components:"
echo "--------------------------------"
approval_files=(
  "services/soar/internal/approval/approval.go"
  "services/soar/internal/approval/workflow.go"
  "services/soar/internal/approval/notification.go"
)

for file in "${approval_files[@]}"; do
  if [ -f "$PROJECT_ROOT/$file" ]; then
    size=$(stat -f%z "$PROJECT_ROOT/$file" 2>/dev/null || stat -c%s "$PROJECT_ROOT/$file" 2>/dev/null)
    echo "✅ $file ($(($size / 1024)) KB)"
  else
    echo "❌ MISSING: $file"
  fi
done
echo ""

# Playbook Categories
echo "3. SOAR Playbooks:"
echo "------------------"
playbook_dirs=(
  "enrichment"
  "containment"
  "notification"
  "remediation"
  "investigation"
  "compliance"
)

total_playbooks=0
for dir in "${playbook_dirs[@]}"; do
  count=$(find "$PROJECT_ROOT/services/soar/playbooks/$dir" -name "*.yaml" 2>/dev/null | wc -l)
  total_playbooks=$((total_playbooks + count))
  echo "✅ $dir: $count playbooks"
done

echo ""
echo "Total Playbooks: $total_playbooks / 50"

if [ $total_playbooks -eq 50 ]; then
  echo "✅ Target of 50 playbooks ACHIEVED!"
else
  echo "⚠️  Expected 50, found $total_playbooks"
fi

echo ""
echo "========================================="
echo "Verification Complete"
echo "========================================="

# Summary
echo ""
echo "Summary:"
echo "--------"
echo "Case Service: 3 Go files"
echo "Approval Service: 3 Go files"
echo "Total Playbooks: $total_playbooks"
echo ""

if [ $total_playbooks -eq 50 ]; then
  echo "✅ Phase 8 is COMPLETE!"
else
  echo "⚠️  Phase 8 is INCOMPLETE"
fi
