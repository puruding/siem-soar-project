#!/bin/bash
# =============================================================================
# Alert Grouping 파이프라인 통합 테스트 스크립트
#
# 사용법:
#   ./scripts/test/run_grouping_test.sh [OPTIONS]
#
# 옵션:
#   --url URL        Collector HTTP Receiver URL (기본값: http://localhost:8087)
#   --dry-run        실제 전송 없이 로그 생성만 테스트
#   --pattern NAME   테스트할 패턴: all|ssh|portscan|dns|malware|exfil (기본값: all)
#   --no-wait        처리 대기 없이 즉시 종료
#   --help           도움말 출력
# =============================================================================

set -euo pipefail

# 기본값
COLLECTOR_URL="http://localhost:8087"
DRY_RUN=""
PATTERN="all"
NO_WAIT=""
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# 색상 출력
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info()    { echo -e "${GREEN}[INFO]${NC}  $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $*"; }
log_step()    { echo -e "${BLUE}[STEP]${NC}  $*"; }

# 인자 파싱
while [[ $# -gt 0 ]]; do
    case "$1" in
        --url)
            COLLECTOR_URL="$2"
            shift 2
            ;;
        --dry-run)
            DRY_RUN="--dry-run"
            shift
            ;;
        --pattern)
            PATTERN="$2"
            shift 2
            ;;
        --no-wait)
            NO_WAIT="true"
            shift
            ;;
        --help|-h)
            sed -n '3,20p' "${BASH_SOURCE[0]}" | sed 's/^# \?//'
            exit 0
            ;;
        *)
            log_error "알 수 없는 옵션: $1"
            exit 1
            ;;
    esac
done

echo ""
echo "============================================================"
echo "  Alert Grouping Pipeline Integration Test"
echo "============================================================"

# Python 확인
if ! command -v python3 &>/dev/null; then
    log_error "python3가 설치되어 있지 않습니다."
    exit 1
fi

# 의존성 확인 및 설치
REQUIREMENTS="${SCRIPT_DIR}/requirements.txt"
if [[ -f "$REQUIREMENTS" ]]; then
    if ! python3 -c "import requests" &>/dev/null 2>&1; then
        log_step "Python 의존성 설치 중..."
        pip3 install -r "$REQUIREMENTS" -q || {
            log_error "의존성 설치 실패. 수동으로 설치하세요: pip install -r ${REQUIREMENTS}"
            exit 1
        }
        log_info "의존성 설치 완료"
    fi
fi

# Docker 서비스 상태 확인 (docker-compose 사용 가능한 경우)
if command -v docker &>/dev/null && [[ -f "${PROJECT_ROOT}/docker-compose.yml" ]]; then
    log_step "Docker 서비스 상태 확인..."
    echo ""
    # collector, detection, alert 서비스 상태 표시
    docker compose -f "${PROJECT_ROOT}/docker-compose.yml" ps \
        collector detection alert normalizer 2>/dev/null || true
    echo ""
else
    log_warn "Docker 또는 docker-compose.yml을 찾을 수 없습니다. 서비스 상태 확인을 건너뜁니다."
fi

# Python 스크립트 실행
log_step "테스트 로그 생성 및 전송 시작..."
echo ""

python3 "${SCRIPT_DIR}/generate_test_logs.py" \
    --url "${COLLECTOR_URL}" \
    --pattern "${PATTERN}" \
    ${DRY_RUN}

EXIT_CODE=$?

if [[ $EXIT_CODE -ne 0 ]]; then
    log_error "로그 생성 스크립트가 오류로 종료되었습니다 (exit code: ${EXIT_CODE})"
    exit $EXIT_CODE
fi

# 처리 대기 (dry-run이나 --no-wait가 아닌 경우)
if [[ -z "${DRY_RUN}" ]] && [[ -z "${NO_WAIT}" ]]; then
    echo ""
    log_step "파이프라인 처리 대기 중..."
    echo ""

    # 30초 카운트다운
    for i in $(seq 30 -1 1); do
        printf "\r  %2d초 후 UI 확인 가능..." "$i"
        sleep 1
    done
    printf "\r  처리 완료!                    \n"

    echo ""
    log_info "UI에서 결과 확인:"
    echo "  http://localhost:5173/alerts"
    echo ""
    log_info "예상 결과:"
    if [[ "${PATTERN}" == "all" ]] || [[ "${PATTERN}" == "ssh" ]]; then
        echo "  - SSH Brute Force : 50개 이벤트 → 1개 그룹 알림 (target.ip 기준)"
    fi
    if [[ "${PATTERN}" == "all" ]] || [[ "${PATTERN}" == "portscan" ]]; then
        echo "  - Port Scan       : 100개 이벤트 → 1개 그룹 알림 (principal.ip 기준)"
    fi
    if [[ "${PATTERN}" == "all" ]] || [[ "${PATTERN}" == "dns" ]]; then
        echo "  - Suspicious DNS  : 30개 이벤트 → 1개 그룹 알림 (dns.domain 기준)"
    fi
    if [[ "${PATTERN}" == "all" ]] || [[ "${PATTERN}" == "malware" ]]; then
        echo "  - Malware         : 20개 이벤트 → 1개 그룹 알림 (file.sha256 기준)"
    fi
    if [[ "${PATTERN}" == "all" ]] || [[ "${PATTERN}" == "exfil" ]]; then
        echo "  - Data Exfil      : 20개 이벤트 → 1개 그룹 알림 (user+dest_ip 기준)"
    fi
fi

echo ""
echo "============================================================"
echo "  테스트 완료"
echo "============================================================"
echo ""
