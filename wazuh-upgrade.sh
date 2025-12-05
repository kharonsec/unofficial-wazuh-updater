#!/bin/bash
#===============================================================================
# Wazuh All-in-One Upgrade Script
# 
# This script upgrades all Wazuh central components (Indexer, Manager, Dashboard)
# and optionally upgrades all connected agents.
#
# Based on official Wazuh documentation:
# https://documentation.wazuh.com/current/upgrade-guide/upgrading-central-components.html
#
# Author: kharonsec
# Repository: https://github.com/kharonsec/unofficial-wazuh-updater
# Tested on: Ubuntu/Debian and RHEL-compatible systems
#
# IMPORTANT: 
# - Run as root
# - Create a backup before running (index snapshot recommended)
# - Review and test in a non-production environment first
#===============================================================================

set -e
trap 'echo -e "\n${RED}[ERROR] Script failed at line $LINENO${NC}"; cleanup_on_error' ERR

#-------------------------------------------------------------------------------
# Configuration
#-------------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

LOG_FILE="/var/log/wazuh-upgrade-$(date +%Y%m%d-%H%M%S).log"
BACKUP_DIR="/var/ossec/backup-$(date +%Y%m%d-%H%M%S)"

# Default values - will be prompted if not set
WAZUH_INDEXER_IP="${WAZUH_INDEXER_IP:-127.0.0.1}"
WAZUH_API_USER="${WAZUH_API_USER:-admin}"
WAZUH_API_PASS="${WAZUH_API_PASS:-}"
UPGRADE_AGENTS="${UPGRADE_AGENTS:-false}"
SKIP_CONFIRMATION="${SKIP_CONFIRMATION:-false}"

#-------------------------------------------------------------------------------
# Helper Functions
#-------------------------------------------------------------------------------
log() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${timestamp} [${level}] ${message}" | tee -a "$LOG_FILE"
}

print_step() {
    local step="$1"
    local total="$2"
    local message="$3"
    echo -e "\n${BLUE}[$step/$total]${NC} ${GREEN}${message}${NC}"
    log "INFO" "Step $step/$total: $message"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
    log "WARNING" "$1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
    log "ERROR" "$1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
    log "INFO" "$1"
}

cleanup_on_error() {
    print_error "An error occurred. Check the log file: $LOG_FILE"
    print_warning "You may need to manually restart services and re-enable shard allocation."
    echo -e "\nTo re-enable shard allocation, run:"
    echo "curl -X PUT \"https://${WAZUH_INDEXER_IP}:9200/_cluster/settings\" -u ${WAZUH_API_USER} -k -H 'Content-Type: application/json' -d'{\"persistent\":{\"cluster.routing.allocation.enable\":\"all\"}}'"
}

detect_package_manager() {
    if command -v apt-get &> /dev/null; then
        PKG_MANAGER="apt"
        PKG_INSTALL="apt-get install -y"
        PKG_UPDATE="apt-get update"
    elif command -v yum &> /dev/null; then
        PKG_MANAGER="yum"
        PKG_INSTALL="yum install -y"
        PKG_UPDATE="yum makecache"
    elif command -v dnf &> /dev/null; then
        PKG_MANAGER="dnf"
        PKG_INSTALL="dnf install -y"
        PKG_UPDATE="dnf makecache"
    else
        print_error "Unsupported package manager. This script supports apt, yum, and dnf."
        exit 1
    fi
    log "INFO" "Detected package manager: $PKG_MANAGER"
}

detect_init_system() {
    if command -v systemctl &> /dev/null && systemctl --version &> /dev/null; then
        INIT_SYSTEM="systemd"
    else
        INIT_SYSTEM="sysvinit"
    fi
    log "INFO" "Detected init system: $INIT_SYSTEM"
}

service_cmd() {
    local action="$1"
    local service="$2"
    
    if [ "$INIT_SYSTEM" = "systemd" ]; then
        systemctl "$action" "$service" 2>/dev/null || true
    else
        service "$service" "$action" 2>/dev/null || true
    fi
}

check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        print_error "This script must be run as root (e.g., with sudo)."
        exit 1
    fi
}

get_current_versions() {
    echo -e "\n${BLUE}Current installed versions:${NC}"
    
    if [ "$PKG_MANAGER" = "apt" ]; then
        CURRENT_INDEXER=$(dpkg -l wazuh-indexer 2>/dev/null | grep "^ii" | awk '{print $3}' || echo "Not installed")
        CURRENT_MANAGER=$(dpkg -l wazuh-manager 2>/dev/null | grep "^ii" | awk '{print $3}' || echo "Not installed")
        CURRENT_DASHBOARD=$(dpkg -l wazuh-dashboard 2>/dev/null | grep "^ii" | awk '{print $3}' || echo "Not installed")
        CURRENT_FILEBEAT=$(dpkg -l filebeat 2>/dev/null | grep "^ii" | awk '{print $3}' || echo "Not installed")
    else
        CURRENT_INDEXER=$(rpm -q wazuh-indexer 2>/dev/null | sed 's/wazuh-indexer-//' || echo "Not installed")
        CURRENT_MANAGER=$(rpm -q wazuh-manager 2>/dev/null | sed 's/wazuh-manager-//' || echo "Not installed")
        CURRENT_DASHBOARD=$(rpm -q wazuh-dashboard 2>/dev/null | sed 's/wazuh-dashboard-//' || echo "Not installed")
        CURRENT_FILEBEAT=$(rpm -q filebeat 2>/dev/null | sed 's/filebeat-//' || echo "Not installed")
    fi
    
    echo "  - Wazuh Indexer:   $CURRENT_INDEXER"
    echo "  - Wazuh Manager:   $CURRENT_MANAGER"
    echo "  - Wazuh Dashboard: $CURRENT_DASHBOARD"
    echo "  - Filebeat:        $CURRENT_FILEBEAT"
}

prompt_credentials() {
    if [ -z "$WAZUH_API_PASS" ]; then
        echo -e "\n${YELLOW}Please enter the Wazuh indexer credentials:${NC}"
        read -p "Indexer IP address [$WAZUH_INDEXER_IP]: " input_ip
        WAZUH_INDEXER_IP="${input_ip:-$WAZUH_INDEXER_IP}"
        
        read -p "Username [$WAZUH_API_USER]: " input_user
        WAZUH_API_USER="${input_user:-$WAZUH_API_USER}"
        
        read -sp "Password: " WAZUH_API_PASS
        echo
        
        if [ -z "$WAZUH_API_PASS" ]; then
            print_error "Password cannot be empty."
            exit 1
        fi
    fi
}

test_indexer_connection() {
    print_step "1" "15" "Testing connection to Wazuh indexer..."
    
    local response=$(curl -s -o /dev/null -w "%{http_code}" -k -u "${WAZUH_API_USER}:${WAZUH_API_PASS}" \
        "https://${WAZUH_INDEXER_IP}:9200/" 2>/dev/null || echo "000")
    
    if [ "$response" != "200" ]; then
        print_error "Failed to connect to Wazuh indexer at ${WAZUH_INDEXER_IP}:9200 (HTTP $response)"
        print_error "Please check your credentials and network connectivity."
        exit 1
    fi
    
    print_success "Successfully connected to Wazuh indexer."
}

#-------------------------------------------------------------------------------
# Pre-upgrade Steps
#-------------------------------------------------------------------------------
add_wazuh_repository() {
    print_step "2" "15" "Ensuring Wazuh repository is configured..."
    
    if [ "$PKG_MANAGER" = "apt" ]; then
        apt-get install -y gnupg apt-transport-https &>> "$LOG_FILE"
        curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | \
            gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import &>> "$LOG_FILE" && \
            chmod 644 /usr/share/keyrings/wazuh.gpg
        echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | \
            tee /etc/apt/sources.list.d/wazuh.list > /dev/null
        apt-get update &>> "$LOG_FILE"
    else
        rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH &>> "$LOG_FILE"
        
        # Determine RHEL version for correct repo config
        local rhel_version=$(rpm -E %{rhel} 2>/dev/null || echo "8")
        
        if [ "$rhel_version" -ge 9 ]; then
            echo -e '[wazuh]\ngpgcheck=1\ngpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH\nenabled=1\nname=EL-$releasever - Wazuh\nbaseurl=https://packages.wazuh.com/4.x/yum/\npriority=1' | \
                tee /etc/yum.repos.d/wazuh.repo > /dev/null
        else
            echo -e '[wazuh]\ngpgcheck=1\ngpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH\nenabled=1\nname=EL-$releasever - Wazuh\nbaseurl=https://packages.wazuh.com/4.x/yum/\nprotect=1' | \
                tee /etc/yum.repos.d/wazuh.repo > /dev/null
        fi
        $PKG_UPDATE &>> "$LOG_FILE"
    fi
    
    print_success "Wazuh repository configured."
}

create_backup() {
    print_step "3" "15" "Creating configuration backups..."
    
    mkdir -p "$BACKUP_DIR"
    
    # Backup ossec.conf
    if [ -f /var/ossec/etc/ossec.conf ]; then
        cp /var/ossec/etc/ossec.conf "$BACKUP_DIR/" 2>/dev/null || true
    fi
    
    # Backup Filebeat config
    if [ -f /etc/filebeat/filebeat.yml ]; then
        cp /etc/filebeat/filebeat.yml "$BACKUP_DIR/" 2>/dev/null || true
    fi
    
    # Backup Dashboard config
    if [ -f /etc/wazuh-dashboard/opensearch_dashboards.yml ]; then
        cp /etc/wazuh-dashboard/opensearch_dashboards.yml "$BACKUP_DIR/" 2>/dev/null || true
    fi
    
    # Backup JVM options
    if [ -f /etc/wazuh-indexer/jvm.options ]; then
        cp /etc/wazuh-indexer/jvm.options "$BACKUP_DIR/" 2>/dev/null || true
    fi
    
    print_success "Backups created in $BACKUP_DIR"
}

stop_services() {
    print_step "4" "15" "Stopping Filebeat and Dashboard services..."
    
    service_cmd stop filebeat
    service_cmd stop wazuh-dashboard
    
    print_success "Services stopped."
}

#-------------------------------------------------------------------------------
# Indexer Upgrade
#-------------------------------------------------------------------------------
backup_indexer_security() {
    print_step "5" "15" "Backing up Wazuh indexer security configuration..."
    
    /usr/share/wazuh-indexer/bin/indexer-security-init.sh \
        --options "-backup /etc/wazuh-indexer/opensearch-security -icl -nhnv" &>> "$LOG_FILE"
    
    print_success "Security configuration backed up."
}

disable_shard_allocation() {
    print_step "6" "15" "Disabling shard allocation..."
    
    curl -s -X PUT "https://${WAZUH_INDEXER_IP}:9200/_cluster/settings" \
        -u "${WAZUH_API_USER}:${WAZUH_API_PASS}" -k \
        -H 'Content-Type: application/json' \
        -d '{"persistent":{"cluster.routing.allocation.enable":"primaries"}}' &>> "$LOG_FILE"
    
    # Flush the cluster
    curl -s -X POST "https://${WAZUH_INDEXER_IP}:9200/_flush" \
        -u "${WAZUH_API_USER}:${WAZUH_API_PASS}" -k &>> "$LOG_FILE"
    
    print_success "Shard allocation disabled and cluster flushed."
}

upgrade_indexer() {
    print_step "7" "15" "Upgrading Wazuh indexer..."
    
    service_cmd stop wazuh-indexer
    service_cmd stop wazuh-manager
    
    if [ "$PKG_MANAGER" = "apt" ]; then
        DEBIAN_FRONTEND=noninteractive apt-get install -y -o Dpkg::Options::="--force-confnew" wazuh-indexer &>> "$LOG_FILE"
    else
        yum upgrade -y wazuh-indexer &>> "$LOG_FILE"
    fi
    
    # Restore custom JVM settings if backup exists
    if [ -f "$BACKUP_DIR/jvm.options" ]; then
        print_warning "Review $BACKUP_DIR/jvm.options for any custom JVM settings to restore."
    fi
    
    if [ "$INIT_SYSTEM" = "systemd" ]; then
        systemctl daemon-reload
        systemctl enable wazuh-indexer
    fi
    service_cmd start wazuh-indexer
    
    # Wait for indexer to be ready
    echo -n "Waiting for indexer to start..."
    for i in {1..60}; do
        if curl -s -k -u "${WAZUH_API_USER}:${WAZUH_API_PASS}" "https://${WAZUH_INDEXER_IP}:9200/" &>/dev/null; then
            echo " Ready!"
            break
        fi
        echo -n "."
        sleep 2
    done
    
    print_success "Wazuh indexer upgraded."
}

restore_indexer_security() {
    print_step "8" "15" "Restoring indexer security configuration..."
    
    /usr/share/wazuh-indexer/bin/indexer-security-init.sh &>> "$LOG_FILE"
    
    print_success "Security configuration restored."
}

enable_shard_allocation() {
    print_step "9" "15" "Re-enabling shard allocation..."
    
    curl -s -X PUT "https://${WAZUH_INDEXER_IP}:9200/_cluster/settings" \
        -u "${WAZUH_API_USER}:${WAZUH_API_PASS}" -k \
        -H 'Content-Type: application/json' \
        -d '{"persistent":{"cluster.routing.allocation.enable":"all"}}' &>> "$LOG_FILE"
    
    print_success "Shard allocation re-enabled."
}

#-------------------------------------------------------------------------------
# Manager Upgrade
#-------------------------------------------------------------------------------
upgrade_manager() {
    print_step "10" "15" "Upgrading Wazuh manager..."
    
    if [ "$PKG_MANAGER" = "apt" ]; then
        DEBIAN_FRONTEND=noninteractive apt-get install -y wazuh-manager &>> "$LOG_FILE"
    else
        yum upgrade -y wazuh-manager &>> "$LOG_FILE"
    fi
    
    if [ "$INIT_SYSTEM" = "systemd" ]; then
        systemctl daemon-reload
        systemctl enable wazuh-manager
    fi
    service_cmd start wazuh-manager
    
    print_success "Wazuh manager upgraded."
}

#-------------------------------------------------------------------------------
# Filebeat Upgrade
#-------------------------------------------------------------------------------
upgrade_filebeat() {
    print_step "11" "15" "Upgrading Filebeat and Wazuh module..."
    
    # Download Wazuh module
    curl -s https://packages.wazuh.com/4.x/filebeat/wazuh-filebeat-0.4.tar.gz | \
        tar -xvz -C /usr/share/filebeat/module &>> "$LOG_FILE"
    
    # Download alerts template
    curl -so /etc/filebeat/wazuh-template.json \
        https://raw.githubusercontent.com/wazuh/wazuh/v4.14.1/extensions/elasticsearch/7.x/wazuh-template.json
    chmod go+r /etc/filebeat/wazuh-template.json
    
    # Upgrade Filebeat
    if [ "$PKG_MANAGER" = "apt" ]; then
        DEBIAN_FRONTEND=noninteractive apt-get install -y filebeat &>> "$LOG_FILE"
    else
        yum upgrade -y filebeat &>> "$LOG_FILE"
    fi
    
    # Restore Filebeat config
    if [ -f "$BACKUP_DIR/filebeat.yml" ]; then
        cp "$BACKUP_DIR/filebeat.yml" /etc/filebeat/filebeat.yml
    fi
    
    if [ "$INIT_SYSTEM" = "systemd" ]; then
        systemctl daemon-reload
        systemctl enable filebeat
    fi
    service_cmd start filebeat
    
    # Upload new template and pipelines
    sleep 5
    filebeat setup --pipelines &>> "$LOG_FILE" || true
    filebeat setup --index-management -E output.logstash.enabled=false &>> "$LOG_FILE" || true
    
    print_success "Filebeat upgraded."
}

#-------------------------------------------------------------------------------
# Dashboard Upgrade
#-------------------------------------------------------------------------------
upgrade_dashboard() {
    print_step "12" "15" "Upgrading Wazuh dashboard..."
    
    if [ "$PKG_MANAGER" = "apt" ]; then
        DEBIAN_FRONTEND=noninteractive apt-get install -y -o Dpkg::Options::="--force-confnew" wazuh-dashboard &>> "$LOG_FILE"
    else
        yum upgrade -y wazuh-dashboard &>> "$LOG_FILE"
    fi
    
    # Restore custom settings from backup if needed
    if [ -f "$BACKUP_DIR/opensearch_dashboards.yml" ]; then
        print_warning "Review $BACKUP_DIR/opensearch_dashboards.yml for any custom settings to restore."
    fi
    
    # Ensure default route is set correctly
    if grep -q "uiSettings.overrides.defaultRoute" /etc/wazuh-dashboard/opensearch_dashboards.yml; then
        sed -i 's|uiSettings.overrides.defaultRoute:.*|uiSettings.overrides.defaultRoute: /app/wz-home|' \
            /etc/wazuh-dashboard/opensearch_dashboards.yml
    else
        echo "uiSettings.overrides.defaultRoute: /app/wz-home" >> /etc/wazuh-dashboard/opensearch_dashboards.yml
    fi
    
    if [ "$INIT_SYSTEM" = "systemd" ]; then
        systemctl daemon-reload
        systemctl enable wazuh-dashboard
    fi
    service_cmd start wazuh-dashboard
    
    print_success "Wazuh dashboard upgraded."
}

#-------------------------------------------------------------------------------
# Agent Upgrade (Optional)
#-------------------------------------------------------------------------------
upgrade_agents() {
    print_step "13" "15" "Checking for outdated agents..."
    
    local outdated_agents=$(/var/ossec/bin/agent_upgrade -l 2>/dev/null | grep -i "wazuh" | awk '{print $1}' || true)
    
    if [ -z "$outdated_agents" ]; then
        print_success "No outdated agents found."
        return
    fi
    
    echo -e "\n${YELLOW}Outdated agents found:${NC}"
    /var/ossec/bin/agent_upgrade -l 2>/dev/null || true
    
    if [ "$UPGRADE_AGENTS" = "true" ]; then
        echo -e "\n${BLUE}Upgrading agents...${NC}"
        for agent_id in $outdated_agents; do
            echo "Upgrading agent $agent_id..."
            /var/ossec/bin/agent_upgrade -a "$agent_id" &>> "$LOG_FILE" || \
                print_warning "Failed to upgrade agent $agent_id"
        done
        print_success "Agent upgrades initiated."
    else
        echo -e "\n${YELLOW}To upgrade agents, run:${NC}"
        echo "  /var/ossec/bin/agent_upgrade -a <agent_id>"
        echo "  Or re-run this script with: UPGRADE_AGENTS=true $0"
    fi
}

#-------------------------------------------------------------------------------
# Verification
#-------------------------------------------------------------------------------
verify_upgrade() {
    print_step "14" "15" "Verifying upgrade..."
    
    echo -e "\n${BLUE}Checking service status:${NC}"
    
    local all_ok=true
    
    # Check Indexer
    if service_cmd status wazuh-indexer 2>/dev/null | grep -q "active\|running"; then
        echo -e "  - Wazuh Indexer:   ${GREEN}Running${NC}"
    else
        echo -e "  - Wazuh Indexer:   ${RED}Not running${NC}"
        all_ok=false
    fi
    
    # Check Manager
    if service_cmd status wazuh-manager 2>/dev/null | grep -q "active\|running"; then
        echo -e "  - Wazuh Manager:   ${GREEN}Running${NC}"
    else
        echo -e "  - Wazuh Manager:   ${RED}Not running${NC}"
        all_ok=false
    fi
    
    # Check Dashboard
    if service_cmd status wazuh-dashboard 2>/dev/null | grep -q "active\|running"; then
        echo -e "  - Wazuh Dashboard: ${GREEN}Running${NC}"
    else
        echo -e "  - Wazuh Dashboard: ${RED}Not running${NC}"
        all_ok=false
    fi
    
    # Check Filebeat
    if service_cmd status filebeat 2>/dev/null | grep -q "active\|running"; then
        echo -e "  - Filebeat:        ${GREEN}Running${NC}"
    else
        echo -e "  - Filebeat:        ${RED}Not running${NC}"
        all_ok=false
    fi
    
    # Check cluster health
    echo -e "\n${BLUE}Cluster health:${NC}"
    curl -s -k -u "${WAZUH_API_USER}:${WAZUH_API_PASS}" \
        "https://${WAZUH_INDEXER_IP}:9200/_cluster/health?pretty" 2>/dev/null | \
        grep -E '"status"|"number_of_nodes"|"active_shards"' || true
    
    if [ "$all_ok" = true ]; then
        print_success "All services are running."
    else
        print_warning "Some services may not be running. Check the logs."
    fi
}

show_final_versions() {
    print_step "15" "15" "Upgrade complete!"
    
    get_current_versions
    
    echo -e "\n${GREEN}========================================${NC}"
    echo -e "${GREEN}  Wazuh upgrade completed successfully!${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo -e "\nLog file: $LOG_FILE"
    echo -e "Backups:  $BACKUP_DIR"
    echo -e "\nAccess your Wazuh dashboard at: https://${WAZUH_INDEXER_IP}"
}

#-------------------------------------------------------------------------------
# Main
#-------------------------------------------------------------------------------
main() {
    clear
    echo -e "${GREEN}"
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║           Wazuh All-in-One Upgrade Script                     ║"
    echo "║                                                               ║"
    echo "║  This script will upgrade:                                    ║"
    echo "║    • Wazuh Indexer                                            ║"
    echo "║    • Wazuh Manager                                            ║"
    echo "║    • Wazuh Dashboard                                          ║"
    echo "║    • Filebeat                                                 ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    check_root
    detect_package_manager
    detect_init_system
    
    get_current_versions
    prompt_credentials
    
    if [ "$SKIP_CONFIRMATION" != "true" ]; then
        echo -e "\n${YELLOW}WARNING: This will upgrade all Wazuh components.${NC}"
        echo -e "${YELLOW}Ensure you have a backup of your data and configurations.${NC}"
        read -p "Do you want to proceed? (y/N): " confirm
        
        if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
            echo "Upgrade cancelled."
            exit 0
        fi
    fi
    
    echo -e "\n${BLUE}Starting upgrade... Log file: $LOG_FILE${NC}\n"
    
    # Execute upgrade steps
    test_indexer_connection
    add_wazuh_repository
    create_backup
    stop_services
    backup_indexer_security
    disable_shard_allocation
    upgrade_indexer
    restore_indexer_security
    enable_shard_allocation
    upgrade_manager
    upgrade_filebeat
    upgrade_dashboard
    upgrade_agents
    verify_upgrade
    show_final_versions
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --ip)
            WAZUH_INDEXER_IP="$2"
            shift 2
            ;;
        --user)
            WAZUH_API_USER="$2"
            shift 2
            ;;
        --password)
            WAZUH_API_PASS="$2"
            shift 2
            ;;
        --upgrade-agents)
            UPGRADE_AGENTS=true
            shift
            ;;
        --yes|-y)
            SKIP_CONFIRMATION=true
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --ip IP              Wazuh indexer IP address (default: 127.0.0.1)"
            echo "  --user USERNAME      Wazuh API username (default: admin)"
            echo "  --password PASSWORD  Wazuh API password"
            echo "  --upgrade-agents     Also upgrade all connected agents"
            echo "  --yes, -y            Skip confirmation prompt"
            echo "  --help, -h           Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0 --ip 192.168.1.100 --user admin --password mypass"
            echo "  $0 --upgrade-agents --yes"
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            echo "Use --help for usage information."
            exit 1
            ;;
    esac
done

main
