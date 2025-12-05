# Wazuh All-in-One Upgrade Script

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Wazuh](https://img.shields.io/badge/Wazuh-4.14.x-blue.svg)](https://wazuh.com)
[![Shell Script](https://img.shields.io/badge/Shell-Bash-green.svg)](https://www.gnu.org/software/bash/)

Automated bash script to upgrade all Wazuh central components (Indexer, Manager, Dashboard, and Filebeat) in a single run. Designed for **all-in-one deployments** where all components run on the same server.

Based on the [official Wazuh upgrade documentation](https://documentation.wazuh.com/current/upgrade-guide/upgrading-central-components.html).

## Features

- ✅ Upgrades all components in the correct order (Indexer → Manager → Filebeat → Dashboard)
- ✅ Automatic backup of all configuration files
- ✅ Proper shard allocation management during indexer upgrade
- ✅ Security configuration backup and restoration
- ✅ Downloads latest Filebeat module and alert templates
- ✅ Service verification after upgrade
- ✅ Detailed logging
- ✅ Support for both Debian/Ubuntu (apt) and RHEL-based systems (yum/dnf)
- ✅ Support for both systemd and SysV init systems
- ✅ Optional batch agent upgrade
- ✅ Error handling with cleanup guidance

## Requirements

- **Root access** (sudo)
- **All-in-one Wazuh deployment** (Indexer, Manager, and Dashboard on the same server)
- **Wazuh 4.x** already installed
- **Internet connectivity** to download packages from Wazuh repositories
- Wazuh indexer credentials (username/password)

## Supported Operating Systems

| Distribution | Versions |
|--------------|----------|
| Ubuntu | 18.04, 20.04, 22.04, 24.04 |
| Debian | 10, 11, 12 |
| CentOS | 7, 8, 9 |
| RHEL | 7, 8, 9 |
| Amazon Linux | 2, 2023 |

## Installation

```bash
# Download the script
curl -sO https://raw.githubusercontent.com/kharonsec/unofficial-wazuh-updater/main/wazuh-upgrade.sh

# Make it executable
chmod +x wazuh-upgrade.sh
```

## Usage

### Interactive Mode

Run the script without arguments to be prompted for credentials:

```bash
sudo ./wazuh-upgrade.sh
```

### Command Line Arguments

```bash
sudo ./wazuh-upgrade.sh [OPTIONS]
```

| Option | Description | Default |
|--------|-------------|---------|
| `--ip IP` | Wazuh indexer IP address | `127.0.0.1` |
| `--user USERNAME` | Wazuh API username | `admin` |
| `--password PASSWORD` | Wazuh API password | *(prompted)* |
| `--upgrade-agents` | Also upgrade all connected agents | `false` |
| `--yes`, `-y` | Skip confirmation prompt | `false` |
| `--help`, `-h` | Show help message | - |

### Examples

```bash
# Interactive mode (prompts for credentials)
sudo ./wazuh-upgrade.sh

# With credentials as arguments
sudo ./wazuh-upgrade.sh --ip 127.0.0.1 --user admin --password MySecretPass

# Skip confirmation prompt
sudo ./wazuh-upgrade.sh --password MySecretPass --yes

# Also upgrade all connected agents
sudo ./wazuh-upgrade.sh --password MySecretPass --upgrade-agents

# Full example with all options
sudo ./wazuh-upgrade.sh --ip 127.0.0.1 --user admin --password MySecretPass --upgrade-agents --yes
```

## What the Script Does

The script follows the official Wazuh upgrade procedure:

### 1. Pre-upgrade Phase
1. Validates root permissions
2. Detects package manager (apt/yum/dnf) and init system (systemd/sysvinit)
3. Tests connection to Wazuh indexer
4. Displays current installed versions
5. Adds/updates the Wazuh repository
6. Creates backups of configuration files
7. Stops Filebeat and Dashboard services

### 2. Indexer Upgrade Phase
1. Backs up indexer security configuration
2. Disables shard allocation
3. Flushes the cluster
4. Stops the indexer and manager services
5. Upgrades the wazuh-indexer package
6. Starts the indexer service
7. Restores security configuration
8. Re-enables shard allocation

### 3. Manager Upgrade Phase
1. Upgrades the wazuh-manager package
2. Starts the manager service

### 4. Filebeat Upgrade Phase
1. Downloads the latest Wazuh Filebeat module
2. Downloads the latest alerts template
3. Upgrades the Filebeat package
4. Restores Filebeat configuration
5. Uploads new templates and pipelines

### 5. Dashboard Upgrade Phase
1. Upgrades the wazuh-dashboard package
2. Configures the default route
3. Starts the dashboard service

### 6. Post-upgrade Phase
1. Optionally upgrades all connected agents
2. Verifies all services are running
3. Checks cluster health
4. Displays final version information

## Backups

The script creates backups in `/var/ossec/backup-<timestamp>/`:

| File | Description |
|------|-------------|
| `ossec.conf` | Wazuh manager configuration |
| `filebeat.yml` | Filebeat configuration |
| `opensearch_dashboards.yml` | Dashboard configuration |
| `jvm.options` | Indexer JVM settings |

Indexer security configuration is backed up to `/etc/wazuh-indexer/opensearch-security/`.

## Logs

All operations are logged to `/var/log/wazuh-upgrade-<timestamp>.log`.

## Upgrading Agents

The script can optionally upgrade agents using the `--upgrade-agents` flag. Alternatively, you can upgrade agents manually:

### From the Manager (Remote Upgrade)

```bash
# List outdated agents
/var/ossec/bin/agent_upgrade -l

# Upgrade specific agents
/var/ossec/bin/agent_upgrade -a 001 -a 002 -a 003

# Upgrade all outdated agents
for id in $(/var/ossec/bin/agent_upgrade -l | grep -E "^[0-9]+" | awk '{print $1}'); do
    /var/ossec/bin/agent_upgrade -a $id
done
```

### Locally on Each Agent

**Debian/Ubuntu:**
```bash
sudo apt update && sudo apt install wazuh-agent
sudo systemctl restart wazuh-agent
```

**RHEL/CentOS:**
```bash
sudo yum upgrade wazuh-agent
sudo systemctl restart wazuh-agent
```

## Troubleshooting

### Dashboard not accessible after upgrade

The upgrade may reset the dashboard port or SSL certificate paths. Check:

```bash
# Check what port dashboard is listening on
sudo ss -tlnp | grep -E "node|443"

# Check SSL certificate configuration
sudo grep -E "server.ssl|server.port" /etc/wazuh-dashboard/opensearch_dashboards.yml

# Check dashboard logs
sudo journalctl -u wazuh-dashboard -n 50 --no-pager
```

Common fixes:

```bash
# Fix certificate paths (if filenames don't match config)
# Check actual cert names: ls /etc/wazuh-dashboard/certs/
# Then update config to match:
sudo nano /etc/wazuh-dashboard/opensearch_dashboards.yml

# Set specific port
sudo sed -i 's/^server.port:.*/server.port: 443/' /etc/wazuh-dashboard/opensearch_dashboards.yml

# Restart dashboard
sudo systemctl restart wazuh-dashboard
```

### Indexer connection failed

```bash
# Check if indexer is running
sudo systemctl status wazuh-indexer

# Test connection manually
curl -k -u admin:password https://127.0.0.1:9200/

# Check indexer logs
sudo tail -f /var/log/wazuh-indexer/wazuh-cluster.log
```

### Agent upgrade fails with "WPK not available"

Some platforms don't have WPK packages available. Upgrade the agent locally instead:

```bash
# On the agent machine
sudo apt update && sudo apt install wazuh-agent  # Debian/Ubuntu
sudo yum upgrade wazuh-agent                      # RHEL/CentOS
```

### Shard allocation stuck

If the script fails mid-upgrade, manually re-enable shard allocation:

```bash
curl -X PUT "https://127.0.0.1:9200/_cluster/settings" \
  -u admin:password -k \
  -H 'Content-Type: application/json' \
  -d '{"persistent":{"cluster.routing.allocation.enable":"all"}}'
```

## Important Notes

### Before Upgrading

1. **Create a backup** — Especially an [index snapshot](https://documentation.wazuh.com/current/user-manual/wazuh-indexer/migrating-wazuh-indices.html) for data recovery
2. **Test in non-production** — Always test the upgrade process first
3. **Check compatibility** — Ensure your agents are compatible with the new manager version

### After Upgrading

- Agents should be upgraded to match or be lower than the manager version
- Custom JVM settings need to be manually restored from backups
- If using Nginx as a reverse proxy, verify the backend port matches

### Limitations

- Designed for **all-in-one deployments** only
- Multi-node clusters require manual node-by-node upgrades
- **Downgrading to 4.11 or earlier is not possible** after upgrading to 4.12+ (Lucene limitation)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Wazuh](https://wazuh.com/) for the excellent SIEM platform
- [Official Wazuh Documentation](https://documentation.wazuh.com/) for the upgrade procedures
- Community scripts that inspired this project

## Disclaimer

This script is provided as-is without warranty. Always backup your data before performing upgrades. The authors are not responsible for any data loss or system issues resulting from the use of this script.

---

**If this script helped you, consider giving it a ⭐!**
