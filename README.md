# Complete Step-by-Step Guide to Install and Configure Suricata IDS/IPS on Ubuntu 24.04 LTS

## Executive Summary

Suricata is a high-performance, open-source network intrusion detection system (IDS) and intrusion prevention system (IPS) developed by the Open Information Security Foundation (OISF). This guide provides enterprise-grade installation and configuration procedures for Ubuntu 24.04 LTS, the latest long-term support release. The installation covers two deployment methods—via the official PPA (recommended for most deployments) and from source code (for advanced configurations)—followed by comprehensive configuration, rule management, and operational procedures.[^1_1][^1_2]

***

## System Requirements and Prerequisites

### Hardware Requirements

| Specification | Minimum | Recommended | High-Performance |
| :-- | :-- | :-- | :-- |
| CPU Cores | 2 | 4-8 | 16+ |
| RAM | 2 GB | 4-8 GB | 16+ GB |
| Disk Space | 5 GB | 20-50 GB | 100+ GB |
| Network Interface | 1 Gbps | 1-10 Gbps | 10+ Gbps |
| NIC Offloading | Not required | Recommended | Required |

For a typical small-to-medium enterprise network deployment, allocate 4 CPU cores and 8 GB RAM to balance performance and cost. High-speed networks (>1 Gbps) require dedicated tuning parameters discussed in the Performance Tuning section.[^1_3][^1_4]

### Software Prerequisites

Ubuntu 24.04 LTS ships with modern kernel versions (6.8+) that include AF_PACKET support, which Suricata uses for packet capture. Verify kernel version compatibility:[^1_1]

```bash
uname -r
```

Expected output: `6.8.0-xx-generic` or later. The guide assumes a fresh Ubuntu 24.04 installation with internet access for package downloads.

***

## System Preparation (Pre-Installation)

### Phase 1: Update and Install Dependencies

Execute the following commands to prepare the system:

```bash
sudo apt update
sudo apt upgrade -y
sudo apt install -y software-properties-common curl wget vim net-tools jq
```

The `jq` tool is essential for parsing Suricata's EVE JSON event output, which contains detailed alert metadata in structured format.[^1_5]

### Phase 2: Identify and Document Network Interface

Before configuration, identify the physical network interface that will monitor traffic:

```bash
ip addr show
```

The output displays all network interfaces with their MAC addresses and IP assignments. For example:

```
2: enp0s3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP
    link/ether 08:00:27:aa:bb:cc brd ff:ff:ff:ff:ff:ff
    inet 192.168.1.100/24 brd 192.168.1.255 scope global dynamic enp0s3
```

Document the interface name (e.g., `enp0s3`) and subnet (e.g., `192.168.1.0/24`), as these are required for configuration. For multi-interface monitoring, repeat this step for each interface.[^1_2][^1_1]

***

## Installation Methods

Suricata offers two installation paths, each with distinct advantages and trade-offs.

### Method 1: Installation via Official PPA Repository (Recommended)

The PPA approach is recommended for production deployments because pre-compiled binaries reduce deployment complexity, ensure consistency across systems, and receive timely security updates.[^1_1]

#### Step 1: Add Official OISF Repository

```bash
sudo add-apt-repository ppa:oisf/suricata-stable
```

This adds the Open Information Security Foundation's stable PPA to your system. Press **ENTER** to confirm.

#### Step 2: Update Package Index

```bash
sudo apt update
```

This fetches the repository metadata, making the latest Suricata packages available for installation.

#### Step 3: Install Suricata and Required Tools

```bash
sudo apt install -y suricata jq
```

The installer automatically:

- Downloads Suricata binaries (typically version 7.0.x as of January 2025)
- Creates system user and group (`suricata`)
- Establishes directory structure (`/etc/suricata`, `/var/lib/suricata`, `/var/log/suricata`)
- Generates default configuration files
- Configures systemd service file for automatic startup


#### Step 4: Verify Installation Success

```bash
sudo suricata --build-info
```

Expected output:

```
Suricata Version 7.0.3
FEATURES: AF_PACKET=yes NFQUEUE=yes ... (additional features)
```

This confirms compilation with critical features including AF_PACKET (for IDS mode) and NFQUEUE (for IPS mode).

***

### Method 2: Installation from Source Code (Advanced)

Source compilation is recommended when:

- Custom features are required (advanced protocol support, specific hardware acceleration)
- Latest development features are needed
- Binary packages lack required capabilities
- Deployment requires precise control over compilation options[^1_6]


#### Step 1: Install Compilation Dependencies

```bash
sudo apt install -y \
    build-essential autoconf automake libtool pkg-config \
    libpcre3 libpcre3-dev libpcap-dev libnet1-dev \
    libyaml-dev libjansson-dev zlib1g-dev libgeoip-dev \
    rustc cargo libssl-dev
```

These dependencies provide:

- **build-essential**: GCC compiler and build tools
- **libpcre3-dev**: Regular expression library for rule matching
- **libpcap-dev**: Packet capture library for network interface access
- **libyaml-dev**: YAML parser for configuration files
- **rustc/cargo**: Rust compiler for modern Suricata components


#### Step 2: Download and Extract Source

```bash
cd /usr/src
sudo wget https://www.openinfosecfoundation.org/download/suricata-7.0.6.tar.gz
sudo tar -xzf suricata-7.0.6.tar.gz
cd suricata-7.0.6
```

Replace `7.0.6` with the latest version available at the official repository.

#### Step 3: Configure Compilation

```bash
./configure \
    --prefix=/usr \
    --sysconfdir=/etc \
    --localstatedir=/var \
    --enable-nfqueue \
    --enable-geoip
```

Key configuration options:


| Option | Purpose | Value |
| :-- | :-- | :-- |
| `--prefix` | Binary installation path | `/usr` |
| `--sysconfdir` | Configuration file location | `/etc/suricata` |
| `--localstatedir` | Log and data directory | `/var/lib/suricata` |
| `--enable-nfqueue` | Enable IPS mode via iptables | Recommended |
| `--enable-geoip` | GeoIP database support | Optional |

#### Step 4: Compile and Install

```bash
sudo make -j$(nproc)
sudo make install-full
```

The `-j$(nproc)` flag parallelizes compilation using all available CPU cores, reducing compilation time from 15-30 minutes to 5-10 minutes depending on hardware.

***

## Basic Configuration

### Phase 1: Essential Configuration Parameters

Edit the main configuration file:

```bash
sudo nano /etc/suricata/suricata.yaml
```

The YAML format requires precise indentation (2 spaces per level). Common formatting errors include:

- Using tabs instead of spaces (YAML prohibition)
- Misaligned dictionary keys
- Unquoted special characters (`:`, `[`, `]`)


#### Configure HOME_NET Variable (Line ~18)

The `HOME_NET` variable defines your protected network. Suricata uses this to distinguish internal traffic from external threats.

**Default configuration (covers RFC 1918 private networks):**

```yaml
HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"
```

**Single subnet example:**

```yaml
HOME_NET: "[10.0.0.0/24]"
```

**Multiple subnets example (multi-branch organization):**

```yaml
HOME_NET: "[10.0.0.0/24,10.1.0.0/24,10.2.0.0/24]"
```

**Single host (server-based monitoring):**

```yaml
HOME_NET: "[192.168.1.100/32]"
```

The `/32` CIDR notation indicates a single host; `/24` indicates a typical Class C network (256 hosts).

#### Configure EXTERNAL_NET Variable (Line ~25)

This variable represents external networks, typically all non-HOME_NET traffic:

```yaml
EXTERNAL_NET: "!$HOME_NET"
```

This syntax (negation operator `!`) dynamically excludes all HOME_NET ranges. Alternative configurations:

```yaml
# Monitor all traffic as external
EXTERNAL_NET: "any"

# Specific external subnets
EXTERNAL_NET: "[203.0.113.0/24,198.51.100.0/24]"
```


#### Configure Network Interface (Line ~615)

Locate the `af-packet` section and specify your monitoring interface:

```yaml
af-packet:
  - interface: enp0s3
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
    tpacket-v3: yes
```

| Parameter | Purpose | Recommended Value |
| :-- | :-- | :-- |
| `interface` | NIC to monitor | From `ip addr` output |
| `cluster-id` | Packet cluster identifier (unique per interface) | 99 (different for multiple interfaces) |
| `cluster-type` | Load distribution method | `cluster_flow` for general use; `cluster_cpu` for high-performance |
| `defrag` | Reassemble fragmented packets | `yes` (improves protocol analysis) |
| `tpacket-v3` | Use modern packet ring buffer API | `yes` (requires kernel 3.2+) |

**Multiple Interface Configuration:**

For organizations monitoring multiple network segments:

```yaml
af-packet:
  - interface: enp0s3
    cluster-id: 99
    cluster-type: cluster_flow
  - interface: enp0s8
    cluster-id: 98
    cluster-type: cluster_flow
```

Use different `cluster-id` values (99, 98, etc.) to prevent resource contention.

### Phase 2: Validate Configuration Syntax

Before running Suricata, test the configuration for YAML syntax errors:

```bash
sudo suricata -T -c /etc/suricata/suricata.yaml -v
```

Expected success output:

```
suricata: Configuration provided was successfully loaded.
```

Common errors and remediation:


| Error | Cause | Solution |
| :-- | :-- | :-- |
| `YAML parse error at line X` | Indentation or syntax error | Verify 2-space indentation; check YAML structure |
| `Unknown rule protocol` | Invalid protocol specification | Review rule files for typos |
| `Cannot bind to interface X` | Interface name incorrect or unavailable | Verify with `ip addr`; check interface is up |


***

## Rule Management with Suricata-Update

Suricata's detection capability depends entirely on current, relevant rules. The `suricata-update` tool automates rule lifecycle management.

### Phase 1: Initial Rule Download

```bash
sudo suricata-update
```

This command:

1. Connects to the Emerging Threats (ET) Open repository
2. Downloads free rule signatures (48,000+ rules as of 2025)
3. Parses rules for enabled/disabled status
4. Resolves dependency relationships (flowbits)
5. Compiles rules to `/var/lib/suricata/rules/suricata.rules`
6. Logs activity with summary statistics

Expected output:

```
-- Using data-directory /var/lib/suricata.
-- Using Suricata configuration /etc/suricata/suricata.yaml
-- Using /etc/suricata/rules for Suricata provided rules.
-- Found Suricata version 7.0.3 at /usr/bin/suricata.
-- Loading /etc/suricata/suricata.yaml
...
-- Total: 48776; Enabled: 47234; Modified: 0; Disabled: 1542
```


### Phase 2: Verify Rules Installation

```bash
ls -lah /var/lib/suricata/rules/
wc -l /var/lib/suricata/rules/suricata.rules
```

Expected output shows file size (typically 30-50 MB) and line count (48,000+ lines).

### Phase 3: Configure Automatic Updates

Schedule daily rule updates to maintain current threat signatures:

```bash
sudo crontab -e
```

Add this line to execute updates at 3 AM daily and restart Suricata:

```cron
0 3 * * * /usr/bin/suricata-update && systemctl restart suricata >/dev/null 2>&1
```

Verify cron job:

```bash
sudo crontab -l
```


### Phase 4: Advanced Rule Source Management

View available rule sources:

```bash
sudo suricata-update list-sources
```

Enable ET Pro ruleset (requires commercial license):

```bash
sudo suricata-update enable-source et/pro
```

Disable specific sources:

```bash
sudo suricata-update disable-source emerging-threats.rules
```

Apply source changes:

```bash
sudo suricata-update
```


***

## Running and Monitoring Suricata

### Phase 1: Start Suricata Service

```bash
sudo systemctl restart suricata
sudo systemctl status suricata
```

Expected status output:

```
● suricata.service - Suricata IDS/IPS
     Loaded: loaded (/etc/systemd/system/suricata.service; enabled; vendor preset: enabled)
     Active: active (running) since Wed 2025-01-21 10:15:23 EET; 2min ago
   Process: 1234 ExecStart=/usr/bin/suricata -c /etc/suricata/suricata.yaml -i enp0s3 (code=exited, status=0/SUCCESS)
   Main PID: 1245 (suricata)
```


### Phase 2: Enable Automatic Startup

```bash
sudo systemctl enable suricata
```

This configures Suricata to start automatically at system boot, ensuring continuous network monitoring.

### Phase 3: Monitor Startup Process

```bash
sudo tail -f /var/log/suricata/suricata.log
```

Expected final lines indicate successful engine initialization:

```
<Notice> - Initializing file-data buffer
<Notice> - Protocol DNS over TCP disabled by default
<Notice> - all 4 packet processing threads, 4 management threads initialized, engine started.
```

If initialization fails, check `/var/log/suricata/suricata.log` for specific error messages.

### Phase 4: Test Detection with Known Signature

Trigger a test alert using a known malicious traffic pattern:

```bash
curl http://testmynids.org/uid/index.html
```

This URL is specifically crafted to match Suricata's test signature (SID 2100498) and should generate an alert.

### Phase 5: Verify Alert Generation

In a separate terminal, monitor for alerts:

```bash
sudo tail -f /var/log/suricata/fast.log
```

Expected output within seconds:

```
01/21/2025-10:20:15.123456  [**] [1:2100498:7] GPL ATTACK_RESPONSE id check returned root [**] [Classification: Potentially Bad Traffic] [Priority: 2] {TCP} 203.0.113.45:80 -> 192.168.1.100:54321
```

The format includes timestamp, Suricata alert ID (SID), alert message, classification, priority level, protocol, and IP addresses with ports.[^1_2]

***

## IPS Mode Configuration (Active Blocking)

IDS mode (default) monitors traffic and generates alerts. IPS mode actively blocks malicious traffic in real-time. IPS requires additional configuration and more careful testing to prevent false positives from blocking legitimate traffic.[^1_7]

### Phase 1: Enable NFQUEUE Support

Edit `/etc/suricata/suricata.yaml` and locate the nfqueue section (approximately line 650):

```bash
sudo nano /etc/suricata/suricata.yaml
```

Uncomment and configure:

```yaml
nfqueue:
  - queue-num: 0
    mode: 'accept'
    repeat-mark: 1
    repeat-mask: 1
    bypass-mark: 1
    bypass-mask: 1
```

Parameters:

- `queue-num`: iptables queue number (0 for single queue; use 0-15 for multiple independent queues)
- `mode: accept`: Accept packets by default if Suricata crashes
- `repeat-mark`: Mark repeated packets for faster processing


### Phase 2: Update Suricata Service Configuration

Edit the systemd service wrapper configuration:

```bash
sudo nano /etc/default/suricata
```

Change the RUN parameter to enable IPS mode:

```bash
RUN=yes
LISTENMODE=nfqueue
```


### Phase 3: Install iptables-persistent

Ensure iptables rules persist across reboots:

```bash
sudo apt install -y iptables-persistent netfilter-persistent
```

During installation, select YES to save current iptables rules.

### Phase 4: Configure iptables Rules

Add iptables rules to send traffic through Suricata (NFQUEUE):

```bash
# Send INPUT traffic through NFQUEUE
sudo iptables -I INPUT -j NFQUEUE

# Send OUTPUT traffic through NFQUEUE
sudo iptables -I OUTPUT -j NFQUEUE

# Send FORWARD traffic through NFQUEUE (for gateway/bridge mode)
sudo iptables -I FORWARD -j NFQUEUE
```

Verify rules:

```bash
sudo iptables -L -n -v | grep NFQUEUE
```

Save rules for persistence:

```bash
sudo netfilter-persistent save
```


### Phase 5: Convert Rules to DROP Action

IPS mode requires rules to use "drop" action rather than "alert":

```bash
# Backup original rules
sudo cp /var/lib/suricata/rules/suricata.rules /var/lib/suricata/rules/suricata.rules.bak

# Convert alert to drop
sudo sed -i 's/^alert/drop/' /var/lib/suricata/rules/suricata.rules
```

Or selectively modify specific high-confidence signatures in the YAML configuration.

### Phase 6: Test IPS Mode

Restart Suricata in IPS mode:

```bash
sudo systemctl restart suricata
```

Verify IPS mode is active:

```bash
sudo tail /var/log/suricata/suricata.log | grep -i "nfqueue\|ips"
```

Expected output: `Starting suricata in IPS (nfqueue) mode... done.`

***

## Logging Architecture and Monitoring

Suricata generates multiple log streams, each serving different operational and forensic purposes.[^1_8][^1_9]

### Log File Overview

| File | Location | Format | Refresh | Purpose |
| :-- | :-- | :-- | :-- | :-- |
| suricata.log | `/var/log/suricata/suricata.log` | Text | Variable | Operational events, errors, warnings |
| fast.log | `/var/log/suricata/fast.log` | Text | Per alert | Single-line alert summaries |
| eve.json | `/var/log/suricata/eve.json` | JSON | Per event | Detailed structured alerts with metadata |
| stats.log | `/var/log/suricata/stats.log` | Text | 8 seconds | Performance metrics and packet statistics |

### Operational Log Monitoring

```bash
# Monitor operational log for errors and warnings
sudo tail -f /var/log/suricata/suricata.log

# Filter for specific severity levels
sudo grep "Error\|Notice" /var/log/suricata/suricata.log | tail -20
```


### Real-Time Alert Monitoring

```bash
# Watch fast.log for incoming alerts
sudo tail -f /var/log/suricata/fast.log

# Count alerts per hour
sudo tail -f /var/log/suricata/fast.log | cut -d'-' -f1 | uniq -c
```


### EVE JSON Parsing with jq

The EVE JSON format provides structured data suitable for analysis tools, SIEM integration, and automation:

```bash
# Display all alerts with key metadata
sudo tail -f /var/log/suricata/eve.json | jq 'select(.event_type=="alert") | {timestamp, src_ip, dest_ip, alert: .alert.signature}'

# Extract alerts by severity
sudo tail -f /var/log/suricata/eve.json | jq 'select(.event_type=="alert" and .alert.severity<3)'

# Generate hourly alert statistics
sudo cat /var/log/suricata/eve.json | jq 'select(.event_type=="alert") | .timestamp' | cut -d'T' -f2 | cut -d':' -f1 | sort | uniq -c
```


### Performance Statistics Monitoring

```bash
# Real-time packet processing rates
sudo tail -f /var/log/suricata/stats.log | grep "capture.kernel_packets\|capture.kernel_drops"

# Parse EVE statistics for detailed metrics
sudo tail -f /var/log/suricata/eve.json | jq 'select(.event_type=="stats") | .stats.capture'

# Monitor for packet drops (indicator of capacity issues)
sudo tail -f /var/log/suricata/eve.json | jq 'select(.event_type=="stats") | .stats.capture | select(.kernel_drops>0)'
```


### Centralized Logging (Optional)

Configure Suricata to send logs to a centralized syslog server:

```yaml
outputs:
  - syslog:
      enabled: yes
      address: "192.168.1.50"
      port: 514
      facility: local5
      format: "[%i] <%d> -- "
```

Restart Suricata and verify syslog reception on the central server.

***

## Performance Tuning and Optimization

Network throughput and CPU utilization significantly impact detection capability and operational cost. Production deployments should incorporate targeted performance tuning.[^1_10][^1_4][^1_3]

### Thread Configuration Strategy

Suricata employs a multi-threaded architecture distributing packet processing across CPU cores:

```yaml
af-packet:
  - interface: enp0s3
    threads: auto
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
```

| Configuration | Scenarios | Performance Impact |
| :-- | :-- | :-- |
| `threads: auto` | Most deployments | Automatically matches CPU core count |
| `threads: 4` (explicit) | Controlled environments | Better predictability and resource isolation |
| `cluster_flow` | General-purpose networks | Hash distribution by flow; lower CPU overhead |
| `cluster_cpu` | High-speed networks | Per-CPU queue; superior performance at high throughput |

### CPU Affinity Configuration (Advanced)

Bind Suricata threads to specific CPU cores to improve cache locality and reduce context switching:

```yaml
threading:
  set-cpu-affinity: yes
  cpu-affinity:
    management-cpu-set:
      cpu: [ 0 ]
    receive-cpu-set:
      cpu: [ 1 ]
    worker-cpu-set:
      cpu: [ 2, 3, 4, 5 ]
      mode: "exclusive"
```

This configuration:

- **Core 0**: Management operations (non-packet processing)
- **Core 1**: Packet reception and initial processing
- **Cores 2-5**: Packet analysis and rule matching (worker threads)


### Memory Buffer Optimization

For high-speed networks (>1 Gbps), increase ring buffer sizes to accommodate traffic bursts:

```yaml
af-packet:
  - interface: enp0s3
    threads: 8
    cluster-id: 99
    cluster-type: cluster_qm
    ring-size: 100000
    block-size: 1048576
    use-mmap: yes
    mmap-locked: yes
    tpacket-v3: yes
```

| Parameter | Purpose | Default | Recommended |
| :-- | :-- | :-- | :-- |
| `ring-size` | Packet buffer slots | 32768 | 100000 (high-speed) |
| `block-size` | Memory block size | 32768 | 1048576 (1MB blocks) |
| `use-mmap` | Memory-mapped I/O | no | yes |
| `mmap-locked` | Lock memory in RAM | no | yes |

### Performance Verification

Monitor real-time metrics to validate tuning effectiveness:

```bash
# Extract packet statistics from eve.json
sudo tail -f /var/log/suricata/eve.json | jq 'select(.event_type=="stats") | {
  packets_captured: .stats.capture.kernel_packets,
  packets_dropped: .stats.capture.kernel_drops,
  packets_processed: .stats.decoder.pkts,
  alerts_generated: .stats.alert.alerts
}'
```

Key performance indicators:

- **Kernel drops ≈ 0**: System handling traffic correctly
- **Kernel drops > 0 and rising**: Insufficient resources; add threads, cores, or upgrade hardware
- **Decoder.pkts ≈ kernel_packets**: Normal protocol distribution and processing
- **Alert rate trending**: Baseline for anomaly detection

***

## Troubleshooting and Diagnostics

### Issue 1: Suricata Service Fails to Start

**Diagnosis:**

```bash
sudo systemctl status suricata
sudo journalctl -u suricata -n 100
```

**Common causes:**


| Symptom | Cause | Resolution |
| :-- | :-- | :-- |
| `YAML parse error` | Configuration syntax error | Run `sudo suricata -T -c /etc/suricata/suricata.yaml -v` |
| `Cannot bind to interface` | Interface name incorrect or down | Verify with `ip addr`; check `ip link show` for status |
| `Permission denied` | User/group permission issue | Verify file ownership: `sudo chown -R suricata:suricata /var/lib/suricata` |
| `Port already in use` | Another process using Suricata socket | Check `sudo netstat -tlnp` for conflicts |

### Issue 2: No Alerts Generated Despite Active Traffic

**Diagnosis:**

```bash
# Verify interface receives packets
sudo tcpdump -i enp0s3 -c 20

# Check if rules are loaded
grep -c "^alert\|^drop" /var/lib/suricata/rules/suricata.rules

# Verify alert output enabled
grep "eve-log:\|fast-log:" /etc/suricata/suricata.yaml
```

**Causes and remediation:**

- **Interface is not capturing**: Verify interface name in configuration matches `ip addr` output
- **No rules loaded**: Run `sudo suricata-update` to download rules
- **Alert logging disabled**: Enable in suricata.yaml: `eve-log: enabled: yes`


### Issue 3: High CPU Usage and Packet Drops

**Diagnosis:**

```bash
# Monitor CPU usage per thread
top -p $(pgrep -f suricata) -H

# Extract drop statistics
sudo tail /var/log/suricata/eve.json | jq 'select(.event_type=="stats") | .stats.capture'
```

**Remediation strategies:**

1. **Increase thread count**: Set `threads: 8` (or higher based on core count)
2. **Increase memory buffers**: `ring-size: 100000`, `block-size: 1048576`
3. **Reduce rule complexity**: Disable unnecessary protocol analyzers in suricata.yaml
4. **Upgrade hardware**: Add CPU cores or RAM to accommodate sustained traffic
5. **Offload to specialized hardware**: Deploy dedicated IDS sensors with hardware acceleration

### Issue 4: Rapid Disk Usage Growth

**Diagnosis:**

```bash
du -sh /var/log/suricata/*
# Find largest logs
find /var/log/suricata -type f -exec du -sh {} \; | sort -h
```

**Remediation:**

```bash
# Enable log rotation for eve.json (every 100MB)
# Modify /etc/suricata/suricata.yaml eve-log section:
outputs:
  - eve-log:
      enabled: yes
      filename: eve.json
      rotate: 100mb

# Archive and compress old logs
sudo tar -czf /archive/suricata-logs-$(date +%Y%m%d).tar.gz /var/log/suricata/*.log.1
sudo rm -f /var/log/suricata/*.log.1
```


***

## Advanced Configuration Examples

### Multi-Interface Monitoring

For organizations monitoring multiple network segments, configure multiple af-packet instances:

```yaml
af-packet:
  - interface: enp0s3
    cluster-id: 99
    cluster-type: cluster_flow
    threads: 4
  - interface: enp0s8
    cluster-id: 98
    cluster-type: cluster_flow
    threads: 4
```

Restart Suricata:

```bash
sudo systemctl restart suricata
```


### Custom Rule Creation

Create organization-specific detection rules in `/etc/suricata/rules/custom.rules`:

```bash
sudo nano /etc/suricata/rules/custom.rules
```

Example rule detecting suspicious User-Agent strings:

```
alert http $HOME_NET any -> $EXTERNAL_NET any (
  msg:"Suspicious User-Agent - Bot Detection";
  content:"User-Agent|3a|";
  content:"BadBot|3b|";
  http_header;
  sid:1000001;
  rev:1;
  classtype:bad-unknown;
)
```

Register in suricata.yaml:

```yaml
rule-files:
  - suricata.rules
  - custom.rules
```

Validate and restart:

```bash
sudo suricata -T -c /etc/suricata/suricata.yaml -v
sudo systemctl restart suricata
```


***

## Comparison: IDS vs. IPS Mode

| Characteristic | IDS (Default) | IPS (NFQUEUE) |
| :-- | :-- | :-- |
| **Traffic Action** | Monitor and alert only | Monitor, alert, and block |
| **False Positive Impact** | Alerts reviewed manually | Blocks traffic (service disruption) |
| **Configuration Complexity** | Low | High (iptables rules required) |
| **Performance Overhead** | Low (capture only) | Moderate-high (drop decision) |
| **Deployment Scenario** | Detection/forensics | Perimeter defense/inline |
| **Rule Action** | alert (default) | drop/reject |

**Recommendation**: Deploy IDS mode for initial evaluation and baseline development. Transition to IPS mode only after validating rule accuracy and coordinating with network operations to minimize false positive incidents.

***

## Deployment Checklist

Use this checklist for production deployment validation:

- [ ] System meets hardware requirements (2+ cores, 4+ GB RAM, 20+ GB disk)
- [ ] Ubuntu 24.04 LTS installed and updated
- [ ] Network interface identified and documented
- [ ] Suricata installed via PPA and verified (`suricata --version`)
- [ ] HOME_NET and EXTERNAL_NET configured for environment
- [ ] Network interface specified in af-packet section
- [ ] Configuration validated (`suricata -T`)
- [ ] Rules downloaded (`suricata-update`)
- [ ] Service started and enabled (`systemctl start`, `systemctl enable`)
- [ ] Test alert generated and detected (curl testmynids.org)
- [ ] Log files verified and accessible
- [ ] Performance metrics established (CPU, memory, packet rates)
- [ ] Automated rule updates scheduled (cron job configured)
- [ ] Monitoring and alerting integrated with SOC/SIEM
- [ ] Backup configuration documented

***

## Summary

This comprehensive guide provides enterprise-grade procedures for deploying Suricata IDS/IPS on Ubuntu 24.04 LTS. The two-method installation approach—PPA for production deployments and source for advanced configurations—accommodates diverse operational requirements. Configuration covers essential parameters (HOME_NET, EXTERNAL_NET, network interface), rule management automation, IPS mode for active threat blocking, and performance optimization for high-speed networks.

The resulting deployment establishes real-time network intrusion detection, generating structured alerts compatible with SIEM integration and security orchestration platforms. Performance monitoring procedures enable continuous optimization, while troubleshooting guidance addresses common operational issues. With proper configuration and maintenance, Suricata provides cost-effective, open-source threat detection matching enterprise-grade security appliances.[^1_11][^1_6][^1_2][^1_1]

***

## References

Official Suricata Quickstart Guide, docs.suricata.io/en/latest/quickstart.html[^1_1]
HowtoForge Ubuntu 24.04 Installation Guide[^1_11]
Wafatech Comprehensive Setup Guide[^1_6]
YouTube: Suricata IDS/IPS Installation Tutorial (2024-2025)[^1_12]
DigitalOcean: Ubuntu 22.04 Installation and Configuration[^1_13]
Server-World: Ubuntu 24.04 Suricata Installation[^1_2]
Suricata Official Documentation: Rule Format and Syntax[^1_14]
AF_PACKET Configuration and Multi-Interface Setup[^1_15]
EVE JSON Output Format Documentation[^1_16]
NFQUEUE IPS Mode Configuration for Linux[^1_17]
Performance Tuning and CPU Affinity[^1_18]
Syslog-ng Integration for Centralized Logging[^1_19]
Suricata Rule Management with suricata-update[^1_20]
High-Performance Configuration Best Practices[^1_21]
Troubleshooting and Diagnostic Procedures[^1_22]
<span style="display:none">[^1_23][^1_24][^1_25][^1_26][^1_27][^1_28][^1_29][^1_30][^1_31][^1_32][^1_33][^1_34][^1_35][^1_36][^1_37][^1_38]</span>

<div align="center">⁂</div>

[^1_1]: https://www.howtoforge.com/how-to-install-suricata-ids-on-ubuntu-24-04-server/

[^1_2]: https://www.server-world.info/en/note?os=Ubuntu_24.04\&p=suricata

[^1_3]: https://redpiranha.net/news/High-speed-IDP/S-suricata-hardware-tuning-for-60gpbs-throughput

[^1_4]: https://docs.suricata.io/en/latest/performance/high-performance-config.html

[^1_5]: https://docs.suricata.io/en/latest/output/eve/eve-json-output.html

[^1_6]: https://wafatech.sa/blog/linux/linux-security/comprehensive-guide-to-setting-up-suricata-ids-ips-on-your-linux-server/

[^1_7]: https://www.digitalocean.com/community/tutorials/how-to-configure-suricata-as-an-intrusion-prevention-system-ips-on-ubuntu-20-04

[^1_8]: https://1modm.github.io/Troubleshooting_with_Suricata.html

[^1_9]: https://www.syslog-ng.com/community/b/blog/posts/analyze-your-suricata-logs-in-real-time-using-syslog-ng

[^1_10]: https://www.onlinehashcrack.com/guides/security-tools/suricata-ids-tuning-boost-detection.php

[^1_11]: https://letsdefend.io/blog/how-to-install-and-configure-suricata-on-ubuntu

[^1_12]: https://www.youtube.com/watch?v=8Q3Nhyvh-1I

[^1_13]: https://www.digitalocean.com/community/questions/how-to-install-and-configure-suricata-on-ubuntu-22-04

[^1_14]: https://www.hackingarticles.in/configure-suricata-ids-ubuntu/

[^1_15]: https://forum.netgate.com/topic/173514/suricata-interfaces

[^1_16]: https://www.hostinger.com/uk/tutorials/how-to-install-suricata-on-ubuntu

[^1_17]: https://www.youtube.com/watch?v=wmcmu6znlCQ

[^1_18]: https://docs.suricata.io/en/suricata-6.0.20/quickstart.html

[^1_19]: https://cloud-courses.upb.ro/docs/security/ids/

[^1_20]: https://serverspace.io/support/help/how-to-install-suricata-on-ubuntu-20-04/

[^1_21]: https://github.com/AlexeyKuzko/ITMO_Suricata-IPS-Docker-Lab

[^1_22]: https://manpages.ubuntu.com/manpages/plucky/man1/suricata.1.html

[^1_23]: http://pevma.blogspot.com/2015/05/suricata-multiple-interface.html

[^1_24]: https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Setting_up_IPSinline_for_Linux

[^1_25]: https://redmine.openinfosecfoundation.org/issues/3778

[^1_26]: http://docs.tenzir.com/integrations/suricata/

[^1_27]: https://home.regit.org/2012/09/new-af_packet-ips-mode-in-suricata/

[^1_28]: https://docs.suricata.io/en/latest/output/eve/eve-json-format.html

[^1_29]: https://github.com/Security-Onion-Solutions/securityonion/discussions/6092

[^1_30]: https://jasonish.org/blog/quick-guide-building-testing-suricata-linux/

[^1_31]: https://github.com/cisagov/malcolm/issues/723

[^1_32]: https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Unit_Tests

[^1_33]: https://www.youtube.com/watch?v=ZgvcVVLoGd8

[^1_34]: https://support.kaspersky.com/help/XDR/1.3/en-US/265590.htm

[^1_35]: https://coralogix.com/blog/writing-effective-suricata-rules-with-examples-best-practices/

[^1_36]: http://www.bictor.com/2024/07/02/ubuntu-24-04-problems-solutions/

[^1_37]: https://www.virtono.com/community/tutorial-how-to/how-to-install-suricata-on-ubuntu-22-04/

[^1_38]: https://docs.suricata.io/en/latest/rules/intro.html

