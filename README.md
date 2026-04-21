# Detection Visibility Probe (DVP)

A container security monitoring system that uses eBPF to detect and analyze potential security threats in real-time. DVP provides comprehensive visibility into containerized workloads by monitoring system calls, enriching events with threat intelligence, and identifying detection gaps across security layers.

## Features

- **Real-time eBPF Monitoring**: Uses eBPF tracepoints to monitor critical system calls without performance overhead
- **Threat Intelligence Enrichment**: Maps events to MITRE ATT&CK techniques and assigns risk scores
- **Visibility Gap Analysis**: Identifies which security tools lack visibility into detected events
- **Attack Chain Detection**: Detects fileless execution patterns and other attack sequences
- **Multi-format Export**: Supports JSON logging and Splunk fixture generation for integration
- **Container-aware**: Targets specific containers using cgroup isolation

## Monitored Events

- **EXECVE**: Process execution events
- **MEMFD_CREATE**: Memory file descriptor creation (fileless execution primitive)
- **MPROTECT_EXEC**: Memory protection changes to executable
- **PROCESS_VM_WRITEV**: Process memory injection
- **NETWORK_CONNECT**: Network connection attempts

## Architecture

```
sensor.py (Python)
├── ebpf/runtime_probe.c (eBPF program)
├── Enrichment Modules
│   ├── attack_map.py (MITRE ATT&CK mapping)
│   ├── risk_model.py (Risk scoring)
│   ├── visibility_matrix.py (Tool visibility)
│   ├── chain_detector.py (Attack pattern detection)
│   └── gap_analyzer.py (Detection gap analysis)
└── Exporters
    ├── json_logger.py
    └── splunk_fixture.py
```

## Prerequisites

- Linux kernel with eBPF support (4.15+)
- BCC (BPF Compiler Collection)
- Python 3.6+
- Docker/container runtime for target monitoring

## Installation

1. Install BCC:
```bash
# Ubuntu/Debian
sudo apt-get install bcc-tools python3-bcc

# CentOS/RHEL
sudo yum install bcc-tools python3-bcc
```

2. Install Python dependencies:
```bash
pip install -r requirements.txt
```

## Usage

```bash
python sensor.py -c <container_name> [options]
```

### Options

- `-c, --container`: Target container name (required)
- `--gap-analysis`: Enable visibility gap analysis
- `--emit-splunk-tests`: Generate Splunk fixture data

### Example

```bash
# Monitor nginx container with gap analysis
python sensor.py -c nginx --gap-analysis

# Generate Splunk test fixtures
python sensor.py -c webapp --emit-splunk-tests
```

## Output Format

Events are emitted as JSON with the following structure:

```json
{
  "timestamp": "2024-01-15T10:30:45.123456+00:00",
  "sensor": "detection_visibility_probe",
  "event_type": "MEMFD_CREATE",
  "actor": {
    "pid": 1234,
    "process_name": "malicious_binary"
  },
  "attack_technique": "T1620",
  "risk_score": 8.5,
  "visibility_matrix": {
    "auditd": false,
    "sysmon": false,
    "falco": true,
    "tracepoint": true
  },
  "namespace_context": {...},
  "visibility_gaps": ["auditd", "sysmon"]
}
```

## Security Layers Visibility

DVP tracks visibility across common security tools:

- **auditd**: Linux audit daemon
- **sysmon**: System Monitor for Linux
- **falco**: Runtime security monitoring
- **tracepoint**: eBPF tracepoints

## Risk Scoring

Events are assigned risk scores from 1.0-10.0:
- NETWORK_CONNECT: 4.0 (Moderate)
- EXECVE: 3.0 (Low-Moderate)
- MPROTECT_EXEC: 7.5 (High)
- MEMFD_CREATE: 8.5 (High)
- PROCESS_VM_WRITEV: 9.2 (Critical)

## Attack Chain Detection

Detects fileless execution chains:
1. MEMFD_CREATE → Memory-backed file creation
2. MPROTECT_EXEC → Making memory executable
3. EXECVE → Executing from memory

## Development

### Building eBPF Programs

```bash
# Compile eBPF program
clang -O2 -target bpf -c ebpf/runtime_probe.c -o runtime_probe.o
```

### Testing

```bash
# Run with test container
docker run -d --name test-container nginx
python sensor.py -c test-container --gap-analysis
```

## Security Considerations

- DVP requires privileged access to load eBPF programs
- Monitor only trusted containers in production
- Regularly update eBPF programs for new kernel versions
- Validate output before integration with SIEM systems
