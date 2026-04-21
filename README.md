# Detection Visibility Probe (DVP)

Detection Visibility Probe (DVP) is a lightweight eBPF-based sensor for detection engineers that helps measure runtime telemetry coverage, validate detection rules, and identify visibility gaps across Linux environments.


## Features

- eBPF runtime telemetry collection
- Container-scoped tracing (via cgroups)
- MITRE ATT&CK mapping
- Detection visibility matrix scoring
- Namespace-aware enrichment
- Fileless execution signal detection
- Memory injection primitive detection
- Splunk Detection-as-Code fixture generation support

## Monitored Events
| Primitive           | ATT&CK Technique      |
| ------------------- | --------------------- |
| execve              | T1106                 |
| memfd_create        | T1620                 |
| process_vm_writev   | T1055                 |
| mprotect(PROT_EXEC) | Shellcode loaders     |
| connect()           | C2 / pivot indicators |

## Architecture

```
sensor.py
├── ebpf/runtime_probe.c
├── Enrichment Modules
│   ├── attack_map.py
│   ├── risk_model.py
│   ├── visibility_matrix.py
│   ├── chain_detector.py
│   └── gap_analyzer.py
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
python sensor.py -c ubuntu --gap-analysis

# Generate Splunk test fixtures
python sensor.py -c ubuntu --emit-splunk-tests
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

## Demo Video
https://drive.google.com/file/d/1xeXc_65ULP7jBvVu_GC-Llh_TI7u-U-j/view?usp=sharing

## Security Considerations

- DVP requires privileged access to load eBPF programs
- Monitor only trusted containers in production
- Regularly update eBPF programs for new kernel versions
- Validate output before integration with SIEM systems