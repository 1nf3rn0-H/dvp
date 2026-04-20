VISIBILITY_MATRIX = {

    "EXECVE": {
        "auditd": True,
        "sysmon": True,
        "falco": True,
        "tracepoint": True
    },

    "MEMFD_CREATE": {
        "auditd": False,
        "sysmon": False,
        "falco": True,
        "tracepoint": True
    },

    "MPROTECT_EXEC": {
        "auditd": False,
        "sysmon": False,
        "falco": True,
        "tracepoint": True
    },

    "PROCESS_VM_WRITEV": {
        "auditd": False,
        "sysmon": "partial",
        "falco": True,
        "tracepoint": True
    },

    "NETWORK_CONNECT": {
        "auditd": True,
        "sysmon": True,
        "falco": True,
        "tracepoint": True
    }
}