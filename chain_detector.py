CHAIN_STATE = {}

FILELESS_PATTERN = [
    "MEMFD_CREATE",
    "MPROTECT_EXEC",
    "EXECVE"
]


def detect_fileless_chain(pid, event_type):
    if pid not in CHAIN_STATE:
        CHAIN_STATE[pid] = []
    CHAIN_STATE[pid].append(event_type)
    chain = CHAIN_STATE[pid]
    if all(step in chain for step in FILELESS_PATTERN):
        return True
    return False