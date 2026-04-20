from bcc import BPF
import ctypes as ct
import socket
import struct
import re
import argparse
from datetime import datetime, timezone

from ctypes_structs import *
from event_types import *
from cgroup_resolver import get_cgroup_id
from payload_extractor import *
from attack_map import ATTACK_MAP
from visibility_matrix import VISIBILITY_MATRIX
from risk_model import RISK_MODEL
from namespace_context import namespace_metadata
from chain_detector import detect_fileless_chain
from gap_analyzer import compute_visibility_gaps
from exporters.json_logger import emit_json
from exporters.splunk_fixture import emit_splunk_fixture


def base_event(event_type, pid, comm):
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "sensor": "detection_visibility_probe",
        "event_type": event_type,
        "actor": {
            "pid": pid,
            "process_name": comm
        }
    }


def enrich(event):
    etype = event["event_type"]
    event["attack_technique"] = ATTACK_MAP.get(etype)
    event["risk_score"] = RISK_MODEL.get(etype)
    event["visibility_matrix"] = VISIBILITY_MATRIX.get(etype)
    event["namespace_context"] = namespace_metadata(
        event["actor"]["pid"]
    )
    return event


def handle_event(ctx, data, size):
    common = ct.cast(data, ct.POINTER(CommonData)).contents

    pid = common.pid

    comm = common.comm.decode()
    event_name = EVENT_NAME_MAP[common.type]
    log = base_event(event_name, pid, comm)
    log = enrich(log)

    if runtime_args.gap_analysis:
        log["visibility_gaps"] = compute_visibility_gaps(log)

    emit_json(log)
    if runtime_args.emit_splunk_tests:
        emit_splunk_fixture(log)


parser = argparse.ArgumentParser()
parser.add_argument("-c", "--container", required=True)
parser.add_argument("--gap-analysis", action="store_true")
parser.add_argument("--emit-splunk-tests", action="store_true")
runtime_args = parser.parse_args()

cgroup_id = get_cgroup_id(runtime_args.container)


b = BPF(src_file="ebpf/runtime_probe.c")
b["target_cgroup"][ct.c_int(0)] = ct.c_uint64(cgroup_id)
b["events"].open_ring_buffer(handle_event)


while True:
    b.ring_buffer_poll()