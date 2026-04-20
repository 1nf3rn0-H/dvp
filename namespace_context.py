import os


def namespace_metadata(pid):
    meta = {}
    try:
        meta["pid_ns"] = os.readlink(f"/proc/{pid}/ns/pid")
        meta["mnt_ns"] = os.readlink(f"/proc/{pid}/ns/mnt")
        meta["net_ns"] = os.readlink(f"/proc/{pid}/ns/net")
    except:
        meta["namespace_error"] = True
    return meta