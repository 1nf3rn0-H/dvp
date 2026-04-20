import os
import hashlib


def extract_memfd_payload(pid, fd):
    path = f"/proc/{pid}/fd/{fd}"
    try:
        with open(path, "rb") as f:
            payload = f.read()

        outfile = f"dump_memfd_{pid}_{fd}.bin"
        with open(outfile, "wb") as out:
            out.write(payload)

        return {
            "status": "extracted",
            "artifact": outfile,
            "sha256": hashlib.sha256(payload).hexdigest()
        }
    except Exception as e:
        return {"status": "failed", "error": str(e)}



def extract_injection_payload(pid, addr, size):
    try:
        with open(f"/proc/{pid}/mem", "rb") as mem:
            mem.seek(addr)
            payload = mem.read(size)

        outfile = f"dump_inject_{pid}_{addr}.bin"
        with open(outfile, "wb") as f:
            f.write(payload)

        return {
            "status": "extracted",
            "artifact": outfile,
            "sha256": hashlib.sha256(payload).hexdigest()
        }

    except Exception as e:
        return {"status": "failed", "error": str(e)}