import subprocess
import os
import sys


def get_cgroup_id(container):

    try:
        full_id = subprocess.check_output(
            ["docker", "inspect", "--format", "{{.Id}}", container]
        ).decode().strip()

        paths = [
            f"/sys/fs/cgroup/system.slice/docker-{full_id}.scope",
            f"/sys/fs/cgroup/docker/{full_id}"
        ]
        for path in paths:
            if os.path.exists(path):
                return os.stat(path).st_ino
        raise Exception("cgroup path not found")

    except Exception as e:
        print(f"[!] cgroup resolution failed: {e}")
        sys.exit(1)