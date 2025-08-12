# Intentionally insecure Python snippet for SAST (Bandit) demo
import os
import subprocess

def run_user_cmd(cmd):
    # Command injection risk (for SAST demo only)
    return subprocess.check_output(cmd, shell=True)

def get_secret():
    return os.environ.get("SUPER_SECRET", "default")
