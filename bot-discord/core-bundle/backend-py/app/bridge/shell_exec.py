from subprocess import run, CompletedProcess
from typing import List


def run_command(args: List[str]) -> CompletedProcess[str]:
    return run(args, capture_output=True, text=True, check=False)
