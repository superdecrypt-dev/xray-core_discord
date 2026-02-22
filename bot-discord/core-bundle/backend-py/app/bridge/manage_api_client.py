from pathlib import Path
from subprocess import run


BRIDGE_SCRIPT = Path(__file__).resolve().parents[3] / "bridge" / "manage_api.sh"


def call_manage_api(action: str) -> dict:
    proc = run([str(BRIDGE_SCRIPT), action], capture_output=True, text=True, check=False)
    return {"code": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr}
