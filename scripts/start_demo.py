"""Start the E1-US1 FastAPI backend and Streamlit UI."""

from __future__ import annotations

import argparse
import importlib.util
import os
import socket
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REQUIRED_MODULES = ("cv2", "fastapi", "httpx", "joblib", "numpy", "pandas", "PIL", "streamlit", "uvicorn")
REQUIRED_FILES = (Path("app/main.py"), Path("app/ui/streamlit_app.py"), Path("models/url_risk_model.joblib"), Path("models/model_metadata.json"), Path(".streamlit/config.toml"))


def run_checks() -> list[str]:
    errors = [f"Missing Python dependency: {name}" for name in REQUIRED_MODULES if importlib.util.find_spec(name) is None]
    errors.extend(f"Missing required file: {path}" for path in REQUIRED_FILES if not (ROOT / path).is_file())
    return errors


def _port_available(port: int) -> bool:
    """Check whether the local demo port can be bound before spawning children."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        try:
            probe.bind(("127.0.0.1", port))
        except OSError:
            return False
    return True


def _port(value: str) -> int:
    port = int(value)
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return port


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--api-port", type=_port, default=8000)
    parser.add_argument("--ui-port", type=_port, default=8501)
    args = parser.parse_args()
    errors = run_checks()
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print("Demo checks passed.")
    if args.check:
        return 0

    occupied = [
        f"API port {args.api_port}" if not _port_available(args.api_port) else None,
        f"UI port {args.ui_port}" if not _port_available(args.ui_port) else None,
    ]
    occupied = [item for item in occupied if item]
    if occupied:
        print(
            "Cannot start the demo because "
            + " and ".join(occupied)
            + " is already in use. Stop the old process or choose free ports "
            "with --api-port and --ui-port.",
            file=sys.stderr,
        )
        return 1

    api = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "app.main:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(args.api_port),
        ],
        cwd=ROOT,
    )
    # --server.headless=true skips Streamlit's first-run email prompt, which would
    # otherwise block startup on a machine without ~/.streamlit/credentials.toml.
    ui_environment = os.environ.copy()
    ui_environment["QR_API_BASE_URL"] = f"http://127.0.0.1:{args.api_port}"
    ui = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "streamlit",
            "run",
            "app/ui/streamlit_app.py",
            "--server.address",
            "127.0.0.1",
            "--server.port",
            str(args.ui_port),
            "--server.headless", "true", "--browser.gatherUsageStats", "false",
        ],
        cwd=ROOT,
        env=ui_environment,
    )
    print(
        f"API:  http://127.0.0.1:{args.api_port}  (health: /health, docs: /docs)"
    )
    print(f"UI:   http://127.0.0.1:{args.ui_port}")
    print("Press Ctrl+C to stop.")
    try:
        api.wait()
        return 0
    finally:
        ui.terminate()


if __name__ == "__main__":
    raise SystemExit(main())
