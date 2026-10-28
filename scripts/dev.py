#!/usr/bin/env python3
"""
Local development CLI for threats.top.

Zero third-party dependencies (Python stdlib plus `node --test`).

    python3 scripts/dev.py test
    python3 scripts/dev.py validate
    python3 scripts/dev.py sync --feed auto
    python3 scripts/dev.py serve --port 8080
"""
import argparse
import http.server
import os
import socketserver
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"


def run(command, env=None):
    return subprocess.run(command, cwd=ROOT, env=env).returncode


def cmd_validate(_args):
    return run([sys.executable, "scripts/validate_feeds.py", "--no-regression"])


def cmd_test(_args):
    steps = [
        ("timestamp normalisation", [sys.executable, "scripts/normalize.py"]),
        ("feed validator", [sys.executable, "scripts/validate_feeds.py", "--no-regression"]),
        ("python unit tests", [sys.executable, "-m", "unittest", "discover", "-s", "scripts/tests", "-t", "scripts"]),
    ]
    for label, command in steps:
        print(f"==> {label}")
        code = run(command)
        if code != 0:
            return code

    print("==> node unit tests (assets + worker + scheduler)")
    env = os.environ.copy()
    env["PATH"] = ":".join(["/opt/homebrew/bin", "/usr/local/bin", env.get("PATH", "")])
    return run(["node", "--test", "assets", "worker", "scheduler"], env=env)


def cmd_sync(args):
    command = [sys.executable, "scripts/run_collectors.py", "--feeds", args.feed]
    code = run(command)
    if code != 0:
        return code
    return cmd_validate(args)


class StaticHandler(http.server.SimpleHTTPRequestHandler):
    # HTTP/1.1 keeps the browser's six pooled connections open across the ten
    # feed fetches; HTTP/1.0 opens one connection per file.
    protocol_version = "HTTP/1.1"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)


class StaticServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    # The stdlib default is 5, and the overview opens ten connections at once.
    request_queue_size = 64


def make_server(port):
    return StaticServer(("127.0.0.1", port), StaticHandler)


def cmd_serve(args):
    httpd = make_server(args.port)
    with httpd:
        print(f"Serving threats.top locally at http://localhost:{args.port}")
        print("Press Ctrl+C to stop.")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nStopped.")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("test", help="run normalisation, validator, Python and Node tests")
    sub.add_parser("validate", help="validate every data/*.json feed")

    sync = sub.add_parser("sync", help="run due collectors (or a named source)")
    sync.add_argument("--feed", default="auto",
                      help="auto, all, or a comma-separated source id")

    serve = sub.add_parser("serve", help="serve the static site locally")
    serve.add_argument("--port", type=int, default=8080)

    args = parser.parse_args()
    handlers = {
        "test": cmd_test,
        "validate": cmd_validate,
        "sync": cmd_sync,
        "serve": cmd_serve,
    }
    return handlers[args.cmd](args)


if __name__ == "__main__":
    raise SystemExit(main())
