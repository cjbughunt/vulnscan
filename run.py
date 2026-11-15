"""Launch the VulnScan dashboard.

Usage:
    python run.py                 # http://127.0.0.1:8000
    python run.py --port 9000 --host 0.0.0.0
"""
import argparse
import uvicorn

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--reload", action="store_true")
    args = ap.parse_args()
    print(f"VulnScan dashboard -> http://{args.host}:{args.port}")
    uvicorn.run("backend.app:app", host=args.host, port=args.port, reload=args.reload)
