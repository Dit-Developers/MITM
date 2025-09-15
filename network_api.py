#!/usr/bin/env python3
"""
tshark_live_firebase_debug.py

Improved live capture -> Firebase uploader with verbose HTTP/logging and test-upload mode.

Usage:
  sudo python3 tshark_live_firebase_debug.py         # start live capture and upload
  python3 tshark_live_firebase_debug.py --test-upload  # send a single test record to firebase (no tshark required)

Requirements:
  pip install requests

CONFIG:
 - Set FIREBASE_BASE to your DB root (example provided).
 - If your DB requires an auth token, set FIREBASE_AUTH to that token (string).
 - Choose UPLOAD_METHOD = "put" (to use /tshark/<uuid>.json) or "post" (to use /tshark.json POST).
"""

import subprocess
import threading
import queue
import requests
import uuid
import json
import time
import os
import signal
import sys
from datetime import datetime
import argparse
import math

# ---------------- CONFIG ----------------
FIREBASE_BASE = "https://techwiz-7f7ab-default-rtdb.firebaseio.com"  # <-- change only if needed
FIREBASE_NODE = "tshark"
# If your DB requires auth token (database secret or idToken), set it here. Otherwise leave None.
FIREBASE_AUTH = None  # e.g. "eyJhbGciOi..." or "YOUR_DB_SECRET"

# Upload method: "put" => stores at /tshark/<uuid>.json (safe, deterministic key)
# or "post" => POST to /tshark.json letting Firebase create the child key automatically.
UPLOAD_METHOD = "put"  # "put" or "post"

# File to persist unsent items
UNSENT_FILE = "unsent_queue.jsonl"

# Tshark command - structured fields (robust parsing)
TSHARK_CMD = [
    "tshark",
    "-l",  # line buffered stdout
    "-n",  # numeric addresses
    "-T", "fields",
    "-E", "separator=|",
    "-E", "quote=d",
    "-E", "occurrence=f",
    "-e", "frame.number",
    "-e", "frame.time_epoch",
    "-e", "ip.src",
    "-e", "ip.dst",
    "-e", "tcp.srcport",
    "-e", "tcp.dstport",
    "-e", "udp.srcport",
    "-e", "udp.dstport",
    "-e", "_ws.col.Protocol",
    "-e", "frame.len",
    "-e", "_ws.col.Info"
]

# Behavior tuning
SENDER_THREADS = 3
MAX_RETRIES = 7
BASE_RETRY_DELAY = 1.0  # seconds (exponential backoff)
REQUEST_TIMEOUT = 12  # seconds

# ---------------- Derived URLs ----------------
def make_post_url():
    q = f"?auth={FIREBASE_AUTH}" if FIREBASE_AUTH else ""
    return FIREBASE_BASE.rstrip("/") + f"/{FIREBASE_NODE}.json" + q

def make_put_url(key):
    q = f"?auth={FIREBASE_AUTH}" if FIREBASE_AUTH else ""
    return FIREBASE_BASE.rstrip("/") + f"/{FIREBASE_NODE}/{key}.json" + q

POST_URL = make_post_url()

# ---------------- Globals ----------------
send_queue = queue.Queue()
stop_event = threading.Event()

# ---------------- Helpers ----------------
def now_ts():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

def persist_unsent(key, rec):
    try:
        with open(UNSENT_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps({"key": key, "record": rec}) + "\n")
    except Exception as e:
        print(f"[{now_ts()}] ERROR persisting unsent: {e}", file=sys.stderr)

def load_persisted_unsent():
    if not os.path.exists(UNSENT_FILE):
        return 0
    count = 0
    try:
        with open(UNSENT_FILE, "r", encoding="utf-8") as f:
            for ln in f:
                ln = ln.strip()
                if not ln:
                    continue
                try:
                    obj = json.loads(ln)
                    key = obj.get("key") or uuid.uuid4().hex
                    send_queue.put({"key": key, "record": obj.get("record"), "attempts": 0})
                    count += 1
                except Exception:
                    continue
        # rotate file to avoid re-loading on next run
        try:
            os.rename(UNSENT_FILE, UNSENT_FILE + ".loaded")
        except Exception:
            pass
    except Exception as e:
        print(f"[{now_ts()}] ERROR loading persisted unsent: {e}", file=sys.stderr)
    return count

def http_put_record(key, rec):
    url = make_put_url(key)
    try:
        resp = requests.put(url, json=rec, timeout=REQUEST_TIMEOUT)
        return resp.status_code, resp.text
    except Exception as e:
        return None, str(e)

def http_post_record(rec):
    try:
        resp = requests.post(POST_URL, json=rec, timeout=REQUEST_TIMEOUT)
        return resp.status_code, resp.text
    except Exception as e:
        return None, str(e)

def sender_worker(worker_id):
    while not stop_event.is_set() or not send_queue.empty():
        try:
            item = send_queue.get(timeout=0.5)
        except queue.Empty:
            continue

        key = item.get("key") or uuid.uuid4().hex
        rec = item["record"]
        attempts = item.get("attempts", 0)

        # choose method
        if UPLOAD_METHOD.lower() == "post":
            code, text = http_post_record(rec)
        else:
            code, text = http_put_record(key, rec)

        ts = now_ts()
        if code and 200 <= int(code) < 300:
            # ✅ success → update record with status
            rec["status"] = "success"
            # push updated record to firebase again (overwrite with status)
            if UPLOAD_METHOD.lower() == "post":
                http_post_record(rec)
            else:
                http_put_record(key, rec)

            print(f"[{ts}] Worker-{worker_id} ✓ uploaded key={key} HTTP={code}")
            try:
                body = json.loads(text)
                print(f"    -> response: {json.dumps(body)}")
            except Exception:
                print(f"    -> response: {text}")
        else:
            # failure
            attempts += 1
            delay = BASE_RETRY_DELAY * (2 ** (attempts - 1))
            delay = min(delay, 60)
            print(f"[{ts}] Worker-{worker_id} ✗ upload failed key={key} attempt={attempts} code={code} error={text}")
            if attempts >= MAX_RETRIES:
                print(f"[{ts}] Worker-{worker_id} → max attempts reached; persisting to {UNSENT_FILE}")
                persist_unsent(key, rec)
            else:
                item["attempts"] = attempts
                time.sleep(delay)
                send_queue.put(item)

        send_queue.task_done()

# ---------------- Parsing / TShark ----------------
def parse_tshark_line(line):
    # line example: "1|169###|192.168.1.2|8.8.8.8|1234|53||DNS|90|Standard query A example.com"
    # fields order defined in TSHARK_CMD
    parts = [p[1:-1] if (len(p) >= 2 and p[0] == '"' and p[-1] == '"') else p for p in line.split("|")]
    # ensure 11 fields
    while len(parts) < 11:
        parts.append("")
    (frame_no, epoch, ip_src, ip_dst, tcp_sport, tcp_dport, udp_sport, udp_dport, proto, frame_len, info) = parts[:11]

    # timestamp
    if epoch:
        try:
            t = datetime.fromtimestamp(float(epoch))
            ts = t.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        except Exception:
            ts = now_ts()
    else:
        ts = now_ts()

    src_port = tcp_sport or udp_sport or None
    dst_port = tcp_dport or udp_dport or None

    rec = {
        "packet_no": frame_no or None,
        "timestamp": ts,
        "src": ip_src or None,
        "dst": ip_dst or None,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": proto or None,
        "length": frame_len or None,
        "info": info or None,
        "raw_line": line
    }
    return rec

def tshark_reader():
    # start tshark subprocess
    try:
        proc = subprocess.Popen(TSHARK_CMD, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, bufsize=1)
    except FileNotFoundError:
        print(f"[{now_ts()}] ERROR: tshark not found. Install tshark and ensure it's in PATH.", file=sys.stderr)
        stop_event.set()
        return
    except Exception as e:
        print(f"[{now_ts()}] ERROR starting tshark: {e}", file=sys.stderr)
        stop_event.set()
        return

    print(f"[{now_ts()}] tshark started; capturing... (Ctrl+C to stop).")
    # read lines
    try:
        while not stop_event.is_set():
            line = proc.stdout.readline()
            if line == "" and proc.poll() is not None:
                break
            if not line:
                continue
            line = line.rstrip("\n")
            rec = parse_tshark_line(line)
            # prepare key+payload
            unique_key = uuid.uuid4().hex
            payload = {
                "src": rec["src"],
                "dst": rec["dst"],
                "src_port": rec["src_port"],
                "dst_port": rec["dst_port"],
                "protocol": rec["protocol"],
                "length": rec["length"],
                "info": rec["info"],
                "packet_no": rec["packet_no"],
                "timestamp": rec["timestamp"],
                "raw_line": rec["raw_line"]
            }
            # print local
            print(f"[{rec['timestamp']}] #{rec['packet_no']} {rec['src'] or '-'}:{rec['src_port'] or '-'} -> {rec['dst'] or '-'}:{rec['dst_port'] or '-'} [{rec['protocol'] or '-'}] length={rec['length'] or '-'}")
            # enqueue
            send_queue.put({"key": unique_key, "record": payload, "attempts": 0})
            # flush to keep terminal live
            sys.stdout.flush()
    except KeyboardInterrupt:
        stop_event.set()
    finally:
        try:
            proc.terminate()
            proc.wait(timeout=2)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
        stop_event.set()

# ---------------- Test upload helper ----------------
def test_upload_once():
    """Send a single test record and show the HTTP response (helpful to confirm DB write permissions)."""
    test_key = uuid.uuid4().hex
    rec = {
        "test": True,
        "timestamp": now_ts(),
        "note": "test-upload from tshark_live_firebase_debug.py"
    }
    if UPLOAD_METHOD.lower() == "post":
        code, text = http_post_record(rec)
        print(f"POST -> HTTP {code}\n{text}")
    else:
        code, text = http_put_record(test_key, rec)
        print(f"PUT -> key={test_key} HTTP {code}\n{text}")

# ---------------- Signals ----------------
def graceful_shutdown(signum, frame):
    print(f"\n[{now_ts()}] Received signal {signum}. Shutting down gracefully...")
    stop_event.set()

# ---------------- Main ----------------
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--test-upload", action="store_true", help="Send a single test record to Firebase then exit")
    args = parser.parse_args()

    # quick sanity checks
    if FIREBASE_BASE.startswith("https://") is False:
        print(f"[{now_ts()}] WARNING: FIREBASE_BASE looks odd: {FIREBASE_BASE}", file=sys.stderr)

    if args.test_upload:
        print(f"[{now_ts()}] Running test-upload (method={UPLOAD_METHOD}) ...")
        test_upload_once()
        return

    loaded = load_persisted_unsent()
    if loaded:
        print(f"[{now_ts()}] Loaded {loaded} persisted unsent items into queue.")

    # start sender threads
    workers = []
    for i in range(SENDER_THREADS):
        t = threading.Thread(target=sender_worker, args=(i+1,), daemon=True)
        t.start()
        workers.append(t)

    # signals
    signal.signal(signal.SIGINT, graceful_shutdown)
    signal.signal(signal.SIGTERM, graceful_shutdown)

    # start tshark reader (blocks until stop_event)
    tshark_reader()

    # wait for queue to finish
    print(f"[{now_ts()}] Waiting for queue to drain (workers will finish queued items)...")
    try:
        send_queue.join()
    except KeyboardInterrupt:
        pass

    # persist remaining
    remaining = 0
    while not send_queue.empty():
        try:
            item = send_queue.get_nowait()
            persist_unsent(item.get("key") or uuid.uuid4().hex, item.get("record"))
            send_queue.task_done()
            remaining += 1
        except queue.Empty:
            break

    if remaining:
        print(f"[{now_ts()}] Persisted {remaining} remaining records to {UNSENT_FILE}.")

    print(f"[{now_ts()}] Exiting.")

if __name__ == "__main__":
    main()
