#!/usr/bin/env python3

import os
import time
import signal
import threading
import pandas as pd
import psutil

from scapy.all import sniff
from scapy.layers.inet import IP
from scapy.layers.inet import TCP

# ============================================================
# CONFIG
# ============================================================

INTERFACE = "eth0"

WINDOW_SIZE = 5

MIN_PACKET_PER_FLOW = 3

REFRESH_INTERVAL = 2

# ============================================================
# INPUT USER
# ============================================================

print()
print("=" * 60)
print("ORANGE PI DATASET RECORDER")
print("=" * 60)
print()

print("1. NORMAL")
print("2. ATTACK")
print()

choice = input("Pilihan : ").strip()

if choice == "1":
    LABEL = "NORMAL"
elif choice == "2":
    LABEL = "ATTACK"
else:
    print("Pilihan tidak valid")
    exit()

print()

filename = input("Nama File (tanpa .csv) : ").strip()

if filename == "":
    print("Nama file tidak boleh kosong")
    exit()

OUTPUT_FILE = filename + ".csv"

print()

duration_minute = float(
    input("Durasi Rekaman (menit) : ")
)

RECORD_SECONDS = int(duration_minute * 60)

# ============================================================
# STORAGE
# ============================================================

flows = {}

rows = []

running = True

start_time = time.time()

# ============================================================
# FLOW KEY
# ============================================================

def create_flow_key(pkt):

    ip = pkt[IP]
    tcp = pkt[TCP]

    window_id = int(time.time() // WINDOW_SIZE)

    return (
        ip.dst,
        tcp.dport,
        window_id
    )

# ============================================================
# INIT FLOW
# ============================================================

def init_flow(pkt):

    tcp = pkt[TCP]

    payload_size = len(tcp.payload)

    return {

        "start_time": time.time(),

        "last_seen": time.time(),

        "dst_ip": pkt[IP].dst,

        "dst_port": tcp.dport,

        "packet_count": 1,

        "total_bytes": len(pkt),

        "syn_count":
            1 if tcp.flags & 0x02 else 0,

        "ack_count":
            1 if tcp.flags & 0x10 else 0,

        "init_window":
            tcp.window,

        "act_data_pkt_fwd":
            1 if payload_size > 0 else 0

    }

# ============================================================
# UPDATE FLOW
# ============================================================

def update_flow(flow, pkt):

    tcp = pkt[TCP]

    payload_size = len(tcp.payload)

    flow["last_seen"] = time.time()

    flow["packet_count"] += 1

    flow["total_bytes"] += len(pkt)

    if tcp.flags & 0x02:
        flow["syn_count"] += 1

    if tcp.flags & 0x10:
        flow["ack_count"] += 1

    if payload_size > 0:
        flow["act_data_pkt_fwd"] += 1

# ============================================================
# BUILD FEATURE
# ============================================================

def build_feature(flow):

    duration = (
        flow["last_seen"]
        -
        flow["start_time"]
    )

    if duration <= 0:
        duration = 0.000001

    return {

        "Flow Duration":
            duration,

        "Flow Bytes/s":
            flow["total_bytes"] / duration,

        "Flow Packets/s":
            flow["packet_count"] / duration,

        "Total Fwd Packets":
            flow["packet_count"],

        "Total Length of Fwd Packets":
            flow["total_bytes"],

        "Fwd Packets/s":
            flow["packet_count"] / duration,

        "SYN Flag Count":
            flow["syn_count"],

        "ACK Flag Count":
            flow["ack_count"],

        "Init_Win_bytes_forward":
            flow["init_window"],

        "act_data_pkt_fwd":
            flow["act_data_pkt_fwd"],

        "Label":
            LABEL

    }

# ============================================================
# PROCESS FLOW
# ============================================================

def process_expired_flows():

    current_window = int(
        time.time() // WINDOW_SIZE
    )

    remove_keys = []

    for key, flow in flows.items():

        flow_window = key[2]

        if flow_window == current_window:
            continue

        if flow["packet_count"] < MIN_PACKET_PER_FLOW:

            remove_keys.append(key)

            continue

        rows.append(
            build_feature(flow)
        )

        remove_keys.append(key)

    for key in remove_keys:

        if key in flows:

            del flows[key]

# ============================================================
# PACKET HANDLER
# ============================================================

def packet_handler(pkt):

    if IP not in pkt:
        return

    if TCP not in pkt:
        return

    key = create_flow_key(pkt)

    if key not in flows:

        flows[key] = init_flow(pkt)

    else:

        update_flow(
            flows[key],
            pkt
        )

    process_expired_flows()

# ============================================================
# DASHBOARD
# ============================================================

def dashboard_loop():

    while running:

        os.system("clear")

        elapsed = int(
            time.time() - start_time
        )

        remain = max(
            0,
            RECORD_SECONDS - elapsed
        )

        cpu = psutil.cpu_percent()

        ram = psutil.virtual_memory().percent

        print("=" * 60)
        print("ORANGE PI DATASET RECORDER")
        print("=" * 60)
        print()

        print(f"FILE         : {OUTPUT_FILE}")
        print(f"LABEL        : {LABEL}")

        print()

        print(f"ACTIVE FLOWS : {len(flows)}")
        print(f"ROWS SAVED   : {len(rows)}")

        print()

        print(f"CPU          : {cpu:.1f}%")
        print(f"RAM          : {ram:.1f}%")

        print()

        minute = remain // 60
        second = remain % 60

        print(
            f"TIME LEFT    : "
            f"{minute:02d}:{second:02d}"
        )

        print()

        time.sleep(
            REFRESH_INTERVAL
        )

# ============================================================
# SAVE CSV
# ============================================================

def save_dataset():

    process_expired_flows()

    if len(rows) == 0:

        print()
        print("Tidak ada data tersimpan")
        return

    df = pd.DataFrame(rows)

    df.to_csv(
        OUTPUT_FILE,
        index=False
    )

    print()
    print("=" * 60)
    print("DATASET SAVED")
    print("=" * 60)

    print()

    print("File :", OUTPUT_FILE)

    print("Rows :", len(df))

    print()

# ============================================================
# CTRL+C HANDLER
# ============================================================

def signal_handler(sig, frame):

    global running

    running = False

    print()
    print()
    print("Stopping recorder...")

    save_dataset()

    exit()

signal.signal(
    signal.SIGINT,
    signal_handler
)

# ============================================================
# START DASHBOARD
# ============================================================

threading.Thread(
    target=dashboard_loop,
    daemon=True
).start()

# ============================================================
# START CAPTURE
# ============================================================

print()
print(f"Recording on {INTERFACE} ...")
print()

sniffer = threading.Thread(

    target=lambda: sniff(
        iface=INTERFACE,
        prn=packet_handler,
        store=False
    ),

    daemon=True

)

sniffer.start()

# ============================================================
# TIMER
# ============================================================

while True:

    elapsed = time.time() - start_time

    if elapsed >= RECORD_SECONDS:

        running = False

        print()
        print()
        print("Recording Finished")

        save_dataset()

        break

    time.sleep(1)