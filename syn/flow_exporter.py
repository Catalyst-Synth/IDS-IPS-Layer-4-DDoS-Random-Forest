#!/usr/bin/env python3

import time
import pandas as pd

from scapy.all import sniff
from scapy.layers.inet import IP
from scapy.layers.inet import TCP


# ============================================================
# CONFIG
# ============================================================

FLOW_TIMEOUT = 10

OUTPUT_FILE = "live_capture.csv"

# ============================================================
# STORAGE
# ============================================================

flows = {}

# ============================================================
# FEATURE NAMES
# ============================================================

FEATURE_COLUMNS = [

    "Flow Bytes/s",
    "Flow Packets/s",
    "Total Length of Fwd Packets",
    "Packet Length Mean",
    "Packet Length Std",
    "Packet Length Variance",
    "Max Packet Length",
    "Avg Fwd Segment Size",
    "Init_Win_bytes_forward",
    "act_data_pkt_fwd"

]

# ============================================================
# FLOW KEY
# ============================================================

def create_flow_key(pkt):

    ip = pkt[IP]
    tcp = pkt[TCP]

    return (

        ip.src,
        ip.dst,
        tcp.sport,
        tcp.dport,
        "TCP"

    )

# ============================================================
# NEW FLOW
# ============================================================

def init_flow(pkt):

    ip = pkt[IP]
    tcp = pkt[TCP]

    packet_len = len(pkt)

    return {

        "start_time": time.time(),
        "last_seen": time.time(),

        "packet_lengths": [packet_len],

        "total_bytes": packet_len,

        "packet_count": 1,

        "syn_count": 1 if tcp.flags & 0x02 else 0,

        "ack_count": 1 if tcp.flags & 0x10 else 0,

        "init_win": tcp.window,

        "act_data_pkt_fwd": 1

    }

# ============================================================
# UPDATE FLOW
# ============================================================

def update_flow(flow, pkt):

    tcp = pkt[TCP]

    packet_len = len(pkt)

    flow["last_seen"] = time.time()

    flow["packet_lengths"].append(packet_len)

    flow["total_bytes"] += packet_len

    flow["packet_count"] += 1

    if tcp.flags & 0x02:
        flow["syn_count"] += 1

    if tcp.flags & 0x10:
        flow["ack_count"] += 1

    flow["act_data_pkt_fwd"] += 1

# ============================================================
# EXPORT FLOW
# ============================================================

def build_feature(flow):

    duration = (
        flow["last_seen"]
        - flow["start_time"]
    )

    # =====================================================
    # HINDARI PEMBAGIAN TERLALU KECIL
    # =====================================================

    if duration < 1:
        duration = 1

    lengths = pd.Series(
        flow["packet_lengths"],
        dtype="float64"
    )

    std_value = lengths.std()
    var_value = lengths.var()

    if pd.isna(std_value):
        std_value = 0

    if pd.isna(var_value):
        var_value = 0

    feature = {

        "Flow Bytes/s":
            flow["total_bytes"] / duration,

        "Flow Packets/s":
            flow["packet_count"] / duration,

        "Total Length of Fwd Packets":
            flow["total_bytes"],

        "Packet Length Mean":
            lengths.mean(),

        "Packet Length Std":
            std_value,

        "Packet Length Variance":
            var_value,

        "Max Packet Length":
            lengths.max(),

        "Avg Fwd Segment Size":
            lengths.mean(),

        "Init_Win_bytes_forward":
            flow["init_win"],

        "act_data_pkt_fwd":
            flow["act_data_pkt_fwd"],

        # =====================================================
        # DEBUG
        # =====================================================

        "DEBUG_PACKET_COUNT":
            flow["packet_count"],

        "DEBUG_SYN_COUNT":
            flow["syn_count"],

        "DEBUG_ACK_COUNT":
            flow["ack_count"],

        "DEBUG_DURATION":
            duration

    }

    return feature

# ============================================================
# SAVE CSV
# ============================================================

def export_expired_flows():

    now = time.time()

    rows = []

    remove_keys = []

    for key, flow in list(flows.items()):

        age = now - flow["last_seen"]

        if age >= FLOW_TIMEOUT:

            # ==========================================
            # BUANG FLOW TERLALU KECIL
            # ==========================================

            if flow["packet_count"] < 3:

                remove_keys.append(key)
                continue

            rows.append(
                build_feature(flow)
            )

            remove_keys.append(key)

    if rows:

        df = pd.DataFrame(rows)

        try:

            old_df = pd.read_csv(
                OUTPUT_FILE
            )

            df = pd.concat(
                [old_df, df],
                ignore_index=True
            )

        except Exception:

            pass

        df.to_csv(
            OUTPUT_FILE,
            index=False
        )

        print()
        print("=" * 60)
        print("FLOW EXPORTED")
        print("=" * 60)
        print("New Flow   :", len(rows))
        print("Total CSV  :", len(df))

    for key in remove_keys:

        if key in flows:

            del flows[key]

# ============================================================
# PACKET HANDLER
# ============================================================

packet_counter = 0

def packet_handler(pkt):

    global packet_counter

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

    packet_counter += 1

    if packet_counter % 1000 == 0:

        print(

            f"\rPackets: {packet_counter:,} | Active Flows: {len(flows):,}",

            end=""

        )

    export_expired_flows()

# ============================================================
# START
# ============================================================

print()
print("="*60)
print("FLOW EXPORTER STARTED")
print("="*60)

print()

print("Timeout :", FLOW_TIMEOUT)
print("Output  :", OUTPUT_FILE)

print()

sniff(

    iface=["eth0","lan0"],

    prn=packet_handler,

    store=False

)