#!/usr/bin/env python3

import os
from sys import flags
import time
import joblib
import psutil
import pandas as pd
import socket
import threading
import time
import csv


RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"

from scapy.all import sniff
from scapy.layers.inet import IP
from scapy.layers.inet import TCP

DEBUG_RF = False

DEBUG_FLOW = False

# ============================================================
# CONFIG
# ============================================================

MODEL_PATH = "rf_opi_file_split.joblib"

INTERFACE = ["eth0", "lan0"]

EARLY_PACKET_THRESHOLD = 100

# ============================================================
# FIREWALL MODE
# ============================================================

FIREWALL_CHAIN = "FORWARD"  # FORWARD untuk Gateway, INPUT untuk Server

# Untuk Gateway nanti:
# FIREWALL_CHAIN = "FORWARD" atau "INPUT" tergantung simulasi nanti

# ============================================================
# LOAD MODEL
# ============================================================

print()

print("Loading RF Model...")

model = joblib.load(MODEL_PATH)

print("Model Loaded")

dummy = pd.DataFrame([{

    "Flow Duration":1,

    "Flow Bytes/s":1000,

    "Flow Packets/s":100,

    "Total Fwd Packets":100,

    "Total Length of Fwd Packets":1000,

    "Fwd Packets/s":100,

    "SYN Flag Count":100,

    "ACK Flag Count":0,

    "Init_Win_bytes_forward":512,

    "act_data_pkt_fwd":100

}])

start = time.perf_counter()

for _ in range(100):

    model.predict(dummy)

elapsed = (

    time.perf_counter()

    -

    start

) * 1000

print()

print(
    f"100 inference = {elapsed:.2f} ms"
)

print(
    f"1 inference ≈ {elapsed/100:.2f} ms"
)

print()

# ============================================================
# STORAGE
# ============================================================

flows = {}

total_attack = 0

total_normal = 0

packet_counter = 0

last_refresh = time.time()

latest_result = None

mitigation_active = False

mitigation_end_time = 0

current_rule = None

mitigation_latency_ms = 0

def get_next_log_file(prefix):

    index = 1

    while os.path.exists(
        f"{prefix}_{index}.csv"
    ):

        index += 1

    return f"{prefix}_{index}.csv"


IPS_LOG_FILE = get_next_log_file(
    "ips_log"
)

RESOURCE_LOG_FILE = get_next_log_file(
    "resource_log"
)

IDPS_LOG_FILE = get_next_log_file(
    "idps_log"
)

def log_ips_event(

    action,
    port,
    latency

):

    file_exists = os.path.isfile(
        IPS_LOG_FILE
    )

    with open(
        IPS_LOG_FILE,
        "a",
        newline=""
    ) as f:

        writer = csv.writer(f)

        if not file_exists:

            writer.writerow([

                "timestamp",

                "action",

                "port",

                "mitigation_latency_ms"

            ])

        writer.writerow([

            time.strftime(
                "%Y-%m-%d %H:%M:%S"
            ),

            action,

            port,

            f"{latency:.2f}"

        ])

def log_resource():

    cpu = psutil.cpu_percent()

    ram = psutil.virtual_memory().percent

    file_exists = os.path.isfile(
        RESOURCE_LOG_FILE
    )

    with open(
        RESOURCE_LOG_FILE,
        "a",
        newline=""
    ) as f:

        writer = csv.writer(f)

        if not file_exists:

            writer.writerow([

                "timestamp",

                "status",

                "cpu_usage",

                "ram_usage",

                "mitigation_active",

                "mitigation_latency_ms"

            ])

        writer.writerow([

            time.strftime(
                "%Y-%m-%d %H:%M:%S"
            ),

            latest_result["status"]
            if latest_result
            else "WAITING",

            round(cpu, 2),

            round(ram, 2),

            mitigation_active,

            round(
                mitigation_latency_ms,
                2
            )

        ])

def log_idps():

    if not latest_result:

        return

    cpu = psutil.cpu_percent()

    ram = psutil.virtual_memory().percent

    remaining = 0

    if mitigation_active:

        remaining = max(

            0,

            int(
                mitigation_end_time
                -
                time.time()
            )

        )

    file_exists = os.path.isfile(
        IDPS_LOG_FILE
    )

    with open(

        IDPS_LOG_FILE,

        "a",

        newline=""

    ) as f:

        writer = csv.writer(f)

        if not file_exists:

            writer.writerow([

                "timestamp",

                "status",

                "dst_port",

                "confidence",

                "detection_latency_ms",

                "mitigation_active",

                "mitigation_latency_ms",

                "mitigation_remaining",

                "cpu_usage",

                "ram_usage"

            ])

        writer.writerow([

            time.strftime(
                "%Y-%m-%d %H:%M:%S"
            ),

            latest_result["status"],

            latest_result["dst_port"],

            round(
                latest_result["confidence"],
                2
            ),

            round(
                latest_result[
                    "detection_latency"
                ],
                2
            ),

            mitigation_active,

            round(
                mitigation_latency_ms,
                2
            ),

            remaining,

            round(cpu,2),

            round(ram,2)

        ])

def apply_mitigation(dst_ip, dst_port):

    global mitigation_active
    global mitigation_end_time
    global current_rule
    global mitigation_latency_ms

    if mitigation_active:
        return

    start = time.perf_counter()

    os.system(
        f"iptables -I {FIREWALL_CHAIN} "
        f"-p tcp "
        f"-d {dst_ip} "
        f"--dport {dst_port} "
        f"-m limit "
        f"--limit 50/second "
        f"--limit-burst 100 "
        f"-j ACCEPT"
    )

    os.system(
        f"iptables -A {FIREWALL_CHAIN} "
        f"-p tcp "
        f"-d {dst_ip} "
        f"--dport {dst_port} "
        f"-j DROP"
    )

    mitigation_latency_ms = (
        time.perf_counter()
        -
        start
    ) * 1000

    mitigation_active = True

    mitigation_end_time = (
        time.time()
        +
        15
    )

    current_rule = (dst_ip, dst_port)

    log_ips_event(
        "ACTIVATE",
        dst_port,
        mitigation_latency_ms
    )

    print(
        f"[IPS] Rate limit active on {dst_ip}:{dst_port}"
    )

def remove_mitigation(rule):

    global mitigation_active
    global current_rule

    dst_ip, dst_port = rule

    os.system(
        f"iptables -D {FIREWALL_CHAIN} "
        f"-p tcp "
        f"-d {dst_ip} "
        f"--dport {dst_port} "
        f"-j DROP"
    )

    os.system(
        f"iptables -D {FIREWALL_CHAIN} "
        f"-p tcp "
        f"-d {dst_ip} "
        f"--dport {dst_port} "
        f"-m limit "
        f"--limit 50/second "
        f"--limit-burst 100 "
        f"-j ACCEPT"
    )

    mitigation_active = False

    current_rule = None

    log_ips_event(
        "REMOVE",
        dst_port,
        0
    )

    print(
        f"[IPS] Rate limit removed from {dst_ip}:{dst_port}"
    )


def get_local_ip():

    try:

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        s.connect(("8.8.8.8", 80))

        ip = s.getsockname()[0]

        s.close()

        return ip

    except:

        return None


LOCAL_IP = get_local_ip()

print(f"LOCAL_IP = {LOCAL_IP}")

# ============================================================
# FLOW KEY
# ============================================================

def create_flow_key(pkt):

    ip = pkt[IP]
    tcp = pkt[TCP]

    window_id = int(time.time() // 5)

    return (
        ip.dst,
        tcp.dport,
        window_id
    )


# ============================================================
# INIT FLOW
# ============================================================

def init_flow(pkt):

    ip = pkt[IP]
    tcp = pkt[TCP]

    payload_size = len(tcp.payload)

    flags = int(tcp.flags)

    return {

        "start_time": time.time(),

        "last_seen": time.time(),

        "src_ip": ip.src,
        "dst_ip": ip.dst,

        "src_port": tcp.sport,
        "dst_port": tcp.dport,

        "packet_count": 1,

        "total_bytes": len(pkt),

        "syn_count":
            1 if flags == 0x02 else 0,

            "ack_count":
                1 if (flags & 0x10) else 0,

        "init_window":
            tcp.window,

        "act_data_pkt_fwd":
            1 if payload_size > 0 else 0,

        "predicted": False,

        "prediction": None


    }


# ============================================================
# UPDATE FLOW
# ============================================================

def update_flow(flow,pkt):

    tcp = pkt[TCP]

    payload_size = len(tcp.payload)

    flow["last_seen"] = time.time()

    flow["packet_count"] += 1

    if (
        flow["predicted"] == False
        and
        flow["packet_count"] >= EARLY_PACKET_THRESHOLD
    ):
        early_predict(flow)

    flow["total_bytes"] += len(pkt)

    flags = int(tcp.flags)

    # SYN ONLY
    if flags == 0x02:

        flow["syn_count"] += 1

    # ACK ONLY atau SYN-ACK
    if flags & 0x10:

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

    feature = {

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
            flow["act_data_pkt_fwd"]

    }

    return feature


# ============================================================
# DASHBOARD
# ============================================================

def draw_dashboard():

    os.system("clear")

    cpu = psutil.cpu_percent()

    ram = psutil.virtual_memory().percent

    print("=" * 70)

    print("            LAYER 4 SYN FLOOD IDPS")

    print("=" * 70)

    print()

    global latest_result

    status_global = "WAITING"

    status_color = YELLOW

    if latest_result:

        status_global = latest_result["status"]

        if status_global == "ATTACK":

            status_color = RED

        elif status_global == "NORMAL":

            status_color = GREEN

    print(
        f"STATUS         : "
        f"{status_color}"
        f"{status_global}"
        f"{RESET}"
    )

    print()

    print(f"CPU USAGE      : {cpu:.1f}%")

    print(f"RAM USAGE      : {ram:.1f}%")


    print()

    print(f"ACTIVE FLOWS   : {len(flows)}")

    print(f"TOTAL PACKETS  : {packet_counter}")

    print()

    print(f"NORMAL FLOWS   : {total_normal}")

    print(f"ATTACK FLOWS   : {total_attack}")

    print()

    if mitigation_active:

        remaining = max(
            0,
            int(
                mitigation_end_time
                -
                time.time()
            )
        )

        print(
            f"IPS STATUS     : "
            f"{RED}ACTIVE{RESET}"
        )

        print(
            f"BLOCK PORT     : "
            f"{current_rule}"
        )

        print(
            f"TIME LEFT      : "
            f"{remaining} sec"
        )

        print(
            f"MITIGATION LAT : "
            f"{mitigation_latency_ms:.2f} ms"
        )


    else:

        print(
            f"IPS STATUS     : "
            f"{GREEN}IDLE{RESET}"
        )

        print(
            f"BLOCK PORT     : -"
        )

        print(
            f"TIME LEFT      : -"
        )

        print(
            f"MITIGATION LAT : -"
        )

    print()

    print(
        f"LAST UPDATE    : "
        f"{time.strftime('%d-%m-%Y %H:%M:%S')}"
    )

    print()

    print("=" * 70)

    print("LATEST FLOW ANALYSIS")

    print("=" * 70)

    print()

    if latest_result:

        print(
            f"DST IP               : "
            f"{latest_result['dst_ip']}"
        )

        print(
            f"DST PORT             : "
            f"{latest_result['dst_port']}"
        )

        print()

        print(
            f"PACKETS              : "
            f"{latest_result['pkt']}"
        )

        print(
            f"SYN FLAGS            : "
            f"{latest_result['syn']}"
        )

        print(
            f"ACK FLAGS            : "
            f"{latest_result['ack']}"
        )

        print()

        print(
            f"FLOW PPS             : "
            f"{latest_result['pps']:.1f}"
        )

        print(
            f"FLOW DURATION        : "
            f"{latest_result['duration']:.0f} ms"
        )

        print()

        print(
            f"CONFIDENCE           : "
            f"{latest_result['confidence']:.2f}%"
        )

        print(
            f"DETECTION LATENCY    : "
            f"{latest_result['detection_latency']:.2f} ms"
        )

        print()

        result_color = (
            RED
            if latest_result["status"] == "ATTACK"
            else GREEN
        )

        print(
            f"RESULT                : "
            f"{result_color}"
            f"{latest_result['status']}"
            f"{RESET}"
        )

    else:

        print("Waiting for first flow...")

    print()

    print("=" * 70)


def early_predict(flow):

    global total_attack
    global total_normal
    global latest_result

    feature = build_feature(flow)

    X = pd.DataFrame([feature])

    detection_start = time.perf_counter()

    prediction = model.predict(X)[0]

    probability = model.predict_proba(X)[0]

    latency_ms = (
        time.perf_counter()
        -
        detection_start
    ) * 1000

    confidence = max(probability) * 100

    status = "ATTACK" if prediction == 1 else "NORMAL"

    latest_result = {

        "time": time.strftime("%H:%M:%S"),

        "dst_ip": flow["dst_ip"],

        "dst_port": flow["dst_port"],

        "pkt": flow["packet_count"],

        "syn": flow["syn_count"],

        "ack": flow["ack_count"],

        "pps": feature["Flow Packets/s"],

        "duration":
            (flow["last_seen"]-flow["start_time"])*1000,

        "confidence": confidence,

        "detection_latency": latency_ms,

        "status": status

    }

    flow["predicted"] = True

    flow["prediction"] = prediction

    if prediction == 1:

        apply_mitigation(
            flow["dst_ip"],
            flow["dst_port"]
        )

        total_attack += 1

    else:

        total_normal += 1

# ============================================================
# PROCESS FLOWS (BUILDER C)
# ============================================================

def process_expired_flows():

    global total_attack
    global total_normal

    current_window = int(time.time() // 5)

    remove_keys = []

    for key, flow in list(flows.items()):

        flow_window = key[2]

        # masih window aktif
        if flow_window == current_window:
            continue

        if flow["predicted"]:

            remove_keys.append(key)

            continue

        if flow["packet_count"] < 2:

            remove_keys.append(key)

            continue

        if DEBUG_FLOW:

            print()

        # hanya proses flow menuju service

        feature = build_feature(flow)

        X = pd.DataFrame([feature])

        detection_start = time.perf_counter()

        prediction = model.predict(X)[0]

        probability = model.predict_proba(X)[0]

        latency_ms = (
            time.perf_counter()
            -
            detection_start
        ) * 1000

        confidence = max(probability) * 100

        status_text = "ATTACK" if prediction == 1 else "NORMAL"

        flow_age_ms = (

            flow["last_seen"]

            -

            flow["start_time"]

        ) * 1000

        global latest_result

        latest_result = {

            "time":
                time.strftime("%H:%M:%S"),

            "dst_ip":
                flow["dst_ip"],

            "dst_port":
                flow["dst_port"],

            "pkt":
                flow["packet_count"],

            "syn":
                flow["syn_count"],

            "ack":
                flow["ack_count"],

            "pps":
                feature["Flow Packets/s"],

            "duration":
                flow_age_ms,

            "confidence":
                confidence,

            "detection_latency":
                latency_ms,

            "status":
                status_text
        }

        if prediction == 1:
            apply_mitigation(
                flow["dst_ip"],
                flow["dst_port"]
            )
            total_attack += 1

        else:

            total_normal += 1

        remove_keys.append(key)

    for key in remove_keys:

        if key in flows:

            del flows[key]

def mitigation_manager():

    while True:

        if mitigation_active:

            if (
                time.time()
                >=
                mitigation_end_time
            ):

                remove_mitigation(
                    current_rule
                )

        time.sleep(1)


def flow_cleaner():

    while True:

        process_expired_flows()

        time.sleep(1)

# ============================================================
# PACKET HANDLER
# ============================================================

def packet_handler(pkt):

    global packet_counter

    packet_counter += 1

    if IP not in pkt:
        return

    if TCP not in pkt:
        return


    if LOCAL_IP is not None:

        if pkt[IP].src == LOCAL_IP:
            return

    # DEBUG

    key = create_flow_key(pkt)

    if key not in flows:
        flows[key] = init_flow(pkt)
    else:
        update_flow(flows[key], pkt)

# ============================================================
# DASHBOARD LOOP
# ============================================================

def dashboard_loop():

    while True:

        draw_dashboard()

        time.sleep(2)

# ============================================================
# START
# ============================================================
def idps_logger():

    while True:

        log_idps()

        time.sleep(2)

def resource_logger():

    while True:

        log_resource()

        time.sleep(2)

threading.Thread(

    target=dashboard_loop,

    daemon=True

).start()

threading.Thread(
    target=resource_logger,
    daemon=True
).start()

threading.Thread(
    target=idps_logger,
    daemon=True
).start()

threading.Thread(

    target=flow_cleaner,

    daemon=True

).start()

threading.Thread(
    target=mitigation_manager,
    daemon=True
).start()

sniff(

    iface=INTERFACE,

    prn=packet_handler,

    store=False

)