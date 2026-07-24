#!/usr/bin/env python3

import os       # izin python untuk mengakses sistem
from sys import flags  
import time     # untuk menghitung waktu
import joblib   # untuk memuat model machine learning yang sudah dilatih sebelumnya
import psutil   # untuk memantau penggunaan CPU dan RAM
import pandas as pd     # alat untuk manipulasi data, mengubah data menjadi format (dataframe) yang bisa dipahami model machine learning
import socket   # untuk mendapatkan IP lokal dari perangkat
import threading    # untuk menjalankan beberapa proses secara bersamaan
import csv      # untuk logging ke file CSV


RED = "\033[91m"    
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"   
RESET = "\033[0m"

from scapy.all import sniff         # untuk menangkap paket jaringan (Sniffing)
from scapy.layers.inet import IP    # untuk mebedah paket IP
from scapy.layers.inet import TCP   # untuk mebedah paket TCP

DEBUG_RF = False

DEBUG_FLOW = False

# ============================================================
# CONFIG
# ============================================================

MODEL_PATH = "rf_opi_file_split.joblib"     # path ke model machine learning yang sudah dilatih sebelumnya

INTERFACE = ["eth0", "lan0"]

EARLY_PACKET_THRESHOLD = 100

FLOW_IDLE_TIMEOUT = 2
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
# STORAGE dan logging pencatatan ke csv
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

def get_next_log_file(prefix): #otomatis membuat nama file log baru jika sudah ada file sebelumnya

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

def log_resource():     #log sumber CPU dan RAM ke file csv

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

def log_idps():     #log hasil deteksi IDPS ke file csv

    if not latest_result:

        return

    cpu = psutil.cpu_percent()

    ram = psutil.virtual_memory().percent

    remaining = 0

    if mitigation_active:

        remaining = max(    # menghitung waktu tersisa untuk mitigasi

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


# ============================================================
# Mitigasi Firewall (IPS)
# ============================================================

def apply_mitigation(dst_ip, dst_port):     #memasukkan aturan iptables untuk membatasi koneksi ke port tertentu

    global mitigation_active
    global mitigation_end_time
    global current_rule
    global mitigation_latency_ms

    if mitigation_active:
        return

    start = time.perf_counter()

    os.system(      # perintah langsung ke terminal untuk menambahkan aturan iptables yang membatasi koneksi ke port tertentu dengan limit 50 koneksi per detik dan burst 100 koneksi, serta meng-drop koneksi yang melebihi limit tersebut
        f"iptables -I {FIREWALL_CHAIN} "    
        f"-p tcp "
        f"-d {dst_ip} "
        f"--dport {dst_port} "
        f"-m limit "
        f"--limit 50/second "
        f"--limit-burst 100 "
        f"-j ACCEPT"
    )

    os.system(      # drop semua koneksi ke port tertentu yang melebihi limit yang ditentukan
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

def remove_mitigation(rule):       #lepas aturan iptables untuk port tertentu

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


def get_local_ip(): # untuk mengabaikan paket yang berasal dari IP lokal agar tidak memicu deteksi serangan sendiri, trafik hanya inggres (masuk saja)

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

def create_flow_key(pkt):   #membuat flow key/id unik berdasarkan dst_ip, dst_port, dan window_id

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

def init_flow(pkt):     #membuat catatan baru jika ada paket pertama dari sebuah aliran

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
            1 if flags == 0x02 else 0,      #0x02 = SYN flag

            "ack_count":
                1 if (flags & 0x10) else 0,     #0x10 = ACK flag

        "init_window":
            tcp.window,

        "act_data_pkt_fwd":
            1 if payload_size > 0 else 0,

        "predicted": False,     #menandakan apakah aliran ini sudah diprediksi atau belum

        "prediction": None      #menyimpan hasil prediksi


    }


# ============================================================
# UPDATE FLOW
# ============================================================

def update_flow(flow,pkt):  #memperbarui catatan aliran jika ada paket baru dari aliran yang sama

    tcp = pkt[TCP]

    payload_size = len(tcp.payload) 

    flow["last_seen"] = time.time()

    flow["packet_count"] += 1

    if (
        flow["predicted"] == False  # jika aliran belum diprediksi
        and
        flow["packet_count"] >= EARLY_PACKET_THRESHOLD  # jika paket mencapai early predict
    ):
        early_predict(flow)

    flow["total_bytes"] += len(pkt)     #menambahkan total byte dari paket baru ke total byte aliran

    flags = int(tcp.flags)      #mengambil nilai flag dari paket TCP

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

def build_feature(flow):    #menerjemah data flow mentah menjadi angka angka yang bisa dipahami model machine learning

    duration = (

        flow["last_seen"]
        -
        flow["start_time"]

    )

    if duration <= 0: #mencegah pembagian dengan nol

        duration = 0.000001  

    feature = {

        "Flow Duration":    #dalam detik
            duration,   

        "Flow Bytes/s":     #bytes per second
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
# DASHBOARD [T]
# ============================================================

def draw_dashboard():   #menampilkan informasi status IDPS, penggunaan CPU dan RAM, jumlah aliran aktif, jumlah paket, jumlah aliran normal dan serangan, serta hasil analisis aliran terakhir

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

    if mitigation_active:   #menampilkan status mitigasi jika sedang aktif, termasuk port yang dibatasi dan waktu tersisa untuk mitigasi

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


    else:   #menampilkan status mitigasi jika tidak aktif, termasuk port yang dibatasi dan waktu tersisa untuk mitigasi

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

    print("LATEST FLOW ANALYSIS")   #menampilkan hasil analisis aliran terakhir oleh ML

    print("=" * 70)

    print()

    if latest_result:       # menampilkan detail hasil analisis aliran terakhir jika ada, termasuk IP tujuan, port tujuan, jumlah paket, jumlah flag SYN dan ACK, kecepatan aliran, durasi aliran, tingkat kepercayaan prediksi, latensi deteksi, dan status hasil prediksi

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

    else:       # menampilkan pesan jika belum ada aliran yang dianalisis

        print("Waiting for first flow...")

    print()

    print("=" * 70)


def early_predict(flow):    # melakukan prediksi ditengah jalan jika jumlah paket dalam aliran sudah mencapai EARLY_PACKET_THRESHOLD, untuk mendeteksi serangan lebih cepat

    global total_attack
    global total_normal
    global latest_result

    feature = build_feature(flow)

    X = pd.DataFrame([feature])

    detection_start = time.perf_counter()

    prediction = model.predict(X)[0]    # melakukan prediksi menggunakan model machine learning

    probability = model.predict_proba(X)[0]     # menghitung probabilitas prediksi untuk setiap kelas (NORMAL dan ATTACK)

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

    flow["predicted"] = True        # menandakan bahwa aliran ini sudah diprediksi

    flow["prediction"] = prediction     # menyimpan hasil prediksi (0 untuk NORMAL, 1 untuk ATTACK)

    if (
        prediction == 1
        and
        flow["syn_count"] > flow["ack_count"]
        and
        flow["syn_count"] >= 20
    ):

        apply_mitigation(
            flow["dst_ip"],
            flow["dst_port"]
        )

        total_attack += 1

    else:

        total_normal += 1

# ============================================================
# PROCESS FLOWS (BUILDER C yang dipilih) [T]
# ============================================================

def process_expired_flows():    # memproses aliran yang sudah tidak aktif lagi, melakukan prediksi jika belum diprediksi, dan menghapus aliran yang sudah selesai diproses dari daftar aliran aktif

    global total_attack
    global total_normal

    current_window = int(time.time() // 5)  # window time 5 detik

    remove_keys = []    # menyimpan kunci aliran yang akan dihapus dari daftar aliran aktif

    for key, flow in list(flows.items()):

         # Flow sudah lama tidak menerima packet
        if (        # memeriksa apakah aliran sudah tidak aktif lebih dari FLOW_IDLE_TIMEOUT detik
            time.time()
            -
            flow["last_seen"]
        ) > FLOW_IDLE_TIMEOUT:  # jika aliran sudah tidak aktif lebih dari FLOW_IDLE_TIMEOUT detik, maka aliran dianggap sudah selesai dan akan dihapus dari daftar aliran aktif

            remove_keys.append(key) 

            continue    # jika aliran sudah diprediksi, maka tidak perlu diproses lagi

        flow_window = key[2]        # memeriksa apakah aliran masih berada dalam window waktu yang sama dengan saat ini

        # masih window aktif
        if flow_window == current_window:
            continue

        if (   
            flow["predicted"]
            and
            (
                time.time() - flow["last_seen"]
                > FLOW_IDLE_TIMEOUT
            )
        ):

            remove_keys.append(key)

            continue

        if flow["packet_count"] < 2:

            remove_keys.append(key)

            continue

        # ======================================================
        # jika bukan flow SYN, abaikan
        # ======================================================

        if (    # memeriksa apakah aliran ini bukan aliran SYN, jika bukan maka aliran ini akan diabaikan
            flow["syn_count"] == 0
            and
            flow["ack_count"] == 0
        ):

            remove_keys.append(key)     # jika gada flag SYN atau ACK, maka aliran ini dianggap bukan aliran SYN dan akan dihapus dari daftar aliran aktif

            continue

        if DEBUG_FLOW:

            print()

        # hanya proses flow menuju service

        feature = build_feature(flow)

        X = pd.DataFrame([feature]) # membuat dataframe dari fitur aliran untuk digunakan sebagai input ke model machine learning

        detection_start = time.perf_counter()

        prediction = model.predict(X)[0]    # melakukan prediksi menggunakan model machine learning untuk menentukan apakah aliran ini merupakan serangan atau bukan



        probability = model.predict_proba(X)[0] # menghitung probabilitas prediksi untuk setiap kelas (NORMAL dan ATTACK)

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

        global latest_result    # menyimpan hasil analisis aliran terakhir untuk ditampilkan di dashboard dan dicatat ke file log

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

def mitigation_manager():   # [T] mengelola status mitigasi, memeriksa apakah mitigasi masih aktif dan jika sudah melewati waktu yang ditentukan, maka mitigasi akan dihapus

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


def flow_cleaner():     # [T] membersihkan aliran yang sudah tidak aktif lagi, memproses aliran yang sudah selesai, dan menghapus aliran yang sudah selesai dari daftar aliran aktif

    while True:

        process_expired_flows()

        time.sleep(1)   

# ============================================================
# PACKET HANDLER [T]
# ============================================================

def packet_handler(pkt):    # menangani setiap paket yang diterima, membuat kunci aliran, memperbarui aliran yang sudah ada atau membuat aliran baru jika belum ada, dan menghitung jumlah paket yang diterima

    global packet_counter

    packet_counter += 1

    if IP not in pkt:   # memeriksa apakah paket memiliki layer IP, jika tidak maka paket akan diabaikan
        return

    if TCP not in pkt:  # memeriksa apakah paket memiliki layer TCP, jika tidak maka paket akan diabaikan
        return


    if LOCAL_IP is not None:    # memeriksa apakah paket berasal dari IP lokal, jika ya maka paket akan diabaikan untuk mencegah loopback

        if pkt[IP].src == LOCAL_IP: # 
            return

    # # DEBUG

    # key = create_flow_key(pkt)

    # if key not in flows:
    #     flows[key] = init_flow(pkt)
    # else:
    #     update_flow(flows[key], pkt)

# ============================================================
# DASHBOARD LOOP [T]
# ============================================================

def dashboard_loop():   # [T] menjalankan loop untuk menampilkan dashboard secara berkala setiap 2 detik

    while True:

        draw_dashboard()

        time.sleep(2)

# ============================================================
# START
# ============================================================
def idps_logger():  #  menjalankan loop untuk mencatat hasil analisis aliran ke file log secara berkala setiap 2 detik

    while True:

        log_idps()

        time.sleep(2)

def resource_logger():  #  menjalankan loop untuk mencatat penggunaan sumber daya (CPU dan RAM) ke file log secara berkala setiap 2 detik

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

sniff(      # menangkap paket dari interface yang ditentukan, memanggil fungsi packet_handler untuk setiap paket yang diterima, dan tidak menyimpan paket ke memori

    iface=INTERFACE,

    prn=packet_handler,

    store=False     # gadisimpen ke memori, karena kita hanya butuh informasi flownya saja

)