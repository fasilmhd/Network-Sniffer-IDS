"""
Full diagnostic test: ML engine + IDS rule-based detections.
Run with:  python test_full_check.py
"""
import sys, os, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# ─── Simple text-safe output ─────────────────────────────────────────────────
PASS = "[PASS]"
FAIL = "[FAIL]"

def section(title: str):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")

results = []

# ─── 1. ML Engine ────────────────────────────────────────────────────────────
section("1. ML IDS ENGINE")
try:
    from utils.ml_ids_engine import MLIDSEngine
    import warnings
    warnings.filterwarnings("ignore")   # suppress sklearn feature-name warning

    ready = MLIDSEngine.is_ready()
    print(f"  Engine loaded : {PASS if ready else FAIL}")
    results.append(("ML Engine loads", ready))

    # Benign traffic
    benign = {
        'Flow Duration': 5000, 'Total Fwd Packets': 5,
        'Total Backward Packets': 4, 'Fwd Packet Length Max': 64,
        'Bwd Packet Length Max': 128, 'Flow Bytes/s': 500,
        'Flow Packets/s': 10, 'SYN Flag Count': 1, 'ACK Flag Count': 5
    }
    label, conf = MLIDSEngine.predict(benign)
    print(f"  Benign sample : label={label!r}  conf={conf:.1%}")
    results.append(("ML predict returns label", label is not None))

    # Attack traffic (SYN flood-like)
    attack = {
        'Flow Duration': 10, 'Total Fwd Packets': 8000,
        'Fwd Packet Length Max': 60, 'Flow Bytes/s': 9_000_000,
        'Flow Packets/s': 800_000, 'SYN Flag Count': 7999, 'ACK Flag Count': 0
    }
    label_a, conf_a = MLIDSEngine.predict(attack)
    print(f"  Attack sample : label={label_a!r}  conf={conf_a:.1%}")
    results.append(("Attack prediction completes", label_a is not None))

    # Anomaly
    is_anom, score = MLIDSEngine.predict_anomaly(attack)
    print(f"  Anomaly check : is_anomaly={is_anom}  score={score:.4f}  {PASS if isinstance(is_anom, bool) else FAIL}")
    results.append(("Anomaly detection returns bool", isinstance(is_anom, bool)))

except Exception as e:
    import traceback
    print(f"  {FAIL} ML engine error: {e}")
    traceback.print_exc()
    results.append(("ML Engine", False))

# ─── 2. FlowFeatureExtractor ─────────────────────────────────────────────────
section("2. FLOW FEATURE EXTRACTOR")
try:
    from utils.flow_feature_extractor import FlowFeatureExtractor
    print(f"  Import : {PASS}")
    results.append(("FlowFeatureExtractor imports", True))
except Exception as e:
    print(f"  Import : {FAIL}  ({e})")
    results.append(("FlowFeatureExtractor imports", False))

# ─── 3. IDS Rules ────────────────────────────────────────────────────────────
section("3. RULE-BASED IDS (PacketAnalyzer.analyze_ids)")
try:
    from utils.packet_analyzer import PacketAnalyzer

    src = "10.0.0.1"
    dst = "10.0.0.2"

    def run_ids_scenario(name, packets):
        """Send a list of info-dicts and return all alerts accumulated."""
        PacketAnalyzer.reset_state()
        all_alerts = []
        for info in packets:
            all_alerts.extend(PacketAnalyzer.analyze_ids(info))
        found = [a for a in all_alerts if a.get("type") == name]
        ok = len(found) > 0
        print(f"  {PASS if ok else FAIL}  {name} : {'DETECTED' if ok else 'NOT DETECTED'}")
        if found:
            print(f"         msg: {found[0]['message'][:80]}")
        results.append((f"{name} detection", ok))

    print()

    # Port Scan: N+5 distinct ports
    run_ids_scenario("Port Scan", [
        {"src": src, "dst": dst, "dst_port": p,
         "protocol": "TCP", "flags_set": {"S"}, "src_mac": "aa:bb:cc:dd:ee:ff"}
        for p in range(1, PacketAnalyzer.PORT_SCAN_THRESHOLD + 5)
    ])

    # SYN Flood: N+5 pure-SYN packets
    run_ids_scenario("DoS / SYN Flood", [
        {"src": src, "dst": dst, "dst_port": 80,
         "protocol": "TCP", "flags_set": {"S"}, "src_mac": "aa:bb:cc:dd:ee:ff"}
        for _ in range(PacketAnalyzer.SYN_FLOOD_THRESHOLD + 5)
    ])

    # ICMP Flood
    run_ids_scenario("DoS / SYN Flood", [
        {"src": src, "dst": dst, "dst_port": 0,
         "protocol": "ICMP", "flags_set": set(), "src_mac": "aa:bb:cc:dd:ee:ff"}
        for _ in range(PacketAnalyzer.ICMP_FLOOD_THRESHOLD + 5)
    ])

    # ARP Spoofing: same IP, different MACs
    PacketAnalyzer.reset_state()
    all_a = []
    all_a.extend(PacketAnalyzer.analyze_ids({
        "src": "192.168.1.1", "dst": dst, "dst_port": 0,
        "protocol": "ARP", "flags_set": set(), "src_mac": "aa:bb:cc:dd:ee:ff"
    }))
    all_a.extend(PacketAnalyzer.analyze_ids({
        "src": "192.168.1.1", "dst": dst, "dst_port": 0,
        "protocol": "ARP", "flags_set": set(), "src_mac": "11:22:33:44:55:66"
    }))
    ok = any(a.get("type") == "ARP Spoofing" for a in all_a)
    print(f"  {PASS if ok else FAIL}  ARP Spoofing : {'DETECTED' if ok else 'NOT DETECTED'}")
    results.append(("ARP Spoofing detection", ok))

    # DNS Tunneling
    run_ids_scenario("DNS Tunneling", [
        {"src": src, "dst": dst, "dst_port": 53,
         "protocol": "DNS", "flags_set": set(), "src_mac": "aa:bb:cc:dd:ee:ff"}
        for _ in range(PacketAnalyzer.DNS_TUNNEL_THRESHOLD + 5)
    ])

except Exception as e:
    import traceback
    print(f"  {FAIL} IDS error: {e}")
    traceback.print_exc()
    results.append(("IDS Rules", False))

# ─── Summary ─────────────────────────────────────────────────────────────────
section("SUMMARY")
passed = sum(1 for _, ok in results if ok)
total  = len(results)
for name, ok in results:
    print(f"  {PASS if ok else FAIL}  {name}")
print(f"\n  Result: {passed}/{total} checks passed\n")
