"""Interactive demonstration of Module 3 — ML & Rule Detection Engines.

This script demonstrates how the components built in Module 3 work together:
1. Normalizer: Converts raw LogEvents into numerical FeatureVectors.
2. ML Engine: Trains an Isolation Forest on normal baseline traffic, then scores events.
3. Rule Engine: Loads YAML detection rules and matches events with MITRE ATT&CK mapping.

Run it with:
    python scripts/demo_module3.py
"""

from __future__ import annotations

from pathlib import Path

from sentinel.core.schemas import EventType, LogEvent
from sentinel.detection.ml_engine import MLEngine
from sentinel.detection.rule_engine import RuleEngine
from sentinel.ingestion.simulator import generate_batch, generate_event
from sentinel.processing.normalizer import extract_features


def main() -> None:
    print("=" * 70)
    print("  AI THREAT SENTINEL — MODULE 3 DETECTION DEMO")
    print("=" * 70)

    # ------------------------------------------------------------------
    # 1. Initialize Engines
    # ------------------------------------------------------------------
    print("\n[1] Initializing Rule Engine & ML Engine...")
    rule_engine = RuleEngine()
    rules_dir = Path("src/sentinel/detection/rules")
    loaded_rules = rule_engine.load_rules(rules_dir)
    print(f"    -> Loaded {loaded_rules} YAML detection rules from {rules_dir}")
    for r in rule_engine.rules:
        print(f"       - [{r.rule_id}] {r.title} (Severity: {r.severity.value}, MITRE: {r.mitre_attack_id})")

    ml_engine = MLEngine()

    # ------------------------------------------------------------------
    # 2. Train ML Engine on Normal Baseline Traffic
    # ------------------------------------------------------------------
    print("\n[2] Training Isolation Forest on 300 normal baseline events...")
    training_events = generate_batch(count=300, attack_ratio=0.0)
    training_features = [extract_features(e) for e in training_events]
    ml_engine.train(training_features)
    print("    -> ML Engine trained successfully on baseline profile!")

    # Generate a burst of 60 port scan events from same IP to simulate heavy reconnaissance
    burst_ip = "192.168.4.99"
    ports_to_scan = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 5432, 8080, 8443, 9000, 27017] * 4
    burst_events = [
        LogEvent(
            src_ip=burst_ip,
            dst_port=p,
            event_type=EventType.PORT_SCAN,
            response_status=0,
            payload="SYN probe",
        )
        for p in ports_to_scan
    ]

    test_events: list[tuple[str, LogEvent, list[LogEvent] | None]] = [
        ("Normal Web Browse", generate_event(event_type=EventType.NORMAL), None),
        ("Single SSH Brute Force Attempt", generate_event(event_type=EventType.SSH_BRUTE_FORCE), None),
        ("SQL Injection Attempt", generate_event(event_type=EventType.SQLI_ATTEMPT), None),
        ("Port Scan Burst (50 requests, high frequency)", burst_events[-1], burst_events),
    ]

    print("\n[3] Evaluating Events through Dual-Engine Pipeline:\n")

    for label, event, context in test_events:
        print("-" * 70)
        print(f"EVENT: {label}")
        print(f"  IP: {event.src_ip} | Port: {event.dst_port} | Type: {event.event_type.value}")
        print(f"  Path: {event.request_path or 'N/A'} | Status: {event.response_status}")
        if event.payload:
            payload_preview = event.payload[:50] + ("..." if len(event.payload) > 50 else "")
            print(f"  Payload: {payload_preview}")

        # A. Feature Extraction
        features = extract_features(event, recent_events=context)
        print(f"  Features: req/min={features.requests_per_minute}, ports={features.port_diversity}, error_rate={features.error_rate:.2f}")

        # B. ML Detection
        ml_score = ml_engine.predict(features)
        is_anomaly = ml_engine.is_anomaly(ml_score)
        status_symbol = "ANOMALY DETECTED" if is_anomaly else "NORMAL"
        print(f"  [ML Engine]   Score: {ml_score:+.4f} -> [{status_symbol}]")

        # C. Rule Engine Detection
        rule_matches = rule_engine.evaluate(event)
        if rule_matches:
            for match in rule_matches:
                print(f"  [Rule Engine] MATCHED: [{match.rule.rule_id}] {match.rule.title}")
                print(f"                Severity: {match.rule.severity.value.upper()} | MITRE: {match.rule.mitre_attack_id}")
        else:
            print("  [Rule Engine] No deterministic rules triggered.")

    # ------------------------------------------------------------------
    # 4. Statistical ML Comparison (Batch Normal vs Batch Attacks)
    # ------------------------------------------------------------------
    print("\n" + "-" * 70)
    print("[4] Batch Statistical ML Evaluation (50 Benign vs 50 Attacks):")
    batch_normal = generate_batch(count=50, attack_ratio=0.0)
    batch_attacks = generate_batch(count=50, attack_ratio=1.0)

    scores_normal = ml_engine.predict_batch([extract_features(e) for e in batch_normal])
    scores_attacks = ml_engine.predict_batch([extract_features(e) for e in batch_attacks])

    avg_normal = sum(scores_normal) / len(scores_normal)
    avg_attacks = sum(scores_attacks) / len(scores_attacks)

    anomalies_normal = sum(1 for s in scores_normal if ml_engine.is_anomaly(s))
    anomalies_attacks = sum(1 for s in scores_attacks if ml_engine.is_anomaly(s))

    print(f"    Benign Traffic : Avg ML Score = {avg_normal:+.4f} | Anomalies Flagged = {anomalies_normal}/50")
    print(f"    Attack Traffic : Avg ML Score = {avg_attacks:+.4f} | Anomalies Flagged = {anomalies_attacks}/50")

    print("\n" + "=" * 70)
    print("  DEMO COMPLETE: Both ML & Rule engines operating as expected!")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()
