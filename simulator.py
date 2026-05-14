# simulator.py
import json
import time
import random
import uuid
from datetime import datetime, timezone

DEVICE_ID = f"WRB-{uuid.uuid4().hex[:6].upper()}"
FIRMWARE  = "2.4.1"
INTERVAL  = 2  # seconds between payloads

def generate_hrv():
    return {
        "rmssd_ms":    round(random.uniform(18, 82), 1),
        "sdnn_ms":     round(random.uniform(25, 95), 1),
        "lf_hf_ratio": round(random.uniform(0.5, 4.0), 2),
        "pnn50_pct":   round(random.uniform(5, 45), 1),
        "status":      random.choice(["normal", "elevated_stress", "recovery"]),
    }

def generate_rhr():
    avg = random.randint(50, 75)
    return {
        "bpm":       random.randint(44, 88),
        "avg_7d_bpm": avg,
        "trend":     random.choice(["improving", "stable", "degrading"]),
    }

def generate_sleep():
    # Distribute 100% across stages realistically
    awake = random.randint(3, 12)
    rem   = random.randint(15, 25)
    light = random.randint(35, 50)
    deep  = 100 - awake - rem - light  # remainder → deep sleep

    stages = {"awake": awake, "rem": rem, "light": light, "deep": max(deep, 0)}

    return {
        "total_duration_min": random.randint(280, 520),
        "efficiency_pct":     round(random.uniform(72, 97), 1),
        "stages_pct":         stages,
        "current_stage":      random.choice(list(stages.keys())),
        "interruptions":      random.randint(0, 8),
    }

def generate_payload():
    return {
        "device_id":        DEVICE_ID,
        "timestamp":        datetime.now(timezone.utc).isoformat(),
        "firmware_version": FIRMWARE,
        "hrv":              generate_hrv(),
        "rhr":              generate_rhr(),
        "sleep":            generate_sleep(),
        "battery_pct":      random.randint(15, 100),
        "signal_quality":   random.choice(["excellent", "good", "fair"]),
    }

def run():
    print(f"[simulator] device {DEVICE_ID} starting — interval {INTERVAL}s\n")
    count = 0
    while True:
        count += 1
        payload = generate_payload()
        print(f"--- payload #{count} ---")
        print(json.dumps(payload, indent=2))
        print()
        time.sleep(INTERVAL)

if __name__ == "__main__":
    run()