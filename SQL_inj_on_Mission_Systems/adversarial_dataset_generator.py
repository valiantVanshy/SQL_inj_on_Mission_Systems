import os
import random
import pandas as pd
from sklearn.utils import shuffle

random.seed(42)

KAGGLE_PATH  = "data/raw/kaggle_original.csv"
OUTPUT_PATH  = "data/raw/sql_injection_raw.csv"

# SATELLITE TABLES

TABLES = [
    "missions", "satellites", "telemetry", "orbit_params",
    "ground_stations", "operators", "commands", "sensor_logs",
    "fuel_levels", "attitude_control", "communication_links",
    "mission_events", "anomaly_reports", "payload_data",
    "orbital_maneuvers", "battery_status", "thermal_data",
    "navigation_data", "antenna_configs", "launch_records"
]

COLUMNS = [
    "id", "mission_id", "satellite_id", "operator_id",
    "status", "altitude_km", "velocity_ms", "signal_strength_db",
    "fuel_pct", "temperature_c", "created_at", "updated_at",
    "latitude", "longitude", "inclination_deg", "eccentricity",
    "battery_voltage", "solar_panel_output", "data_rate_kbps",
    "command_sequence", "anomaly_code", "ground_station_id",
]

STATUSES = ["active", "inactive", "standby", "nominal",
            "critical", "maintenance", "decommissioned"]

# Subtle — designed to look like safe queries

def adversarial_attacks():
    attacks = []

    # Attacks that look like normal queries
    for t in TABLES:
        attacks += [
            f"SELECT * FROM {t} WHERE id = 1 OR 1=1",
            f"SELECT * FROM {t} WHERE mission_id = 1 OR mission_id = 1",
            f"SELECT * FROM {t} WHERE id = 1 AND 1=1 AND id = 1",
            f"SELECT * FROM {t} WHERE status = 'active' OR 'x'='x'",
            f"SELECT * FROM {t} WHERE id = 1; SELECT * FROM {t}",
            f"SELECT * FROM {t} WHERE satellite_id = 1 OR satellite_id > 0",
            f"SELECT * FROM {t} WHERE altitude_km > 0 OR 1=1",
            f"SELECT * FROM {t} WHERE fuel_pct >= 0 OR fuel_pct >= 0",
        ]

    # Whitespace and comment evasion
    attacks += [
        "SELECT/*comment*/*/*from*/missions/**/WHERE/**/id=1/**/OR/**/1=1",
        "SELECT * FROM missions WHERE id=1 OR/**/1=1",
        "SELECT * FROM satellites WHERE id = 1 OR 1 = 1 -- normal query",
        "SELECT	*	FROM	missions	WHERE	id	=	1	OR	1=1",
        "SELECT * FROM missions WHERE id = 0x31 OR 1=1",
        "SELECT * FROM missions WHERE id = 1 OR 0x313d31",
    ]

    # Case variation evasion
    attacks += [
        "sElEcT * fRoM missions wHeRe id = 1 oR 1=1",
        "SELECT * FROM missions WHERE id = 1 Or 1=1",
        "select * from satellites where id = 1 or 1=1 --",
        "SELECT * FROM MISSIONS WHERE ID = 1 OR 1=1",
        "Select * From Operators Where Id = 1 Or 1=1",
    ]

    # URL encoded and special character evasion
    attacks += [
        "SELECT * FROM missions WHERE id = 1 OR 1=1%20--",
        "SELECT * FROM missions WHERE id = 1' OR '1'='1",
        "SELECT * FROM satellites WHERE id = -1 OR 1=1",
        "SELECT * FROM missions WHERE id = 1 OR 2=2",
        "SELECT * FROM missions WHERE id = 1 OR 3>2",
        "SELECT * FROM missions WHERE id = 1 OR 'a'='a'",
    ]

    # Blind injection disguised as normal queries
    attacks += [
        f"SELECT * FROM {random.choice(TABLES)} WHERE id = 1 AND SLEEP(0)",
        f"SELECT * FROM {random.choice(TABLES)} WHERE id = 1 AND 1=1 LIMIT 1",
        f"SELECT * FROM {random.choice(TABLES)} WHERE id = 1 AND LENGTH(status)>0",
        f"SELECT * FROM {random.choice(TABLES)} WHERE id = 1 AND SUBSTRING(status,1,1)='a'",
        f"SELECT * FROM {random.choice(TABLES)} WHERE id = 1 AND ASCII(SUBSTRING(status,1,1))>0",
    ]

    # UNION attacks with satellite column counts
    attacks += [
        f"SELECT id, status FROM missions WHERE id = 1 UNION SELECT 1,2",
        f"SELECT id, status, mission_id FROM satellites WHERE id = 1 UNION SELECT 1,2,3",
        f"SELECT * FROM missions WHERE id = -1 UNION SELECT null,null,null,null",
        f"SELECT id FROM operators WHERE id = 1 UNION SELECT password FROM operators",
        f"SELECT mission_id FROM missions WHERE id = 1 UNION SELECT operator_id FROM operators",
    ]

    # Stacked queries disguised
    attacks += [
        f"SELECT * FROM missions WHERE id = 1; DROP TABLE missions",
        f"SELECT * FROM satellites WHERE id = 1; UPDATE operators SET password = 'hacked'",
        f"SELECT * FROM missions WHERE id = 1; INSERT INTO operators VALUES(99,'hack','hack')",
        f"SELECT * FROM missions WHERE id = 1; DELETE FROM operators WHERE 1=1",
        f"SELECT * FROM missions WHERE id = 1; TRUNCATE TABLE sensor_logs",
    ]

    return attacks


# Complex safe queries that look suspicious

def adversarial_safe():
    safe = []

    # Queries with OR that are genuinely safe
    for t in TABLES:
        safe += [
            f"SELECT * FROM {t} WHERE status = 'active' OR status = 'standby'",
            f"SELECT * FROM {t} WHERE mission_id = 1 OR mission_id = 2",
            f"SELECT * FROM {t} WHERE id = 1 OR id = 2 OR id = 3",
            f"SELECT * FROM {t} WHERE altitude_km = 400 OR altitude_km = 500",
            f"SELECT * FROM {t} WHERE created_at > '2023-01-01' OR updated_at > '2023-01-01'",
        ]

    # Queries with special characters that are safe
    safe += [
        "SELECT * FROM missions WHERE operator_id = 'ops_admin'",
        "SELECT * FROM satellites WHERE status != 'decommissioned'",
        "SELECT * FROM telemetry WHERE temperature_c BETWEEN -50 AND 150",
        "SELECT * FROM missions WHERE mission_id IN (1, 2, 3, 4, 5)",
        "SELECT * FROM operators WHERE operator_id LIKE 'ops%'",
        "SELECT COUNT(*) FROM missions WHERE status = 'active' OR status = 'nominal'",
        "SELECT * FROM satellites WHERE altitude_km > 300 OR altitude_km < 200",
        "SELECT * FROM missions WHERE id BETWEEN 1 AND 100",
        "SELECT * FROM telemetry WHERE signal_strength_db > -90 OR signal_strength_db = 0",
        "SELECT mission_id, COUNT(*) FROM missions GROUP BY mission_id HAVING COUNT(*) > 1",
    ]

    # Subqueries that look dangerous but are safe
    safe += [
        f"SELECT * FROM missions WHERE id IN (SELECT mission_id FROM satellites WHERE status = 'active')",
        f"SELECT * FROM operators WHERE id IN (SELECT operator_id FROM missions WHERE status = 'nominal')",
        f"SELECT * FROM telemetry WHERE satellite_id IN (SELECT id FROM satellites WHERE altitude_km > 400)",
        f"SELECT * FROM missions WHERE id NOT IN (SELECT mission_id FROM anomaly_reports)",
        f"SELECT * FROM satellites WHERE id IN (SELECT satellite_id FROM fuel_levels WHERE fuel_pct < 20)",
    ]

    return safe

#MERGING

def load_kaggle(path):
    df = pd.read_csv(path)
    df.columns = df.columns.str.strip().str.lower()

    col_map = {}
    for c in df.columns:
        if c in ["query", "sentence", "text", "sql", "input"]:
            col_map[c] = "query"
        if c in ["label", "class", "target", "type", "output"]:
            col_map[c] = "label"
    df = df.rename(columns=col_map)
    df = df[["query", "label"]].dropna()
    df["query"] = df["query"].astype(str).str.lower().str.strip()
    df["label"] = df["label"].astype(int)
    print(f"[Kaggle] Loaded {len(df)} rows")
    return df


def generate():
    os.makedirs("data/raw", exist_ok=True)

    # Load Kaggle dataset
    if not os.path.exists(KAGGLE_PATH):
        print(f"[Error] Kaggle file not found at {KAGGLE_PATH}")
        print(f"[Fix]   Rename your Kaggle CSV to 'kaggle_original.csv'")
        print(f"[Fix]   and place it in data/raw/ folder")
        return

    kaggle_df = load_kaggle(KAGGLE_PATH)

    # Generate adversarial examples
    print("[Generator] Creating adversarial attack examples...")
    adv_attacks = adversarial_attacks()
    print(f"[Generator] Created {len(adv_attacks)} adversarial attacks")

    print("[Generator] Creating adversarial safe examples...")
    adv_safe = adversarial_safe()
    print(f"[Generator] Created {len(adv_safe)} adversarial safe queries")

    # Build adversarial dataframe
    adv_records = (
        [{"query": q.lower().strip(), "label": 1} for q in adv_attacks] +
        [{"query": q.lower().strip(), "label": 0} for q in adv_safe]
    )
    adv_df = pd.DataFrame(adv_records)

    # Merge Kaggle + adversarial
    combined_df = pd.concat([kaggle_df, adv_df], ignore_index=True)
    combined_df = shuffle(combined_df, random_state=42).reset_index(drop=True)

    # Save
    combined_df.to_csv(OUTPUT_PATH, index=False)

    print(f"\n[Generator] ✓ Dataset saved → {OUTPUT_PATH}")
    print(f"[Generator] Total rows    : {len(combined_df)}")
    print(f"[Generator] Safe queries  : {len(combined_df[combined_df.label==0])}")
    print(f"[Generator] Attack queries: {len(combined_df[combined_df.label==1])}")
    print(f"\n[Generator] Now run:")
    print(f"  python Preprocess/dataset_download.py")
    print(f"  python main.py")


if __name__ == "__main__":
    generate()
