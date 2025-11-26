"""
reporting.py
Advanced Reporting Module for firewall project.

Dependencies:
    pip install pandas matplotlib python-dateutil

Place this file in your project (next to logging_monitoring.py).
"""

import tkinter as tk
from PIL import Image, ImageTk
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import os
import json
from pathlib import Path
from datetime import datetime, timedelta
from dateutil import parser as dtparser
import pandas as pd
from PIL import Image, ImageTk
import os
from pathlib import Path
from datetime import datetime
import json
import pandas as pd
from PIL import Image, ImageTk
# ---- Configuration defaults ----
DEFAULT_LOG_DIR = Path("logs")
DEFAULT_OUTPUT_DIR = Path("reports")
DEFAULT_LOG_FILES = ["firewall.log", "security.log"]  # try these by default
REPORT_TIMEZONE = None  # if needed, set timezone-aware handling

def generate_report(log_dir=DEFAULT_LOG_DIR, output_dir=DEFAULT_OUTPUT_DIR, period="daily", log_files=None, now=None):
    """
    High-level function:
      - loads logs
      - aggregates metrics for specified period ('daily' or 'weekly')
      - writes JSON report to output_dir/<period>/report_<YYYYMMDD>.json
      - produces PNG graphs into output_dir/<period>/images/
      - returns path to JSON report and list of Tkinter PhotoImage objects
    """
    now = now or datetime.utcnow()
    output_dir = Path(output_dir) / period
    df = load_logs_to_dataframe(log_dir, files=log_files)
    aggregated = aggregate_metrics(df, period=period)

    # Prepare filenames
    date_str = now.strftime("%Y%m%d")
    report_path = output_dir / f"report_{date_str}.json"
    image_dir = output_dir / "images"
    image_dir.mkdir(parents=True, exist_ok=True)

    saved_image_paths = []

    # Save graphs
    ts = aggregated["dataframes"].get("time_series")
    if ts is not None and not ts.empty:
        xcol = ts.columns[0]
        img_path = image_dir / f"time_series_{date_str}.png"
        save_plot_from_series(ts, xcol, ["events", "bytes"], f"Events & Bytes per {period.capitalize()}", img_path)
        saved_image_paths.append(img_path)

    # Top lists
    for name in ("top_src", "top_dst", "top_blocked_src", "top_rules"):
        dfp = aggregated["dataframes"].get(name)
        if dfp is None or dfp.empty:
            continue
        if name == "top_rules":
            img_path = image_dir / f"{name}_{date_str}.png"
            save_bar_from_df(dfp, "rule_id", "hits", f"Top Rules ({period})", img_path, top_n=15)
        else:
            cols = list(dfp.columns)
            idx_col = cols[0]
            val_col = cols[1] if len(cols) > 1 else cols[-1]
            img_path = image_dir / f"{name}_{date_str}.png"
            save_bar_from_df(dfp, idx_col, val_col, f"{name.replace('_',' ').title()} ({period})", img_path)
        saved_image_paths.append(img_path)

    # Convert summary and top N into simple JSON serializable structure
    def df_to_records(dfr):
        if dfr is None or dfr.empty:
            return []
        res = dfr.fillna("").to_dict(orient="records")
        for r in res:
            for k, v in r.items():
                if isinstance(v, (datetime, pd.Timestamp)):
                    r[k] = str(v)
        return res

    report = {
        "generated_at": now.isoformat(),
        "period": period,
        "summary": aggregated["summary"],
        "time_series": df_to_records(aggregated["dataframes"].get("time_series")),
        "top_src": df_to_records(aggregated["dataframes"].get("top_src")),
        "top_dst": df_to_records(aggregated["dataframes"].get("top_dst")),
        "top_blocked_src": df_to_records(aggregated["dataframes"].get("top_blocked_src")),
        "top_rules": df_to_records(aggregated["dataframes"].get("top_rules")),
        "images": [str(p.relative_to(output_dir)) for p in sorted(saved_image_paths)],
    }

    output_dir.mkdir(parents=True, exist_ok=True)
    with open(report_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, default=str)

    # Load images as Tkinter PhotoImage objects
    gui_images = [ImageTk.PhotoImage(Image.open(p)) for p in saved_image_paths]

    return report_path, gui_images

def show_report_images(image_paths):
    # Filter out non-existing files
    image_paths = [p for p in image_paths if p.exists()]
    if not image_paths:
        print("No images to display.")
        return

    root = tk.Tk()
    root.title("Firewall Report Images")

    # Load images once and keep references in a list
    root.imgs = []
    for path in image_paths:
        try:
            img = Image.open(path)
            img = img.resize((800, 400), Image.Resampling.LANCZOS)
            root.imgs.append(ImageTk.PhotoImage(img))
        except Exception as e:
            print(f"Failed to load image {path}: {e}")

    if not root.imgs:
        print("No valid images could be loaded.")
        return

    index = {"current": 0}
    label = tk.Label(root, image=root.imgs[0])
    label.pack()

    def show_next():
        index["current"] = (index["current"] + 1) % len(root.imgs)
        label.config(image=root.imgs[index["current"]])
        label.img = root.imgs[index["current"]]  # keep reference

    btn = tk.Button(root, text="Next", command=show_next)
    btn.pack()

    root.mainloop()



# ---- Helper parsers ----
def try_parse_line_to_record(line: str):
    """
    Try to parse a single log line. The function attempts:
      - JSON decode (if log is JSON lines)
      - CSV-like split on whitespace with known fields fallback
      - returns dict with at least: timestamp, src_ip, dst_ip, action, bytes, rule_id
    """
    line = line.strip()
    if not line:
        return None

    # Try JSON
    try:
        obj = json.loads(line)
        # normalize keys
        record = {
            "timestamp": obj.get("timestamp") or obj.get("time") or obj.get("ts"),
            "src_ip": obj.get("src") or obj.get("src_ip") or obj.get("source"),
            "dst_ip": obj.get("dst") or obj.get("dst_ip") or obj.get("destination"),
            "action": obj.get("action") or obj.get("result") or obj.get("verdict"),
            "bytes": obj.get("bytes") or obj.get("size") or obj.get("length") or 0,
            "rule_id": obj.get("rule_id") or obj.get("rule") or obj.get("rid"),
        }
        return record
    except Exception:
        pass

    # Fallback: simple whitespace split with expected tokens (very best-effort).
    parts = line.split()
    # Example fallback patterns (customize for your log format).
    # Try to find a timestamp at start
    rec = {"timestamp": None, "src_ip": None, "dst_ip": None, "action": None, "bytes": 0, "rule_id": None}
    # naive timestamp attempt
    try:
        # assume first token is timestamp-ish
        rec["timestamp"] = parts[0]
    except Exception:
        rec["timestamp"] = None
    # try to locate src/dst tokens like src=1.2.3.4 dst=...
    for p in parts:
        if p.startswith("src="):
            rec["src_ip"] = p.split("=", 1)[1]
        elif p.startswith("dst="):
            rec["dst_ip"] = p.split("=", 1)[1]
        elif p.startswith("action="):
            rec["action"] = p.split("=", 1)[1]
        elif p.startswith("bytes="):
            try:
                rec["bytes"] = int(p.split("=", 1)[1])
            except Exception:
                rec["bytes"] = 0
        elif p.startswith("rule=") or p.startswith("rule_id="):
            rec["rule_id"] = p.split("=", 1)[1]
    # if nothing found, return None
    if not any([rec["timestamp"], rec["src_ip"], rec["dst_ip"], rec["action"]]):
        return None
    return rec

def load_logs_to_dataframe(log_dir=DEFAULT_LOG_DIR, files=None):
    files = files or DEFAULT_LOG_FILES
    records = []
    log_dir = Path(log_dir)
    for fname in files:
        fpath = log_dir / fname
        if not fpath.exists():
            continue
        with open(fpath, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                rec = try_parse_line_to_record(line)
                if rec is None:
                    continue
                # parse timestamp to datetime
                ts = rec.get("timestamp")
                try:
                    rec["timestamp"] = dtparser.parse(ts) if ts else None
                except Exception:
                    rec["timestamp"] = None
                # normalize fields
                try:
                    rec["bytes"] = int(rec.get("bytes") or 0)
                except Exception:
                    rec["bytes"] = 0
                records.append(rec)
    if not records:
        # return empty dataframe with expected columns
        return pd.DataFrame(columns=["timestamp", "src_ip", "dst_ip", "action", "bytes", "rule_id"])
    df = pd.DataFrame.from_records(records)
    # ensure timestamp column is datetime
    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    return df

# ---- Aggregation / metrics ----
def aggregate_metrics(df: pd.DataFrame, period: str = "daily"):
    """
    period: 'daily' or 'weekly'
    Returns a dict of aggregated metrics and dataframes used for graphs.
    Metrics include:
      - total_events
      - total_bytes
      - events_per_hour/day
      - top_src (by events)
      - top_dst
      - top_blocked (action == 'BLOCK' or 'DROP' heuristics)
      - top_rules
    """
    if df.empty:
        return {"summary": {}, "dataframes": {}}
    # normalize action uppercase
    df["action_norm"] = df["action"].fillna("").str.upper()
    # detect block-like actions
    df["is_block"] = df["action_norm"].isin({"BLOCK", "DROP", "DENY", "REJECT"})
    # choose resample rule
    if period == "daily":
        # group by date and hour for more detail: hourly series across last 24 hours/days
        df["date"] = df["timestamp"].dt.date
        # events per day
        events_per_day = df.groupby("date").size().rename("events").reset_index()
        bytes_per_day = df.groupby("date")["bytes"].sum().rename("bytes").reset_index()
        time_series = pd.merge(events_per_day, bytes_per_day, on="date")
    elif period == "weekly":
        # define week start (Monday)
        df["week"] = df["timestamp"].dt.to_period("W").apply(lambda r: r.start_time.date())
        events_per_week = df.groupby("week").size().rename("events").reset_index()
        bytes_per_week = df.groupby("week")["bytes"].sum().rename("bytes").reset_index()
        time_series = pd.merge(events_per_week, bytes_per_week, on="week")
    else:
        raise ValueError("period must be 'daily' or 'weekly'")

    # top talkers
    top_src = df.groupby("src_ip").size().rename("events").reset_index().sort_values("events", ascending=False).head(10)
    top_dst = df.groupby("dst_ip").size().rename("events").reset_index().sort_values("events", ascending=False).head(10)

    # top blocked IPs
    blocked = df[df["is_block"]]
    top_blocked_src = blocked.groupby("src_ip").size().rename("blocked_events").reset_index().sort_values("blocked_events", ascending=False).head(10)
    # top rules
    top_rules = df.groupby("rule_id").size().rename("hits").reset_index().sort_values("hits", ascending=False).head(20)

    summary = {
        "total_events": int(len(df)),
        "total_bytes": int(df["bytes"].sum()),
        "total_blocked": int(blocked.shape[0]),
        "unique_src": int(df["src_ip"].nunique()),
        "unique_dst": int(df["dst_ip"].nunique()),
    }

    dataframes = {
        "time_series": time_series,
        "top_src": top_src,
        "top_dst": top_dst,
        "top_blocked_src": top_blocked_src,
        "top_rules": top_rules,
    }
    return {"summary": summary, "dataframes": dataframes}

# ---- Graph generation ----
def save_plot_from_series(series_df: pd.DataFrame, x_col: str, y_cols: list, title: str, out_path: Path):
    """
    Basic plot routine. y_cols is a list (one or more series columns).
    Uses matplotlib; does not set colors (per your style rules).
    """
    if series_df.empty:
        return None
    plt.figure(figsize=(10, 5))
    for y in y_cols:
        plt.plot(series_df[x_col], series_df[y], label=y)
    plt.xlabel(x_col)
    plt.ylabel(", ".join(y_cols))
    plt.title(title)
    plt.legend()
    plt.tight_layout()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(out_path)
    plt.close()
    return out_path

def save_bar_from_df(df: pd.DataFrame, index_col: str, value_col: str, title: str, out_path: Path, top_n=10):
    if df.empty:
        return None
    plot_df = df.head(top_n)
    plt.figure(figsize=(10, 5))
    plt.bar(plot_df[index_col].astype(str), plot_df[value_col])
    plt.xticks(rotation=45, ha="right")
    plt.xlabel(index_col)
    plt.ylabel(value_col)
    plt.title(title)
    plt.tight_layout()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(out_path)
    plt.close()
    return out_path

# ---- Main report generation ----


# ---- CLI-friendly entrypoint ----
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Generate firewall activity reports (daily/weekly).")
    parser.add_argument("--log-dir", default=str(DEFAULT_LOG_DIR))
    parser.add_argument("--out-dir", default=str(DEFAULT_OUTPUT_DIR))
    parser.add_argument("--period", choices=["daily", "weekly"], default="daily")
    parser.add_argument("--files", nargs="*", default=None, help="specific log filenames (space separated)")
    args = parser.parse_args()
    
    # Generate the report
    rp = generate_report(
        log_dir=Path(args.log_dir),
        output_dir=Path(args.out_dir),
        period=args.period,
        log_files=args.files
    )
    
    print("Report written to:", rp)

    # --- Show GUI images ---
    # Load JSON report to get images
    with open(rp, "r", encoding="utf-8") as fh:
        report_data = json.load(fh)

    # Construct full paths for images
# Construct full paths for images
    image_paths = [Path(args.out_dir) / args.period / p for p in report_data.get("images", [])]
    
    # Display images in a Tkinter window
    show_report_images(image_paths)

