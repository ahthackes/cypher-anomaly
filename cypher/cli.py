from __future__ import annotations
import argparse, pathlib, sys
from typing import List
import pandas as pd
from rich.console import Console

from .config import load_config
from .parsers import parse_auth_line, parse_syslog_line, parse_apache_line
from .utils.features import extract_ip, ip_octets, parse_timestamp_to_fields
from .detectors.ml import train_iforest, score_iforest, save_model, load_model, FEATURE_COLS
from .detectors.rules import burst_rules
from .utils.io import write_parquet, read_parquet_many
from .reports.markdown import generate_markdown
from .reports.html import generate_html

console = Console()

def parse_file(path: str) -> pd.DataFrame:
    p = pathlib.Path(path)
    rows = []
    with p.open("r", errors="ignore") as f:
        for ln in f:
            rec = parse_auth_line(ln) or parse_syslog_line(ln) or parse_apache_line(ln)
            if not rec: 
                continue
            # derive features
            ip = rec.get("src_ip") or extract_ip(rec.get("raw",""))
            rec["src_ip"] = ip
            rec.update(ip_octets(ip))
            rec.update(parse_timestamp_to_fields(rec.get("ts")))
            # default columns
            rec.setdefault("status", 0)
            rec.setdefault("size", 0)
            rec.setdefault("is_failed_ssh", 0)
            rec.setdefault("is_invalid_user", 0)
            rec.setdefault("is_sudo", 0)
            rec.setdefault("is_sudo_fail", 0)
            rows.append(rec)
    if not rows:
        return pd.DataFrame(columns=["ts","raw"] + FEATURE_COLS)
    df = pd.DataFrame(rows)
    df.sort_values("ts", inplace=True, ignore_index=True)
    return df

def cmd_parse(args):
    df = parse_file(args.file)
    if args.out:
        write_parquet(df, args.out)
        console.print(f"[green]Wrote[/green] {len(df)} rows -> {args.out}")
    else:
        console.print(df.head(10).to_string())

def cmd_train(args):
    cfg = load_config(args.config)
    df = read_parquet_many(args.data)
    if df.empty:
        console.print("[red]No data[/red]"); return
    model = train_iforest(df, cfg["train"])
    pathlib.Path(args.model).parent.mkdir(parents=True, exist_ok=True)
    save_model(model, args.model)
    console.print(f"[green]Model saved[/green] -> {args.model}")
    console.print(f"Features used: {FEATURE_COLS}")

def cmd_score(args):
    cfg = load_config(args.config)
    df = read_parquet_many(args.data)
    if df.empty:
        console.print("[red]No data[/red]"); return
    model = load_model(args.model)
    scored = score_iforest(model, df)
    scored = burst_rules(scored, cfg["rules"])
    if args.out:
        write_parquet(scored, args.out)
        console.print(f"[green]Wrote scores[/green] -> {args.out}")
    else:
        console.print(scored.head(20).to_string())

def cmd_report(args):
    df = read_parquet_many([args.scores])
    if df.empty:
        console.print("[red]No scores[/red]"); return
    if args.format == "markdown":
        generate_markdown(df, args.out, top_n=args.top)
    elif args.format == "html":
        generate_html(df, args.out, top_n=args.top)
    console.print(f"[green]Report written[/green] -> {args.out}")

def main(argv: List[str] | None = None):
    ap = argparse.ArgumentParser(prog="cypher", description="Cypher — Local Log Anomaly Detector")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_parse = sub.add_parser("parse", help="Parse a raw log file into a structured dataset")
    p_parse.add_argument("--file", required=True)
    p_parse.add_argument("--out", help="Output .parquet path")
    p_parse.set_defaults(func=cmd_parse)

    p_train = sub.add_parser("train", help="Train IsolationForest on parsed parquet datasets")
    p_train.add_argument("--data", nargs="+", required=True, help="One or more .parquet files")
    p_train.add_argument("--model", required=True, help="Path to save model .joblib")
    p_train.add_argument("--config", default=None)
    p_train.set_defaults(func=cmd_train)

    p_score = sub.add_parser("score", help="Score datasets with trained model and apply rule bursts")
    p_score.add_argument("--data", nargs="+", required=True, help="One or more .parquet files")
    p_score.add_argument("--model", required=True)
    p_score.add_argument("--out", required=True, help="Output scores .parquet")
    p_score.add_argument("--config", default=None)
    p_score.set_defaults(func=cmd_score)

    p_report = sub.add_parser("report", help="Generate a Markdown or HTML report from scored parquet")
    p_report.add_argument("--scores", required=True)
    p_report.add_argument("--format", choices=["markdown","html"], default="markdown")
    p_report.add_argument("--out", required=True)
    p_report.add_argument("--top", type=int, default=50)
    p_report.set_defaults(func=cmd_report)

    args = ap.parse_args(argv)
    args.func(args)

if __name__ == "__main__":
    main()
