#!/usr/bin/env python3
"""
find_secrets.py

Recursively scan files in a Linux system (pod, EC2, local) for regex patterns.
Reads all readable files as text and reports every match with file path, regex, and context.

Outputs:
- JSON file with full details
- CSV file for quick triage

Usage:
  python3 find_secrets.py -r /path/to/scan -R regexes.json -o results.json -c results.csv
"""

import argparse
import json
import os
import re
import sys
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import List, Dict, Any, Optional
import csv

# optional pdf support
try:
    import PyPDF2
except Exception:
    PyPDF2 = None

# Directories that are noisy/unreadable
DEFAULT_SKIP_DIRS = {"/proc", "/sys", "/dev", "/run", "/var/lib/docker", "/var/run"}
DEFAULT_MAX_BYTES = 10 * 1024 * 1024  # 10 MB per file


def load_regexes(path: str) -> List[Dict[str, str]]:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Regex file not found: {path}")
    text = p.read_text(encoding="utf-8", errors="replace")
    try:
        data = json.loads(text)
        if isinstance(data, list):
            out = []
            for i, e in enumerate(data):
                if isinstance(e, dict) and "pattern" in e:
                    name = e.get("name") or f"pattern_{i}"
                    out.append({"name": name, "pattern": e["pattern"]})
                elif isinstance(e, str):
                    out.append({"name": f"pattern_{i}", "pattern": e})
            return out
    except Exception:
        pass
    lines = [l.strip() for l in text.splitlines() if l.strip() and not l.strip().startswith("#")]
    return [{"name": f"pattern_{i}", "pattern": l} for i, l in enumerate(lines)]


def compile_regexes(regex_list: List[Dict[str, str]]) -> List[Dict[str, Any]]:
    compiled = []
    for r in regex_list:
        try:
            cre = re.compile(r["pattern"], re.MULTILINE | re.DOTALL)
            compiled.append({"name": r.get("name", r["pattern"]), "pattern": r["pattern"], "re": cre})
        except re.error as e:
            print(f"[!] Failed to compile pattern {r.get('name')}: {e}", file=sys.stderr)
    return compiled


def extract_text_from_docx(path: str) -> str:
    try:
        with zipfile.ZipFile(path, "r") as z:
            if "word/document.xml" in z.namelist():
                data = z.read("word/document.xml").decode("utf-8", errors="replace")
                text = re.sub(r"<w:t[^>]*>", "", data)
                text = re.sub(r"</w:t>", " ", text)
                text = re.sub(r"<[^>]+>", " ", text)
                return text
    except Exception:
        pass
    return ""


def extract_text_from_pdf(path: str) -> str:
    if PyPDF2 is None:
        return ""
    try:
        with open(path, "rb") as fh:
            reader = PyPDF2.PdfReader(fh)
            out = []
            for page in reader.pages:
                try:
                    out.append(page.extract_text() or "")
                except Exception:
                    pass
            return "\n".join(out)
    except Exception:
        return ""


def read_file_text(path: str, max_bytes: int) -> Optional[str]:
    p = Path(path)
    ext = p.suffix.lower()
    try:
        if ext == ".docx":
            return extract_text_from_docx(path)
        if ext == ".pdf":
            txt = extract_text_from_pdf(path)
            if txt:
                return txt
        with open(path, "rb") as fh:
            data = fh.read(max_bytes + 1)
            try:
                return data.decode("utf-8")
            except Exception:
                try:
                    return data.decode("latin-1")
                except Exception:
                    return data.decode("utf-8", errors="replace")
    except (PermissionError, IsADirectoryError):
        return None
    except Exception:
        return None


def should_skip_path(path: str, no_skip: bool) -> bool:
    if no_skip:
        return False
    for s in DEFAULT_SKIP_DIRS:
        if path == s or path.startswith(s + os.sep):
            return True
    return False


def redact_long(s: str, max_len: int = 120) -> str:
    if len(s) <= max_len:
        return s
    return f"{s[:40]}...[{len(s)}b]...{s[-40:]}"


def scan_file_for_patterns(path: str, compiled_patterns: List[Dict[str, Any]], max_bytes: int, context: int):
    results = []
    txt = read_file_text(path, max_bytes)
    if not txt:
        return results
    for patt in compiled_patterns:
        for m in patt["re"].finditer(txt):
            matched_text = m.group(0)
            display = redact_long(matched_text)
            line = txt.count("\n", 0, m.start()) + 1 if "\n" in txt else None
            ctx_start = max(0, m.start() - context)
            ctx_end = min(len(txt), m.end() + context)
            context_snippet = txt[ctx_start:ctx_end].replace("\n", " ")
            context_snippet = redact_long(context_snippet, max_len=300)
            results.append({
                "file": path,
                "regex_name": patt["name"],
                "regex": patt["pattern"],
                "match": display,
                "start": m.start(),
                "end": m.end(),
                "line": line,
                "context": context_snippet
            })
    return results


def iter_files(root: str, follow_symlinks: bool, no_skip: bool):
    for dirpath, dirnames, filenames in os.walk(root, followlinks=follow_symlinks):
        if should_skip_path(dirpath, no_skip):
            dirnames[:] = []
            continue
        for fn in filenames:
            yield os.path.join(dirpath, fn)


def write_csv(path: str, data: List[Dict[str, Any]]):
    fieldnames = ["file", "line", "regex_name", "regex", "match", "start", "end", "context"]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for r in data:
            writer.writerow(r)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", "-r", default=".", help="Root path to scan")
    ap.add_argument("--regex-file", "-R", required=True, help="File with regexes")
    ap.add_argument("--threads", "-t", type=int, default=6)
    ap.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES)
    ap.add_argument("--out-json", "-o", default="results.json", help="Write results JSON")
    ap.add_argument("--out-csv", "-c", default="results.csv", help="Write results CSV")
    ap.add_argument("--no-skip", action="store_true")
    ap.add_argument("--follow-symlinks", action="store_true")
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--context", type=int, default=40, help="Context chars around match")
    args = ap.parse_args()

    regex_list = load_regexes(args.regex_file)
    compiled = compile_regexes(regex_list)
    if not compiled:
        print("No valid regexes. Exiting.", file=sys.stderr)
        sys.exit(2)

    if not args.quiet:
        print(f"[+] Scanning {args.root} with {len(compiled)} regexes...")

    results = []
    files_iter = iter_files(args.root, args.follow_symlinks, args.no_skip)

    with ThreadPoolExecutor(max_workers=max(1, args.threads)) as ex:
        futures = {ex.submit(scan_file_for_patterns, f, compiled, args.max_bytes, args.context): f for f in files_iter}
        for fut in as_completed(futures):
            try:
                res = fut.result()
                if res:
                    results.extend(res)
            except Exception as e:
                if not args.quiet:
                    print(f"[!] Error scanning {futures[fut]}: {e}", file=sys.stderr)

    with open(args.out_json, "w", encoding="utf-8") as of:
        json.dump(results, of, indent=2, ensure_ascii=False)
    if not args.quiet:
        print(f"[+] Wrote {len(results)} matches to {args.out_json}")

    write_csv(args.out_csv, results)
    if not args.quiet:
        print(f"[+] Wrote CSV with {len(results)} rows to {args.out_csv}")

    sys.exit(0 if not results else 3)


if __name__ == "__main__":
    main()
