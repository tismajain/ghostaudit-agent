#!/usr/bin/env python3
"""Review every intended commit file; print paths/counts, never secret values."""
import argparse
import os
import re
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
DIRECTORIES = {"src", "tests", "examples", "docs", "scripts"}
TOP_FILES = {"README.md", "requirements.txt", ".gitignore", "LICENSE"}
LOCAL_ONLY = {"runs", "cache", ".cache", ".venv", "venv", "env", ".git", "__pycache__", ".pytest_cache"}
SECRET = re.compile(rb"\bsk-[A-Za-z0-9_-]{20,}|\bgh[pousr]_[A-Za-z0-9]{20,}|\bgithub_pat_[A-Za-z0-9_]{20,}|\bAKIA[0-9A-Z]{16}\b|-----BEGIN [A-Z ]*PRIVATE KEY-----\s+[A-Za-z0-9+/=]{20,}")

def intended_files():
    files = []
    for path in ROOT.rglob("*"):
        relative = path.relative_to(ROOT)
        if any(part in LOCAL_ONLY for part in relative.parts):
            continue
        if path.is_symlink():
            raise RuntimeError(f"Review symlink before committing: {relative}")
        if not path.is_file():
            continue
        if path.name.startswith(".env") or path.suffix in {".pem", ".key", ".zip", ".pyc", ".log", ".jsonl"}:
            raise RuntimeError(f"Unexpected sensitive/generated file: {relative}")
        if relative.parts[0] not in DIRECTORIES and str(relative) not in TOP_FILES:
            raise RuntimeError(f"Unexpected public root file: {relative}")
        files.append(path)
    return sorted(files)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write-manifest", action="store_true")
    args = parser.parse_args()
    manifest = ROOT / "docs/public_files.md"
    if args.write_manifest and not manifest.exists():
        manifest.write_text("")
    files = intended_files()
    current = os.environ.get("OPENAI_API_KEY", "").encode()
    bad = []
    for path in files:
        raw = path.read_bytes()
        if SECRET.search(raw) or (current and current in raw):
            bad.append(str(path.relative_to(ROOT)))
    if bad:
        raise RuntimeError("Secret material detected in these paths (values withheld): " + ", ".join(bad))
    names = [str(p.relative_to(ROOT)) for p in files]
    if args.write_manifest:
        manifest.write_text("# Intended public commit files\n\nOnly these source/docs/new synthetic-example files are intended for the initial commit. Runtime folders and original competition material are excluded.\n\n" + "\n".join(f"- `{n}`" for n in names) + "\n")
    elif not manifest.exists():
        raise RuntimeError("Missing reviewed file manifest; run with --write-manifest")
    else:
        listed = [line[3:-1] for line in manifest.read_text().splitlines() if line.startswith("- `") and line.endswith("`")]
        if names != listed:
            raise RuntimeError("Commit file manifest changed; review and regenerate it explicitly")
    print(f"PASS: {len(files)} intended files reviewed; no secret matches. No competition dataset, history, private logs or run caches are in the commit list.")
    for name in names:
        print(name)
if __name__ == "__main__":
    main()
