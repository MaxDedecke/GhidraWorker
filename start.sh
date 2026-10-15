#!/usr/bin/env sh
# GhidraWorker starten (Linux/macOS). Legt beim ersten Start eine virtuelle Python-Umgebung an.
set -e
cd "$(dirname "$0")"
if [ ! -x .venv/bin/python ]; then
    echo "Erstelle Python-Umgebung..."
    python3 -m venv .venv
    .venv/bin/python -m pip install --upgrade pip >/dev/null
    .venv/bin/python -m pip install -r requirements.txt
fi
exec .venv/bin/python -m ghidraworker serve "$@"
