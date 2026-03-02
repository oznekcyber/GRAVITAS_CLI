#!/bin/bash
# GRAVITAS Batch Scanner
# Usage: ./batch_gravitas.sh emails.txt
# Runs GRAVITAS against each line in the input file

INPUT_FILE=$1
mkdir -p results

if [ -z "$INPUT_FILE" ]; then
    echo "Usage: $0 <input_file>"
    exit 1
fi

while IFS= read -r target; do
    [ -z "$target" ] && continue
    echo "[*] Scanning: $target"
    python gravitas.py --email "$target" > "results/${target}_result.txt" 2>&1
    echo "[+] Done: results/${target}_result.txt"
    sleep 2
done < "$INPUT_FILE"
