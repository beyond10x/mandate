#!/usr/bin/env bash
# Build federated-login-approval.pdf out of tree. Usage: build.sh <output-dir>  (CUSTOMER and DOCDATE env override the footer)
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; out="${1:?output dir}"; mkdir -p "$out"
rsvg-convert -w 240 -h 240 "${B10X_MARK_SVG:-$here/../../../website/static/img/mark.svg}" -o "$out/mark.png" 2>/dev/null || true
python3 "$here/figures/sso-flow.py" "$out/sso-flow.png"
python3 "$here/build.py" "$out"
