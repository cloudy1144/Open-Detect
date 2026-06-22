#!/bin/bash
# Open-Detect container entrypoint
# Supports two modes:
#   CAPTURE (default): live packet capture via Scapy
#   INGEST: read JSON Lines from stdin via pipeline_ingest
#   DRYRUN: just verify model loads and write health.json once

set -e

MODE="${OD_MODE:-capture}"
IFACE="${OD_IFACE:-eth0}"
FILTER="${OD_FILTER:-tcp}"
MODEL_PATH="${OD_MODEL_PATH:-save_model/mixed_44_split_0.pt}"
THRESHOLD="${OD_THRESHOLD:-2.24}"
HEALTH_FILE="${OD_HEALTH_FILE:-/app/health.json}"
ALERTS_DB="${OD_ALERTS_DB:-/app/alerts.db}"
EXPORT_DIR="${OD_EXPORT_DIR:-./abnormal_flows}"
DURATION="${OD_DURATION:-}"

echo "=== Open-Detect Container ==="
echo "Mode:       $MODE"
echo "Interface:  $IFACE"
echo "Filter:     $FILTER"
echo "Model:      $MODEL_PATH"
echo "Threshold:  $THRESHOLD"
echo "Health:     $HEALTH_FILE"
echo "Alerts DB:  $ALERTS_DB"
echo "============================"

# Verify model file exists
if [ ! -f "$MODEL_PATH" ]; then
    echo "ERROR: Model file not found at $MODEL_PATH"
    exit 1
fi

cd /app

case "$MODE" in
    dryrun)
        echo "DRYRUN: Verifying model loads correctly..."
        python -c "
import torch
from model import OpenDetectNet
try:
    model = torch.load('$MODEL_PATH', map_location='cpu', weights_only=False)
    model.eval()
    print('Model loaded successfully. Classes:', model.n_classes)
except Exception as e:
    print('Model load failed:', e)
    import sys; sys.exit(1)
"
        echo "DRYRUN: OK"
        ;;

    ingest)
        echo "INGEST mode: reading from stdin..."
        exec python -m realtime_detection.pipeline_ingest
        ;;

    capture|*)
        echo "CAPTURE mode: starting live capture on $IFACE..."
        # Build optional duration flag
        DUR_FLAG=""
        if [ -n "$DURATION" ]; then
            DUR_FLAG="--duration $DURATION"
        fi
        exec python -m realtime_detection.capture \
            --iface "$IFACE" \
            --filter "$FILTER" \
            $DUR_FLAG \
            --debug
        ;;
esac
