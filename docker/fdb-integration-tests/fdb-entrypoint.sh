#!/bin/bash
# FoundationDB Entrypoint Script for Integration Tests
# This script starts a single-node FDB cluster for testing

set -e

# Get container IP
CONTAINER_IP=$(hostname -i)
FDB_PORT=4500

echo "Starting FDB server on ${CONTAINER_IP}:${FDB_PORT}"

# Create cluster file
echo "docker:docker@${CONTAINER_IP}:${FDB_PORT}" > /var/fdb/fdb.cluster

# Start fdbserver in background so we can configure it
/usr/sbin/fdbserver \
    --cluster-file=/var/fdb/fdb.cluster \
    --datadir=/var/fdb/data \
    --logdir=/var/fdb/logs \
    --public-address=${CONTAINER_IP}:${FDB_PORT} \
    --listen-address=0.0.0.0:${FDB_PORT} &

FDB_PID=$!

# Wait for fdbserver to start accepting connections
echo "Waiting for FDB server to be ready..."
for i in $(seq 1 30); do
    if fdbcli --exec "status minimal" 2>/dev/null | grep -q "The database is"; then
        break
    fi
    # Also check if server is available but unconfigured
    if fdbcli --exec "status" 2>/dev/null | grep -q "Redundancy mode"; then
        break
    fi
    sleep 1
done

# Configure database if not already configured
# Check if we need to create a new database
if ! fdbcli --exec "status" 2>/dev/null | grep -q "Healthy"; then
    echo "Configuring new FDB database..."
    fdbcli --exec "configure new single memory" || true
fi

echo "FDBD joined cluster."

# Wait for the fdbserver process
wait $FDB_PID
