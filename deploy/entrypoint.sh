#!/bin/bash

# Check if external config is mounted
if [ -f "/app/external-config/policy.toml" ]; then
    echo "Using external configuration file"
    exec /app/bin/ltrack --config /app/external-config/policy.toml
else
    echo "Using default configuration file"
    exec /app/bin/ltrack --config /app/policy.toml
fi 