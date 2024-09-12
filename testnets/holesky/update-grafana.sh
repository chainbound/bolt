#!/bin/bash

# Get the commit-hash from first argument
commit_hash=$1

curl https://raw.githubusercontent.com/Commit-Boost/commit-boost-client/main/grafana/dashboards/dashboard.json -o ./grafana/dashboards/dashboard.json
curl https://raw.githubusercontent.com/Commit-Boost/commit-boost-client/main/grafana/dashboards/system_metrics.json -o ./grafana/dashboards/system_metrics.json
