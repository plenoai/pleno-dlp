#!/usr/bin/env bash
set -euo pipefail

go test ./... -race -count=1 -timeout 5m
