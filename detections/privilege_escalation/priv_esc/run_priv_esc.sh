#!/bin/bash

set -e

BASE_DIR="/opt/priv_esc"
PYTHON="/usr/bin/python3"

cd "$BASE_DIR"

$PYTHON audit_parser.py
$PYTHON audit_normalizer.py
