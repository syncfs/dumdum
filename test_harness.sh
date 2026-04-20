#!/bin/bash

echo "=== Test 1: VM environment (expect decoy) ==="
LD_PRELOAD=./cpuinfo_mock.so ./stub
echo "Exit: $?"

echo ""
echo "=== Test 2: Bare metal (expect payload) ==="
./stub
echo "Exit: $?"
