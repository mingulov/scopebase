#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Install this package template as /payload/run in the freshly staged payload.
set -eu
export PATH=/payload:/bin:/usr/bin
export PYTHONHOME=/payload/python
export PYTHONDONTWRITEBYTECODE=1
export TMPDIR=/tmp
mkdir -p /results/bp02
uname -a > /results/bp02/kernel.txt
cat /sys/devices/system/cpu/possible > /results/bp02/possible.txt
cat /sys/devices/system/cpu/online > /results/bp02/online.txt
route_exit=0
for mode in default no-default; do
 if /payload/python/bin/python3 /payload/source/tests/fixtures/bp02/run_live.py \
   --package /payload/source --out "/results/bp02/native-$mode" \
   --toolchain 1.98.1 --feature "$mode" --owned-resource /payload/resource.json \
   --owned-namespace --prebuilt "/payload/specs/$mode.json"; then
  :
 else
  route_exit=$?
  break
 fi
done
if [ "$route_exit" -eq 0 ]; then
 if /payload/python/bin/python3 /payload/archive/tests/fixtures/bp02/run_consumers.py \
   --package /payload/archive --out /results/bp02/archive-native \
   --toolchain 1.98.1 --native --prebuilt /payload/specs/archive-clients.json; then
  :
 else
  route_exit=$?
 fi
fi
if /payload/python/bin/python3 /payload/source/tests/fixtures/bp02/payload_summary.py \
  --payload /payload --results /results/bp02; then
 :
else
 summary_exit=$?
 if [ "$route_exit" -eq 0 ]; then route_exit=$summary_exit; fi
fi
exit "$route_exit"
