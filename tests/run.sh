#!/bin/bash -x

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

cd $DIR
node compare_both.js
node test.js
node test_async.js
node test_async_light.js
node test_async_heavy.js
node test_async_superfast.js
node test_sync-1.js
node test_sync-2.js
node test_sync-xtl.js
node test_sync-msr.js
node test_sync-xao.js
node test_sync-rto.js
node test_sync.js
node test_sync_light.js
node test_sync_light-1.js
node test_sync_heavy.js
node test_sync_heavy-xhv.js
node test_sync_heavy-tube.js
node test_sync_superfast.js
node test_perf.js
node test_perf_light.js
node test_perf_heavy.js
node test_perf_superfast.js
