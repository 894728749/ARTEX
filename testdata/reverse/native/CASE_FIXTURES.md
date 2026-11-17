# Synthetic native case fixtures

These sources are harmless, local-only inputs for native case and assertion
validation. They do not contact a network or affect files outside their process.

Build on Linux with AddressSanitizer to observe the two intentional memory bugs:

```sh
cc -O1 -g -fsanitize=address -fno-omit-frame-pointer case_stack_overflow.c -o case_stack_overflow
cc -O1 -g -fsanitize=address -fno-omit-frame-pointer case_heap_uaf.c -o case_heap_uaf
cc -O1 -g case_local_impact.c -o case_local_impact
cc -O1 -g case_memory_pressure.c -o case_memory_pressure
```

Send one `!` byte to either sanitizer fixture to trigger its controlled bug.
Other input exits normally. The impact fixture prints `LOCAL_IMPACT_MARKER`
only when stdin is exactly `IMPACT`; all other inputs print `NORMAL_INPUT`.
The programs intentionally contain bugs only to provide reproducible local test
signals and should not be used as production examples.
`case_memory_pressure` touches 768 MiB to exercise the native runner's fixed
512 MiB container memory cap; execute it only through the runner.
