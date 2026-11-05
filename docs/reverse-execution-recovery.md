# Reverse execution recovery — v1.1

This update adds bounded APK asset extraction and Hermes bytecode inspection,
and repairs execution receipts, prerequisite handling and task message recovery.

## Behavior

- APK entries are selected explicitly, extracted within the owning task, and
  recorded with parent/child hashes. JavaScript and Hermes bytecode take separate
  analysis routes. Archive directory, entry size and path limits apply.
- Hermes supports version-aware static summary, string/function indexes and
  paginated instructions. The bytecode is never executed. Disassembly does not
  recover the original JavaScript or prove server behavior.
- Evidence readers normalize provider wrappers. Workspace responses contain
  conclusion indexes; full conclusions are fetched by ID.
- Completion receipts use stable acceptance IDs. Missing, unknown or duplicate
  IDs and stale evidence are rejected; legacy text receipts remain supported.
  Schema migration preserves operator enable flags, bindings and annotations.
- Failed prerequisites become explicit dependency blockers. Recovery rechecks
  prerequisites before releasing dependent work. This policy is scoped to reverse
  tasks; completed predecessor status alone is not factual evidence.
- Worker prompts expose the effective turn/time budget and saved continuation
  points. Settlement saves existing progress without starting new analysis.
- Static candidates, behavior explanations and verified vulnerabilities remain
  distinct deliverables. Independent review and goal-proof gates remain enabled.
- New evidence references retain result hashes and reject changed content at
  review. Evidence directory roots cannot redirect through symlinks.
- Task streams reconnect with replay cursors, deduplication and heartbeat checks.
  Polling supplements disconnected streams, including the active worker session.

## Optional Hermes engine

On Linux/WSL, install next to the ARTEX executable:

```sh
bash scripts/install-hermes.sh /absolute/path/to/artex/tools/hermes
```

The installer creates an isolated Python environment and verifies the pinned
`hermes-dec==0.1.8` wheel hash. It does not need pip in the system environment.
For another location, set `ARTEX_HERMES_PYTHON` to that environment's Python.
The adapter requires CPU/memory limits and enforces a 30-second timeout and
bounded output. Native Windows execution without those limits is rejected;
the local Windows deployment uses its WSL engine.

## Validation

- Full related-package tests: db, server, collab, the ARTEX/node/relay commands,
  and mcphttp passed in a separate PostgreSQL test cluster.
- The published release source passed targeted agent/db/server regression tests
  for reverse work, acceptance IDs, execution, dependencies, workflow handoffs
  and activity streams. This is not a claim that every repository test passed.
- Static material acceptance parsed a Hermes v94 bundle and successfully queried
  summary, strings, functions and instructions. No APK execution or target
  network request was performed.
- The compiled binary passed HTTP health, tool registration and receipt schema
  checks in an isolated instance. Frontend stream/merge tests passed.

No complete autonomous production task was resumed for this acceptance, so no
end-to-end speed or cost reduction is claimed. Incremental review guidance is
not a new structured claim data model. Unfinished cross-device execution is
outside this release.
