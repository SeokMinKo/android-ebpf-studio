# Tasks — revision 1

| Task | Spec IDs | Dependency | Output / proof | Status |
| --- | --- | --- | --- | --- |
| TSK-001 | REQ-001, REQ-006, REQ-007 | none | New page model/navigation and Overview | in_progress |
| TSK-002 | REQ-002, NFR-001, INV-001 | TSK-001 | Cached unified Investigate view | pending |
| TSK-003 | REQ-003, NFR-001 | TSK-001 | Explorer presets and advanced controls | pending |
| TSK-004 | REQ-004, CON-001 | TSK-001 | Read-only baseline session comparison | pending |
| TSK-005 | REQ-005, INV-001 | TSK-001 | Overview data-quality cards | pending |
| TSK-006 | all | TSK-002..005 | v0.6.0 metadata, CI, merge and release evidence | pending |

Single implementation stream. Planned paths: `crates/desktop/src/app.rs`, version metadata, release workflow, this change directory. Forbidden: protocol schema, collector probes, destructive repository operations.

Behavior test list:

- TST-001 `CHARACTERIZATION`: existing sampling/group helpers stay green.
- TST-002 `NEW_BEHAVIOR`: each Explorer preset maps to its declared axes/group.
- TST-003 `NEW_BEHAVIOR`: comparison delta handles positive, negative and zero baseline.
- TST-004 `PASS_FIRST/inspection`: unified request view stays bounded and cached.

Local Cargo is unavailable in this environment; the first executable proof boundary is GitHub Actions. Static checks and diff validation run locally, and unavailable checks are not reported as passed.

