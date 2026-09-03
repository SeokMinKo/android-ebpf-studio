# Design

## Data flow

1. Upper-layer typed hook reads `file → inode → super_block` and records `FileIdentity` against the active I/O context/object.
2. Bio hook transfers the identity into a fixed-size `bio -> origin-set` map.
3. `blk_mq_bio_to_request` emits the initial bio origin for a new request; success-only `tp_btf/block_bio_frontmerge|backmerge` hooks emit later merged origins.
4. Agent hashes kernel object correlation values with the session salt and converts origin events into protocol graph facts.
5. Analysis attaches exact origin nodes to the deterministic block request node. Existing heuristic matching runs only when it does not duplicate/compete with exact facts.
6. A path snapshot from a syscall/file hook or `/proc/<pid>/fd` is joined by `FileIdentity`, never used as the exact correlation key.

## Bounded origin set

The wire contract uses one record per origin and an overflow bit. Kernel maps have fixed entry counts, the retained-origin limit is a compile-time constant, and terminal request completion deletes request state. If the set overflows, retained origins remain valid and one final record marks the origin set incomplete.

## Probe strategy

- Mandatory fallback: existing `block_rq_insert/issue/complete` raw tracepoints.
- Preferred exact adapter: fentry/fexit for VFS and bio creation plus success-only BTF merge tracepoints whose signatures provide `struct file`, `struct bio`, and `struct request` identities.
- Attach is trial-based. BTF file existence is only preflight evidence, not proof of load/attach support.
- CO-RE field reads are isolated behind the exact adapter. Failure disables only this adapter and is reported.

## Protocol strategy

Add a backward-compatible `StorageEvent` variant for a request origin rather than overloading heuristic `FileIo`. It carries stable file identity, optional path snapshot, origin classification, byte contribution when known, direct evidence, and bounded-set completeness. Analysis materializes an exact file/bio-origin node and edge to the request node.

## Risks

| Risk | Control |
| --- | --- |
| Android vendor function/signature drift | BTF attach trial and per-probe capability result |
| request/bio pointer reuse | lifecycle deletion, opaque export, timestamps |
| verifier rejects field/loop logic | constant bounds, minimal field reads, phone verifier gate |
| buffered writeback loses original task | inode/page/bio origin is exact for the file, syscall causation stays async/probable |
| one request merges files | fixed-size N-origin set plus overflow signal |
