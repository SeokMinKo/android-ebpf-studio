# UI refinement contract
Existing product: Rust egui, English labels, Light/Dark/High Contrast; preserve analytical semantics. Source baseline 0bf5753, installed baseline 2214e827.

Primary task: inspect LBA I/O, select a request or area, then read its evidence.
- Graph controls remain visible; rare appearance and range controls share one Plot settings disclosure. The graph starts higher without changing values.
- Controls use a consistent 28 px minimum height and 8 px horizontal gaps; wrapping remains available at narrow widths. Inspector actions and tabs align to its left edge.
- Remove duplicate selection cancellation; keep the explicit Clear selection next to Select/Pan. Empty selection has a short action prompt and accessible expandable semantics.

Authority: existing theme and source components; no new visual language or data encodings. Normal and selected real saved-session views, all three themes, and a narrow viewport require native render review. Physical device unavailable; no physical revalidation claimed.
