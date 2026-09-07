# Sampled plot endpoints

The native dense root capture showed the last completed request absent from Explore queue and LBA plots. The LBA time range ended at 24603.878063 ms instead of the observed endpoint 24612.691657 ms. The previous index formula selected floor(i * length / limit), which always omitted the final element when sampling.

The shared evenly spaced index helper now spans 0 through length - 1 inclusively when the budget is at least two. Zero/one budgets remain explicit. Operation groups still sample independently, and selected points remain original measurements. A regression covers the physical population 12,388 at both native point budgets (12,000 and 2,000), a two-point budget, and zero/one edge cases. It fails before the change and passes after it.

This endpoint fix alone does not guarantee arbitrary interior extrema or all sparse-gap boundaries survive. Those acceptance dimensions require independent validation and remain open; it must not be described as complete shape-preserving downsampling.
