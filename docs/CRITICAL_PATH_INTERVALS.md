# Critical path interval accounting

A syscall can cover both a queue interval and its descendant device interval. Subtracting only the direct queue child from the syscall counted the device interval again in the weighted causal path. Exclusive node time now subtracts the union of all reachable causal descendant intervals, clipped to that node. ContextOnly edges neither form the causal path nor discount exclusive time.

The existing metric remains a longest sum of exclusive causal node weights, not a sum of raw span durations or a claim about unobserved device work. Parallel file-origin branches are not summed together; UIC context nodes remain non-additive.

Regression evidence: a 100 ns syscall enclosing queue [40,50] and descendant device [50,80] returned 130 ns before the fix and now returns 100 ns. A context-only overlapping [20,80] interval previously reduced the 100 ns causal duration to 60 ns; it now leaves 100 ns. The verbatim physical read-log-write fixture has a single 808229 ns syscall enclosing queue/device; its graph now reports 808229 ns once.

The source fix and host tests do not establish installed/native acceptance. The installed 2214 executable remains unchanged until UI work resumes. The physical phone is unavailable.
