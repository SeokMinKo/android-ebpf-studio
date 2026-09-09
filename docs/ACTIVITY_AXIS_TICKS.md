# Activity timeline numeric ticks

The 170-point Overview activity plots now choose readable 1/2/5 decimal Y-axis intervals. The previous default logarithmic grid could hide every nonzero label in a 0–65 requests/s range because minor ticks fell below the label-spacing threshold. IOPS and throughput samples, units, filtering and completion-time bins are unchanged.

A renderer regression checks actual egui text shapes: the original plot produced only `0`; the corrected plot must render at least two nonzero numeric ticks. This host renderer test does not substitute for installed-EXE screenshots or physical-device FilePath validation.
