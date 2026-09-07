# Windows native renderer

Windows uses eframe WGPU with D3D12. Other platforms retain Glow. This avoids the observed Windows OpenGL startup path without modifying system graphics drivers.

A second-chance native debug capture of the previously installed ebb655a build, with the 3-event known-read-tooltip fixture, recorded access violation 0xc0000005 in C:/Windows/System32/ControlLib.dll at module offset 0xc856. DLL version 1.0.127.0 and SHA256 8ca3a921e11a26dd2e80ab1d50022f996501aa38a1252f075a5502c8f8ea751f were recorded. The process exited after about 1.9 seconds, so dense attribution work is not required to reproduce this startup fault. A crash dump and diagnosis are retained in the acceptance evidence native-fast-debug/launch-1.

A normal six-launch sweep of the earlier renderer failed once; debugger timing could mask the problem. Initial D3D12 release-build launches passed six times. Installed-binary acceptance must be performed separately and finite repeated launches do not prove universal driver compatibility.
