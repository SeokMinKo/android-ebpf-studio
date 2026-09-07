"""Windows native process benchmark: identical inputs, alternating builds.

Build both binaries with the same Rust toolchain/profile; optional native QA
filter_rebuild_ms instrumentation must be present in both. A missing timer is
not a zero-cost filter. Use an idle machine; do not build/run captures concurrently.
The larger fixture should exercise the retained-detail bound (100,000 requests).
The native reports include startup frames: p95 is not a pure steady-state metric.
"""
import argparse,ctypes as c,ctypes.wintypes as w,pathlib,subprocess,json,os,time,statistics,hashlib,sys
parser=argparse.ArgumentParser(description=__doc__)
for arg in ['baseline','feature','real','large','output']:parser.add_argument(arg)
parser.add_argument('--repeats',type=int,default=3)
parser.add_argument('--profile',required=True,help='Exact shared toolchain/build profile and baseline commit')
options=parser.parse_args()
if options.repeats<1:parser.error('repeats must be positive')
out=pathlib.Path(options.output).resolve();out.mkdir(parents=True,exist_ok=False)
executables={key:pathlib.Path(getattr(options,key)).resolve() for key in ['baseline','feature']}
real=str(pathlib.Path(options.real).resolve());large=str(pathlib.Path(options.large).resolve())
class Mem(c.Structure):
    _fields_=[('cb',w.DWORD),('faults',w.DWORD),('peak_rss',c.c_size_t),('rss',c.c_size_t),('peak_paged',c.c_size_t),('paged',c.c_size_t),('peak_nonpaged',c.c_size_t),('nonpaged',c.c_size_t),('pagefile',c.c_size_t),('peak_pagefile',c.c_size_t),('private',c.c_size_t)]
k=c.WinDLL('kernel32',use_last_error=True);papi=c.WinDLL('psapi',use_last_error=True)
k.OpenProcess.argtypes=[w.DWORD,w.BOOL,w.DWORD];k.OpenProcess.restype=w.HANDLE;k.CloseHandle.argtypes=[w.HANDLE]
papi.GetProcessMemoryInfo.argtypes=[w.HANDLE,c.POINTER(Mem),w.DWORD]
results=[]
for dataset,path in [('real',real),('large',large)]:
 for preset in [0,4]:
  for filtered in [False,True]:
   for repeat in range(options.repeats):
    for build in ['baseline','feature']:
     name=f'{build}-{dataset}-p{preset}-{"read" if filtered else "all"}-{repeat}';exe=executables[build]
     env={k:v for k,v in os.environ.items() if not k.startswith("ANDROID_EBPF_QA_")};env.update(ANDROID_EBPF_QA_SESSION=path,ANDROID_EBPF_QA_PAGE='explore',ANDROID_EBPF_QA_OUTPUT=str(out/(name+'.png')),ANDROID_EBPF_QA_SCALE='1',ANDROID_EBPF_QA_PRESET=str(preset))
     if filtered:env['ANDROID_EBPF_QA_FILTER']='read'
     started=time.perf_counter();peak_rss=peak_private=0
     with (out/(name+'.log')).open('w') as log:
      process=subprocess.Popen([str(exe)],env=env,cwd=out,stdout=log,stderr=subprocess.STDOUT)
      handle=k.OpenProcess(0x410,False,process.pid)
      try:
       while process.poll() is None:
        info=Mem();info.cb=c.sizeof(info)
        if papi.GetProcessMemoryInfo(handle,c.byref(info),c.sizeof(info)):peak_rss=max(peak_rss,info.rss);peak_private=max(peak_private,info.private)
        if time.perf_counter()-started>180:process.terminate();raise RuntimeError('timeout '+name)
        time.sleep(.025)
      finally:k.CloseHandle(handle)
     assert process.returncode==0,name
     d=json.loads((out/(name+'.json')).read_text(encoding='utf-8'));assert not d.get('qa_timed_out'),name
     if filtered:assert d.get('filter_rebuild_ms'), 'Both builds need filter timing instrumentation: '+name
     row={'case':name,'build':build,'dataset':dataset,'preset':preset,'read':filtered,'repeat':repeat,'load_ms':d['reanalysis_ms'],'filter_ms':max(d.get('filter_rebuild_ms',[0]) or [0]),'plot_rebuild_ms':d['ui_performance']['explorer_rebuild']['max_ms'],'ui_p50_ms':d['ui_performance']['ui_update']['p50_ms'],'ui_p95_ms':d['ui_performance']['ui_update']['p95_ms'],'peak_rss_mib':peak_rss/1048576,'peak_private_mib':peak_private/1048576,'wall_s':time.perf_counter()-started,'retained':d['completed_requests']}
     results.append(row);print(json.dumps(row),flush=True);(out/'results.json').write_text(json.dumps(results,indent=2),encoding='utf-8')
summary=[]
for dataset in ['real','large']:
 for preset in [0,4]:
  for filtered in [False,True]:
   row={'dataset':dataset,'preset':preset,'read':filtered}
   for build in ['baseline','feature']:
    group=[r for r in results if r['build']==build and r['dataset']==dataset and r['preset']==preset and r['read']==filtered]
    row[build]={key:statistics.median(r[key] for r in group) for key in ['load_ms','filter_ms','plot_rebuild_ms','ui_p50_ms','ui_p95_ms','peak_rss_mib','peak_private_mib','wall_s']}
   summary.append(row)
(out/'comparison.json').write_text(json.dumps({'profile':options.profile,'repeats':options.repeats,'memory_scope':'whole-process sampled peak, including QA screenshot/CSV export; not idle-only memory','executables':{k:{'path':str(p),'sha256':hashlib.file_digest(p.open('rb'),'sha256').hexdigest()} for k,p in executables.items()},'input_sha256':hashlib.file_digest(pathlib.Path(large).open('rb'),'sha256').hexdigest(),'comparisons':summary},indent=2),encoding='utf-8')
