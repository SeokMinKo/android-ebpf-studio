"""Native 43-feature correspondence gate (HW Queue explicitly deferred).

Input: bounded saved Perfetto-projected NDJSON with observed completions on 8:0.
Scalar percentiles, histogram totals, categorical denominators and CSV row counts
are independently checked. This is not a hardware-acquisition acceptance test.
Provide optional scheduler NDJSON fixtures to verify its separate population.
Run with Python 3.10+ and the GUI-enabled desktop executable. Output must be new.
"""
import argparse,pathlib,json,subprocess,sys,csv,math,os
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('exe');parser.add_argument('session');parser.add_argument('output')
parser.add_argument('--scheduler-small');parser.add_argument('--scheduler-large')
parser.add_argument('--case',action='append',help='Run named matrix case(s); explicitly reports a partial sweep')
options=parser.parse_args()
exe=pathlib.Path(options.exe).resolve();real=str(pathlib.Path(options.session).resolve())
out=pathlib.Path(options.output).resolve();out.mkdir(parents=True,exist_ok=False)
repo=pathlib.Path(__file__).resolve().parent.parent
sys.stdout.reconfigure(encoding='utf-8')
P=lambda n:[f'PRESET={n}'];Y=lambda n:[f'Y_AXIS={n}'];cat=lambda c:['SUMMARY_CATEGORIES=1','CATEGORY='+c]
cases={
'overall':P(28),'custom':Y(24),'custom_pie':Y(3)+cat('Chunk size'),'timeline':P(24),'timeline_core':P(26),
'footprint':P(4),'process_footprint':P(4)+['FOOTPRINT=process'],'all_time_footprint':P(23),
'spatial_locality':P(4)+['LOCALITY=1'],'temporal_locality':P(4)+['LOCALITY=1','PANEL_SCROLL=400'],
'overwrite':P(4)+['PANEL_SCROLL=650'],'gantt':P(25),'cmd_data_size':Y(3)+cat('Command / access / size'),
'sequentiality_ratio':Y(3)+cat('Access pattern'),'data_access_trend':P(22),'chunk_length_trend':P(6),
'chunklength_histo':P(6)+['PAIRED_HISTOGRAM=1'],'chunklength_pie':P(6)+cat('Chunk size'),
'latency_trend':P(0),'latency_sort':P(0)+['SUMMARY_CDF=1','SUMMARY_RANK=1'],'latency_histo':P(0),
'latency_anlaysis':Y(6)+['X_AXIS=3'],'1KB_latency_trend':P(10),'1_chunk_latency_anlaysis':Y(15)+['X_AXIS=3'],
'c2c_trend':P(9),'c2c_sorting':P(9)+['SUMMARY_CDF=1','SUMMARY_RANK=1'],
'd2d_trend':P(8),'d2d_sorting':P(8)+['SUMMARY_CDF=1','SUMMARY_RANK=1'],'iowait_trend':P(27),
'bw_trend_c2c':P(18),'bw_histo':P(18),'host_bw_trend':P(19),'bw_trend_timebase':P(12),
'qd_trend':P(7),'qd_sort':P(7)+['SUMMARY_CDF=1','SUMMARY_RANK=1'],
'busytime_trend':P(20),'busytime_histo':P(20),'idletime_trend':P(21),'idle_analysis':P(21)+['PANEL_SCROLL=600'],'idletime_histo':P(21),
'data_table':P(6)+['TABLE_KEYBOARD=1','GESTURE=table-keyboard','RAW_LOG=1'],'show_log':['PAGE=investigate','RAW_LOG=1'],
}
features=json.loads((repo/'docs/UPAS_FEATURE_MATRIX.json').read_text(encoding='utf-8'))
assert set(cases)=={r['id'] for r in features}-{'hw_q_trend'}
source=[json.loads(line) for line in pathlib.Path(real).read_text(encoding='utf-8').splitlines()]
ios=[r['event']['data'] for r in source if r.get('event',{}).get('kind')=='observed_block_completion' and r['event']['data']['issue']['device_minor']==0 and r['event']['data']['issue']['device_major']==8]
scalar={
'Sector':lambda io:io['issue']['sector'],'Chunk (KiB)':lambda io:io['issue']['bytes']/1024,
'Total latency (ms)':lambda io:None if io['total_latency_ns'] is None else io['total_latency_ns']/1e6,
'Device latency (ms)':lambda io:None if io['device_latency_ns'] is None else io['device_latency_ns']/1e6,
'Observed QD at issue (device)':lambda io:io.get('detail_timing',{}).get('issue_depth'),
'C2C completion gap (ms)':lambda io:None if io.get('detail_timing',{}).get('completion_gap_ns') is None else io['detail_timing']['completion_gap_ns']/1e6,
'D2D issue gap (ms)':lambda io:None if io.get('detail_timing',{}).get('issue_gap_ns') is None else io['detail_timing']['issue_gap_ns']/1e6,
'Device latency (ms/KiB)':lambda io:io['device_latency_ns']/1e6/(io['issue']['bytes']/1024) if io['device_latency_ns'] is not None and io['issue']['bytes'] and io['issue']['operation'] in ('read','write') else None,
}
results=[]
def run(name,args,fixture=real,oracle_ios=ios):
    if options.case and name not in options.case:return None
    args=['SESSION='+str(fixture),'SCALE=1',*(['DEVICE_FILTER=8:0'] if fixture==real else []),*args]
    env={k:v for k,v in os.environ.items() if not k.startswith('ANDROID_EBPF_QA_')}
    env.update(ANDROID_EBPF_QA_OUTPUT=str(out/(name+'.png')),ANDROID_EBPF_QA_PAGE='explore')
    for arg in args:
        key,value=arg.split('=',1);env['ANDROID_EBPF_QA_'+key]=value
    with (out/(name+'.log')).open('w',encoding='utf-8') as log:
        p=subprocess.run([str(exe)],env=env,cwd=out,stdout=log,stderr=subprocess.STDOUT,timeout=120)
    assert p.returncode==0,name
    d=json.loads((out/(name+'.json')).read_text(encoding='utf-8'));assert not d['qa_timed_out'],name
    s=d.get('graph_summary')
    if s:
        assert sum(b['count'] for b in s['histogram'])==s['samples'],name
        if s['samples']==0:assert s['p50'] is None,name
        if s.get('cohort_count') is not None:
            rows=list(csv.DictReader((out/(name+'.io.csv')).open(encoding='utf-8')))
            assert len(rows)==s['cohort_count'],name
            metric=s['metric']
            if metric in scalar and 'TABLE_KEYBOARD=1' not in args:
                population=[io for io in oracle_ios if ('FILTER=read' not in args or io['issue']['operation']=='read') and ('FILTER=write' not in args or io['issue']['operation']=='write')]
                vals=sorted(v for io in population if (v:=scalar[metric](io)) is not None)
                assert len(vals)==s['samples'],(name,len(vals),s['samples'])
                for percentile in [50,95]:
                    expected=vals[max(0,math.ceil(len(vals)*percentile/100)-1)] if vals else None
                    actual=s[f'p{percentile}'];assert (actual is None and expected is None) or (actual is not None and math.isclose(actual,expected,rel_tol=1e-10,abs_tol=1e-10)),(name,percentile,actual,expected)
            for dimension,values in s['categories'].items():
                if 'membership' not in dimension:assert sum(v[0] for v in values.values())==s['cohort_count'],(name,dimension)
    if 'TABLE_KEYBOARD=1' in args:assert d['opened_io'] is not None and d['qa_input_step']==7,name
    if 'RAW_LOG=1' in args:
        assert d.get('raw_log',{}).get('loaded'),name
        text=pathlib.Path(d['raw_log']['path']).read_text(encoding='utf-8');assert 'Exact completion record' in text and 'Matched session records: 1.' in text,name
    result={'case':name,'status':'pass','cohort':None if not s else s.get('cohort_count'),'samples':None if not s else s['samples'],'metric':None if not s else s['metric'],'report':str(out/(name+'.json'))}
    results.append(result);print(json.dumps({k:v for k,v in result.items() if k!='report'}),flush=True)
    (out/'full-matrix-results.json').write_text(json.dumps(results,indent=2),encoding='utf-8')
    return d
for name,args in cases.items():run('matrix-'+name,args)
for preset in [0,4,6,7,8,9,10,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,28]:
    for op in ['read','write']:run(f'matrix-p{preset}-{op}',P(preset)+['FILTER='+op])
for axis in range(20,27):
    run(f'matrix-category-{axis}',Y(axis)+['X_AXIS=3'])
for style in ['line','bar']:
    run('matrix-custom-'+style,Y(3)+['X_AXIS=20','GEOMETRY='+style])
for name,fixture in [('small',options.scheduler_small),('large',options.scheduler_large)]:
    if fixture:
        report=run('matrix-scheduler-'+name,P(27),pathlib.Path(fixture).resolve(),[])
        if report is not None:assert report['graph_summary']['samples']>0,name
if options.case:assert {r['case'] for r in results}==set(options.case), 'Unknown or unavailable selected case'
results.append({'feature':'hw_q_trend','status':'deferred by requested scope; preserved HW queue WIP not implemented / not passed'})
(out/'full-matrix-results.json').write_text(json.dumps(results,indent=2),encoding='utf-8')
print('SELECTED CASES COMPLETE (partial sweep)' if options.case else 'FULL MATRIX COMPLETE',flush=True)
