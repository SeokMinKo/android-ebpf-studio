import fs from 'node:fs';
import cp from 'node:child_process';
import path from 'node:path';
const [rustc,linker,out]=process.argv.slice(2);
fs.mkdirSync(out,{recursive:true});
const source=fs.readFileSync('crates/android-ebpf/src/main.rs','utf8');
const types=fs.readFileSync('crates/ebpf-types/src/lib.rs','utf8');
const struct=name=>'#[derive(Clone, Copy, Default)]\n'+types.match(new RegExp('pub struct '+name+' \\{[\\s\\S]*?\\n\\}'))[0];
const enter=source.slice(source.indexOf('fn capture_sys_enter('),source.indexOf('// Snapshot identity at syscall entry')).trim();
let exit=source.slice(source.indexOf('fn capture_sys_exit('),source.indexOf('    let config = active_filter()',source.indexOf('fn capture_sys_exit(')));
exit+='    Ok(return_value as u32)\n}\n';
const mocks=[
'#![allow(dead_code, unused_variables, unused_unsafe)]',
'use std::cell::RefCell;',
struct('FileStart'),struct('RawSyscallLayout'),
'struct TracePointContext { id:i64, ret:i64 }',
'struct Layout; static RAW_SYSCALL_LAYOUT:Layout=Layout;',
"impl Layout { fn get(&self,_:u32)->Option<&'static RawSyscallLayout> { Some(Box::leak(Box::new(RawSyscallLayout { enter_id_offset:8,enter_args_offset:16,exit_ret_offset:24,..Default::default() }))) } }",
'thread_local! { static PENDING:RefCell<Option<FileStart>>=const {RefCell::new(None)}; static ALLOW:RefCell<bool>=const {RefCell::new(true)}; }',
'struct Starts; static FILE_STARTS:Starts=Starts;',
'impl Starts {',
"fn get(&self,_:&u64)->Option<&'static FileStart> { PENDING.with(|p|p.borrow().map(|v|&*Box::leak(Box::new(v)))) }",
'fn insert(&self,_:&u64,v:&FileStart,_:u64)->Result<(),i32>{PENDING.with(|p|*p.borrow_mut()=Some(*v));Ok(())}',
'fn remove(&self,_:&u64)->Result<(),i32>{PENDING.with(|p|*p.borrow_mut()=None);Ok(())} }',
'fn read_i64(c:&TracePointContext,o:u16)->Result<i64,i32>{Ok(if o==24 {c.ret} else if o==16 {7} else {c.id})}',
'fn read_u64_at(_: &TracePointContext,_:usize)->Result<u64,i32>{Ok(4096)}',
'fn bpf_get_current_pid_tgid()->u64{23447}',
'fn bpf_get_current_uid_gid()->u64{0}',
'fn bpf_get_current_comm()->Result<[u8;16],i32>{Ok([0;16])}',
'fn bpf_ktime_get_ns()->u64{86413988037919}',
'fn syscall_fd_identity(_:i32)->Result<(u64,u32,u32,u64),i32>{Ok((14601,1,0,3932160))}',
'fn matches_filter(_:u32,_:u32,_:u32,_:u32,_:u32,_:u8)->bool{ALLOW.with(|a|*a.borrow())}',
'const OP_READ:u8=1; const OP_WRITE:u8=2;',
enter,exit,
'fn enter(id:i64){capture_sys_enter(TracePointContext{id,ret:0}).unwrap();}',
'fn exit(id:i64,ret:i64)->Result<u32,i32>{capture_sys_exit(TracePointContext{id,ret})}',
'#[test] fn rejects_other_syscall_exit_after_lost_read_exit(){enter(63); assert_ne!(exit(101,777),Ok(777)); assert!(FILE_STARTS.get(&23447).is_none());}',
'#[test] fn clears_stale_read_on_untracked_entry(){enter(63);enter(101);assert!(FILE_STARTS.get(&23447).is_none());}',
'#[test] fn clears_stale_read_on_filtered_entry(){enter(63);ALLOW.with(|a|*a.borrow_mut()=false);enter(63);assert!(FILE_STARTS.get(&23447).is_none());}',
'#[test] fn preserves_matching_read_completion(){enter(63);assert_eq!(exit(63,4096),Ok(4096));assert!(FILE_STARTS.get(&23447).is_none());}',
'#[test] fn distinguishes_read_from_pread(){enter(63);assert_ne!(exit(67,777),Ok(777));}'
].join('\n');
const src=path.join(out,'actual-syscall-harness.rs'),exe=path.join(out,'actual-syscall-harness.exe');
fs.writeFileSync(src,mocks);
const b=cp.spawnSync(rustc,['--edition=2024','--test',src,'-C','linker='+linker,'-o',exe],{encoding:'utf8',windowsHide:true});
if(b.status!==0){console.error(b.stdout,b.stderr);process.exit(b.status??1);}
const r=cp.spawnSync(exe,[],{encoding:'utf8',windowsHide:true});
console.log(r.stdout);console.error(r.stderr);process.exit(r.status??1);
