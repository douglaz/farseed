import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';

// Execute the worker's actual scheduler with a controlled clock and timer queue.
const worker = readFileSync(new URL('../www/worker.js', import.meta.url), 'utf8');
const source = worker.slice(worker.indexOf('let paymentTimer ='), worker.indexOf('const refreshPayments ='));
const run = async ({arm = 59000, fire = 64000, change = '', credit = false, duringCredit = ''} = {}) => {
  let clock = arm, timer, reads = 0, polls = 0;
  const context = vm.createContext({
    Date: {now: () => clock, parse: Date.parse},
    provider_key_is_set: () => true,
    publication_generation: () => 1n,
    setTimeout: (callback, delay) => { assert.equal(delay, 5000); timer = callback; return 1; },
    provider_request: async request => { assert.deepEqual(JSON.parse(request), {action:'payment_check'}); reads++; return '{}'; },
    credit_request: async request => { assert.deepEqual(JSON.parse(request), {action:'poll'}); polls++; vm.runInContext(duringCredit, context); return '{}'; },
    reportStore: async () => {},
    retirementRequested: false,
  });
  vm.runInContext(source + `
    lastReport = {state:'unlocked', lifecycle_state:'running', procurement:{payment:{id:'saved-payment',is_paid:false,expires:'1970-01-01T00:00:00Z'}},credit:{invoices:${credit ? "[{id:'credit-invoice',outcome:'pending',expires_at:120}]" : '[]'}}};
    schedulePayments();`, context);
  assert.equal(typeof timer, 'function');
  const fired = timer; timer = undefined; clock = fire;
  vm.runInContext(change, context);
  await fired();
  return {reads, polls};
};
assert.deepEqual(await run(), {reads:0,polls:0}, 'a timer crossing expiry plus sixty sends nothing');
assert.deepEqual(await run({arm:50000,fire:55000}), {reads:1,polls:0}, 'eligible timer only reads the saved payment');
for (const change of [
  'lastReport.procurement.payment.is_paid = true;',
  "lastReport.procurement.payment.id = 'replacement-payment';",
  'lastReport.procurement.payment = null;',
  'lastReport.procurement.target = {};',
  'retirementRequested = true;',
  'pageVisible = false;',
  "lastReport.state = 'locked';",
  "lastReport.lifecycle_state = 'reconciling';",
  "lastReport.lifecycle_state = 'ended';",
]) assert.equal((await run({arm:50000, fire:55000, change})).reads, 0, change);
for (const duringCredit of [
  'Date.now = () => 64000;',
  'lastReport.procurement.payment.is_paid = true;',
  "lastReport.procurement.payment.id = 'replacement-payment';",
  'retirementRequested = true;',
  'pageVisible = false;',
  "lastReport.lifecycle_state = 'reconciling';",
]) assert.deepEqual(await run({arm:50000,fire:55000,credit:true,duringCredit}), {reads:0,polls:1}, 'machine eligibility is checked again after awaited credit work: '+duringCredit);
console.log('payment scheduler: cutoff, current identity, lifecycle and post-credit dispatch checks passed');


// The paid scheduler and return/Unlock refresh execute the same worker source.
const readinessSource = worker.slice(worker.indexOf('let paymentTimer ='), worker.indexOf('const presentationReport ='));
const makeReady = ({now=100000, paidAt=100, handoff=false, boundary=false}={}) => {
 let clock=now, serial=0, key=true, generation=1n, dispatches=[], timers=new Map(), response, floorUntil=0, held;
 const p={identity:{index:1},phase:'payment_readiness',payment:{id:'paid',is_paid:true},paid_at:paidAt,readiness_poll_seconds:60,readiness_wait_seconds:10800,target:handoff?{}:null};
 const report={state:'unlocked',lifecycle_state:'running',procurement:p};
 const context=vm.createContext({Date:{now:()=>clock,parse:Date.parse},retirementRequested:false,provider_key_is_set:()=>key,provider_action_delay:()=>Math.max(0,floorUntil-clock),publication_generation:()=>generation,
  setTimeout:(callback,delay)=>{const id=++serial;timers.set(id,{callback,delay});return id;},clearTimeout:id=>timers.delete(id),
  provider_request:async request=>{dispatches.push({action:JSON.parse(request).action,at:clock});if(held){const wait=held;held=null;await wait;}return JSON.stringify(response??report);},credit_request:async()=>{throw Error('unexpected credit read');},open:async()=>JSON.stringify(report),
  reportStore:async value=>{vm.runInContext('lastReport = '+value,context);},
 });
 if (boundary) {
  Object.assign(context, {Uint8Array, incarnation:'fixture', poc_key_is_set:()=>true,
   publish_report:async()=>{}, provider_visibility:()=>{},
   lifecycle_transition:async()=>vm.runInContext('JSON.stringify(lastReport)',context),
   unlock:async()=>vm.runInContext('JSON.stringify({...lastReport,state:"unlocked"})',context),
   seed_backup_display:async()=>null, sweep_inference:()=>{}, retry_ended_credit:()=>{}, wake_tasks:()=>{},
  });
  delete context.reportStore;
  const boundarySource=worker.slice(worker.indexOf('let paymentTimer ='),worker.lastIndexOf('await reportStore(await open());'));
  vm.runInContext(boundarySource+';lastReport='+JSON.stringify(report),context);
 } else vm.runInContext(readinessSource+';lastReport='+JSON.stringify(report),context);
 return {context,report,p,dispatches,timers,setClock:value=>clock=value,setGeneration:value=>generation=value,setKey:value=>key=value,setResponse:value=>response=value,setFloor:value=>floorUntil=value,hold:()=>{let release;held=new Promise(resolve=>release=resolve);return release;},
  message:data=>context.onmessage({data:{incarnation:'fixture',generation:String(generation),request:data}}),run:code=>vm.runInContext(code,context),fire:async()=>{assert.equal(timers.size,1,'one readiness timer');const [id,timer]=timers.entries().next().value;timers.delete(id);clock+=timer.delay;await timer.callback();return timer.delay;}};
};
{
 const f=makeReady();f.run('scheduleReadiness()');assert.equal(await f.fire(),1000);assert.deepEqual(f.dispatches.map(d=>d.action),['readiness_check']);
 assert.equal(await f.fire(),60000);assert.equal(f.dispatches[1].at-f.dispatches[0].at,60000,'compiled sixty-second cadence');
 f.run('pageVisible=false;stopReadiness()');assert.equal(f.timers.size,0);await f.run('refreshPayments()');assert.equal(f.dispatches.length,2);
 f.run('pageVisible=true');await f.run('refreshPayments()');assert.equal(f.dispatches.length,3,'one immediate visibility-return read');
 f.run("lastReport.state='locked';stopReadiness()");await f.run('refreshPayments()');assert.equal(f.dispatches.length,3);
 f.run("lastReport.state='unlocked'");f.setKey(false);await f.run('refreshPayments()');assert.equal(f.dispatches.length,3,'keyless Unlock sends nothing');
 f.setKey(true);await f.run('refreshPayments()');assert.equal(f.dispatches.length,4,'one Unlock read once the provider key is held');
 f.setResponse({...f.report,procurement:{...f.p,target:{}}});await f.fire();assert.equal(f.timers.size,0,'Handoff stops readiness');
 assert.ok(f.dispatches.every(d=>d.action==='readiness_check'),'automatic paid traffic never uses full Resume or payment_check');
}
for(const change of ["lastReport.procurement.target={}","lastReport.procurement.phase='terms_changed'","lastReport.procurement.payment=null","pageVisible=false","lastReport.state='locked'","retirementRequested=true","lastReport.lifecycle_state='reconciling'"]){
 const f=makeReady();f.run(change+';scheduleReadiness()');await f.run('refreshPayments()');assert.equal(f.dispatches.length,0,change);
}
{
 const f=makeReady({now:(100+10800)*1000});f.run('scheduleReadiness()');await f.run('refreshPayments()');assert.equal(f.dispatches.length,0,'new worker past durable saved deadline sends nothing');assert.equal(f.timers.size,0);
 const before=makeReady({now:(100+10800)*1000-2000});before.run('scheduleReadiness()');await before.fire();assert.equal(before.dispatches.length,1,'just before durable deadline reads');
 before.setClock((100+10800)*1000+1);await before.fire();assert.equal(before.dispatches.length,1,'deadline crossing timer does not read or save late Handoff');
}
console.log('readiness scheduler: cadence, immediate return/Unlock, inactivity, paid-only traffic and durable deadline passed');

{
 const f=makeReady();const release=f.hold();const pending=f.run('readinessRead()');
 f.run('pageVisible=false;stopReadiness()');f.run('pageVisible=true');await f.run('refreshPayments()');
 assert.equal(f.dispatches.length,1,'return during an in-flight action does not start a second action');
 f.setFloor(100250);release();await pending;
 assert.equal(f.timers.values().next().value.delay,250,'queued return waits only the remaining action floor');
 await f.fire();assert.equal(f.dispatches.length,2,'visibility return is not lost to the sixty-second cadence');
 assert.equal(f.dispatches[1].at-f.dispatches[0].at,250);
}
console.log('in-flight readiness return is queued behind the existing action floor');


{
 const f=makeReady({now:59000});
 f.run("lastReport.procurement.payment={id:'unpaid',is_paid:false,expires:'1970-01-01T00:00:00Z'};schedulePayments()");
 f.setResponse(JSON.parse(f.run('JSON.stringify(lastReport)')));
 f.setClock(120000);await f.fire();
 assert.equal(f.dispatches.length,0,'five-second timer crossing expiry grace sends nothing');
 f.run('pageVisible=false');await f.run('refreshPayments()');assert.equal(f.dispatches.length,0);
 f.run('pageVisible=true');await f.run('refreshPayments()');
 assert.deepEqual(f.dispatches.map(d=>d.action),['payment_check'],'visibility return reconciles the saved unpaid invoice after grace');
 f.run("lastReport.state='locked'");await f.run('refreshPayments()');assert.equal(f.dispatches.length,1);
 f.run("lastReport.state='unlocked'");await f.run('refreshPayments()');
 assert.deepEqual(f.dispatches.map(d=>d.action),['payment_check','payment_check'],'Unlock also reconciles the saved unpaid invoice after grace');
 assert.equal(f.timers.size,0,'one-shot reconciliation does not restart the expired timer');
}
for(const change of ["lastReport.procurement.payment.id='replacement'","lastReport.procurement.payment.is_paid=true","lastReport.procurement.target={}","pageVisible=false","lastReport.state='locked'","lastReport.lifecycle_state='reconciling'","retirementRequested=true"]){
 const f=makeReady({now:120000});
 f.run("lastReport.procurement.payment={id:'unpaid',is_paid:false,expires:'1970-01-01T00:00:00Z'};lastReport.credit={account:true}");
 f.context.credit_request=async()=>{f.run(change);return f.run('JSON.stringify(lastReport)');};
 await f.run('refreshPayments()');
 assert.ok(!f.dispatches.some(d=>d.action==='payment_check'),'return read rechecks saved identity and lifecycle after credit refresh: '+change);
}
console.log('unpaid return/Unlock reconciliation retains its one-shot authority beyond timer expiry');

// Publish the real return/Unlock report before holding credit refresh across the first timer.
for (const wake of ['visible','unlock']) {
 const begin = f => wake==='visible' ? f.message({lifecycle:'visible'}) : f.message({unlock:new Uint8Array(1)});
 const fixture = () => {
  const f=makeReady({boundary:true});
  f.report.credit={account:true};f.run("lastReport.credit={account:true}");
  // Unlock also schedules unrelated zero-delay maintenance; retain the readiness timer only.
  const timeout=f.context.setTimeout;
  f.context.setTimeout=(callback,delay)=>delay===0 ? 0 : timeout(callback,delay);
  let release, entered;
  const creditEntered=new Promise(resolve=>entered=resolve);
  f.context.credit_request=async request=>{
   assert.deepEqual(JSON.parse(request),{action:'refresh'});
   entered();await new Promise(resolve=>release=resolve);
   return f.run('JSON.stringify(lastReport)');
  };
  return {f,begin:()=>begin(f),creditEntered,release:()=>release()};
 };
 {
  const {f,begin,creditEntered,release}=fixture();
  const pending=begin();await creditEntered;
  assert.equal(await f.fire(),1000,'return publication arms the initial readiness timer');
  assert.equal(f.dispatches.length,1);
  f.setFloor(102000);release();await pending;
  assert.equal(f.dispatches.length,1,wake+' credit completion does not duplicate the satisfied wake');
  assert.equal(await f.fire(),60000,wake+' next ordinary read keeps the sixty-second cadence');
  assert.equal(f.dispatches.length,2);
  assert.equal(f.dispatches[1].at-f.dispatches[0].at,60000);
 }
 {
  const {f,begin,creditEntered,release}=fixture();
  const pending=begin();await creditEntered;
  release();await pending;
  assert.equal(f.dispatches.length,1,wake+' fast credit completion reads immediately');
  assert.equal(await f.fire(),60000);
 }
 {
  const {f,begin,creditEntered,release}=fixture();
  let publishEntered,releasePublish;
  const published=new Promise(resolve=>publishEntered=resolve);
  let first=true;
  f.context.publish_report=async()=>{
   if(first){first=false;publishEntered();await new Promise(resolve=>releasePublish=resolve);}
  };
  const pending=begin();await published;
  assert.equal(await f.fire(),1000,'initial timer may read while the wake report publication waits');
  releasePublish();await creditEntered;
  f.setFloor(102000);release();await pending;
  assert.equal(f.dispatches.length,1,wake+' delayed publication and credit share one wake');
  assert.equal(await f.fire(),60000,wake+' delayed publication still preserves sixty-second cadence');
  assert.equal(f.dispatches.length,2);
  assert.equal(f.dispatches[1].at-f.dispatches[0].at,60000);
 }
 for(const change of [
  "lastReport.procurement.identity={index:2}",
  "lastReport.state='locked'",
  "lastReport.lifecycle_state='reconciling'",
  'retirementRequested=true',
  'generation',
  'hide-return',
 ]) {
  const {f,begin,creditEntered,release}=fixture();
  const pending=begin();await creditEntered;
  if(change==='generation')f.setGeneration(2n);
  else if(change==='hide-return'){
   await f.message({lifecycle:'hidden'});
   // A new visibility wake has its own held refresh; do not let the stale wake fulfill it.
   f.context.credit_request=async()=>f.run('JSON.stringify(lastReport)');
   await f.message({lifecycle:'visible'});
  }else f.run(change);
  const before=f.dispatches.length;
  release();await pending;
  assert.equal(f.dispatches.length,before,wake+' stale awaited credit work cannot dispatch: '+change);
 }
}
console.log('real report publication coalesces slow visibility-return/Unlock readiness and fences stale credit work');
