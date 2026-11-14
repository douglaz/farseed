import {createServer} from 'node:http';
import assert from 'node:assert/strict';
import {readFile, mkdtemp, rm} from 'node:fs/promises';
import {spawn, spawnSync} from 'node:child_process';
import {once} from 'node:events';
import {createInterface} from 'node:readline';
import {join} from 'node:path';
import {createHash} from 'node:crypto';
import {layoutCases, layoutObserver, fixtureLayout, publicKeysLayout} from './layout-page.mjs';
import {creditCases, creditId, fixtureCredit, creditProof} from './credit-page.mjs';

async function resumeProof(c) {
 const {name,info,inferenceEndpoint,call,sessionId,evaluate,invoke,wait,click,message,hold,point,release,configure,check,control,observerSource,pageOrigin}=c;
 const observe=async state=>{if(layoutCases.includes(name))await layoutObserver(c,state);};
 const normal='normal-synthetic-key-482700';
 const relayReady=()=>new Promise(resolve=>setTimeout(resolve,info.relay_spacing_ms+50));
 const journal=async()=>{
  await evaluate('fixtureEvents=fixtureEvents.filter(e=>!e.fixture_journal)');
  await message({fixture:{journal:''}});
  return wait('fixtureEvents.find(e=>e.fixture_journal)?.fixture_journal');
 };
 const reopen=async(kind='reload')=>{
  if(kind==='lock') await click('#tau-lock');
  else {
   if(kind==='loss') await evaluate('fixtureWorkers.at(-1).terminate()');
   await call('Page.reload',{},sessionId);
  }
  await wait("document.querySelector('#tau-store')?.dataset.state==='locked'");
  await relayReady();
  await invoke(()=>{document.querySelector('#tau-passphrase').value='durable fixture passphrase';document.querySelector('#tau-unlock').click();});
  await wait("fixtureReports.at(-1)?.store_state==='unlocked' && fixtureReports.at(-1)?.tasks?.length===1");
 };
 await call('Page.navigate',{url:pageOrigin+'/'},sessionId);
 await wait("document.querySelector('#tau-store')?.dataset.state==='none'");
 await observe('none');
 await invoke(()=>{document.querySelector('#tau-passphrase').value=document.querySelector('#tau-confirm').value='durable fixture passphrase';document.querySelector('#tau-create').click();});
 await wait("!document.querySelector('#tau-seed-backup-answer').disabled");
 await click('#tau-seed-backup-answer');await wait("!document.querySelector('#tau-seed-backup-skip').disabled");await click('#tau-seed-backup-skip');
 await wait("!document.querySelector('#tau-poc-inference-form button').disabled");
 await observe('unlocked');
 await configure(normal);await wait("fixtureReports.at(-1)?.poc_configuration?.key_set");
 await invoke(info=>{for(const [id,value]of Object.entries({machine:'machine-a',relay:info.relay,profile:'v1',host:'127.0.0.1',port:info.port,user:'tracer',elevation:'none',pin:info.pin,class:'no'}))document.querySelector('#tau-poc-'+id).value=value;document.querySelector('#tau-poc-approve-existing').checked=document.querySelector('#tau-poc-approve-access').checked=true;document.querySelector('#tau-poc-target-form').requestSubmit();},info);
 await wait('fixtureReports.at(-1)?.poc_targets?.length===1');
 await observe('before-start');
 await invoke(()=>[...document.querySelectorAll('#tau-poc-targets button')].find(b=>b.textContent==='Show public keys machine-a').click());
 const keys=await wait('fixtureReports.at(-1)?.poc_keys');check((await control({keys})).installed,'original public identities installed in loopback relay and machine');
 const command=`while [ ! -f '${info.directory}/continue' ]; do sleep 0.1; done; printf installed`+(layoutCases.includes(name)?' #'+ 'x'.repeat(1200):'');
 await control({inference:{key:normal,commands:name==='start-defaults'?[...Array(11).fill(`sleep ${info.relay_spacing_ms/1000+0.05}; true`),null]:[command,null,...(name==='resume-freeze'?[null]:[])]}});
 if(name==='resume-stale-fetch') await hold('poc_inference_writer');
 if(name==='start-interruption')await hold('poc_start_committed');
 if(name==='start-defaults'){const before=await journal();await message({poc_bind:{machine:'machine-a',goal:'Another goal',checks:[],document_source:null,unexpected:true}});check((await journal()).records===before.records&&await evaluate('fixtureReports.at(-1).sessions.length===0'),'malformed Start retains strict admission without records');}
 await invoke(checks=>{document.querySelector('#tau-poc-targets [data-start-goal]').value='Install and check a small service';document.querySelector('#tau-poc-targets [data-start-checks]').value=checks;[...document.querySelectorAll('#tau-poc-targets button')].find(b=>b.textContent==='Start session machine-a').click();},startCases.includes(name)?'true':layoutCases.includes(name)?`test -f '${info.directory}/'$(printf '\\166\\145\\162\\151\\146\\151\\145\\144')`:`test -f '${info.directory}/verified'`);
 if(name==='start-interruption') {
  await point('poc_start_committed');await reopen('loss');
  const saved=await evaluate('fixtureReports.at(-1).tasks[0]');
  check(saved.checks.length===1&&saved.checks[0]==='true'&&saved.limits.requests===100&&saved.limits.steps===200,'lost Start reply replays original checks and limits');
  check(await evaluate("fixtureReports.at(-1).mode_acceptances.some(a=>a.session===fixtureReports.at(-1).tasks[0].start_session&&a.mode==='Acting on a goal with no brief')"),'lost Start reply replays committed no-brief acceptance');
  await configure(normal);await wait("document.querySelector('[data-requirements-decision=approve]')");
  const recovered=await control({inspect:true});
  check(recovered.inference_requests===1&&recovered.launches.length===0,'interrupted Start resumes its accepted request and proposes the missing machine declaration before any command');
  check(await evaluate(`fixtureReports.at(-1).tasks.length===1&&fixtureReports.at(-1).tasks[0].id===${JSON.stringify(saved.id)}`),'interrupted Start retains the same task and session');
  check((await control({inspect:true})).launches.length===0,'declaration approval stays explicit after interrupted Start');
  return;
 }
 await wait('fixtureReports.at(-1)?.tasks?.[0]?.pause_reason');
 if(name==='start-defaults') {
  const before=await journal();const original=await evaluate('fixtureReports.at(-1).tasks[0]');
  await invoke(()=>{document.querySelector('#tau-poc-targets [data-start-goal]').value='Another goal';document.querySelector('#tau-poc-targets [data-start-checks]').value='false';[...document.querySelectorAll('#tau-poc-targets button')].find(b=>b.textContent==='Start session machine-a').click();});
  await wait('fixtureReports.at(-1)?.tasks?.length===1');
  check((await journal()).records===before.records&&await evaluate(`JSON.stringify(fixtureReports.at(-1).tasks[0])===${JSON.stringify(JSON.stringify(original))}`),'repeated Start preserves original task, goal, checks and acceptance without another record');
 }
 const session=await evaluate('fixtureReports.at(-1).sessions[0].identity');
 await observe('session');
 check(await evaluate("document.querySelector('#tau-poc-targets').textContent.includes('model-a')"),'Start session displays admitted model and machine');
 await wait("document.querySelector('[data-poc-propose]')");await click('[data-poc-propose]');
 await wait("document.querySelector('[data-requirements-decision=\"approve\"]')");
 await observe('requirements');
 if(name==='start-approval') {
  const before=await evaluate('JSON.stringify(fixtureReports.at(-1).tasks)');
  await click('[data-requirements-decision="reject"]');await wait("!document.querySelector('[data-requirements-decision=approve]')");
  check(await evaluate(`JSON.stringify(fixtureReports.at(-1).tasks)===${JSON.stringify(before)}`),'Reject wakes no task');
  await message({fixture:{approval_neighbor:true}});await wait('fixtureEvents.some(e=>e.fixture_neighbor)');
  await evaluate("window.fixtureNeighbor=fixtureReports.at(-1).tasks.find(task=>task.machine==='machine-b');window.fixtureSentinel=fixtureReports.at(-1).tasks.find(task=>task.machine==='machine-c')");
  check(await evaluate("fixtureSentinel.status==='running' && !fixtureSentinel.pause_reason"),'independent sentinel is eligible for an overbroad wake');
  await hold('poc_automatic_resume_'+await evaluate('fixtureSentinel.id'));
  await release('poc_automatic_resume_'+await evaluate('fixtureSentinel.id'));
  await click(`[data-poc-propose="${session}"]`);await wait("document.querySelector('[data-requirements-decision=approve]')");
 }
 if(name==='start-approval-configuration') {
  const edited=inferenceEndpoint.replace(/:(\d+)\//, ':0$1/');
  await invoke(values=>{document.querySelector('#tau-poc-endpoint').value=values.endpoint;document.querySelector('#tau-poc-model').value='model-a';document.querySelector('#tau-poc-key').value=values.key;document.querySelector('#tau-poc-inference-form').requestSubmit();},{endpoint:edited,key:normal});
  await wait(`fixtureReports.at(-1)?.poc_configuration?.configuration?.endpoint===${JSON.stringify(edited)}`);
  const before=await evaluate('fixtureReports.at(-1).tasks[0]');
  const actions=await evaluate("fixtureEvents.filter(e=>e.fixture_action==='requirements').length");
  await click('[data-requirements-decision="approve"]');
  await wait(`fixtureEvents.filter(e=>e.fixture_action==='requirements').length>${actions}`);
  check(await evaluate(`fixtureReports.at(-1).tasks[0].requests===${before.requests} && fixtureReports.at(-1).store_error.includes('automatic continuation waits for the admitted endpoint')`),'approval preserves automatic configuration admission without consuming a request');
  check((await control({inspect:true})).inference_requests===0,'approval sends nothing to the changed endpoint');
  await invoke(()=>[...document.querySelectorAll('[data-task] button')].find(b=>b.textContent==='Resume').click());
  await wait('fixtureReports.at(-1)?.tasks?.[0]?.pending');
  check((await control({inspect:true})).inference_requests===1,'explicit Resume retains authority to use displayed configuration');
  await relayReady();await control({release:true});await wait("fixtureReports.at(-1)?.tasks?.[0]?.status==='complete'");
  return;
 }
 if(name==='resume-approval') {
  for(const decision of ['approve','reject']) {
   await hold('requirements_writer');
   const receivedBefore=await journal();
   const pendingBefore=await evaluate('JSON.stringify(fixtureReports.at(-1).sessions[0].pending_requirements)');
   const completedBefore=await evaluate('fixtureEvents.filter(e=>e.fixture_action===\'requirements\').length');
   await click(`[data-requirements-decision="${decision}"]`);await point('requirements_writer');
   await message({lifecycle:'freeze'});await wait("fixtureReports.at(-1)?.lifecycle_state==='reconciling'");
   await message({lifecycle:'resume'});await wait("fixtureReports.at(-1)?.lifecycle_state==='running'");
   await release('requirements_writer');
   await wait(`fixtureEvents.filter(e=>e.fixture_action==='requirements').length>${completedBefore}`);
   check((await journal()).records===receivedBefore.records && await evaluate('JSON.stringify(fixtureReports.at(-1).sessions[0].pending_requirements)')===pendingBefore,`received ${decision} retired while waiting consumes neither a record nor the pending candidate`);
   await evaluate('fixtureEvents=fixtureEvents.filter(e=>e.fixture_point!==\'requirements_writer\')');
  }
  await evaluate('window.oldApproval=document.querySelector(\'[data-requirements-decision="approve"]\')');
  const before=await journal();
  const budget=await evaluate('fixtureReports.at(-1).tasks[0].requests');
  await message({lifecycle:'freeze'});await wait("fixtureReports.at(-1)?.lifecycle_state==='reconciling'");
  await message({lifecycle:'resume'});await wait("fixtureReports.at(-1)?.lifecycle_state==='running'");
  await evaluate('oldApproval.click()');
  const after=await journal();
  check(after.records===before.records,'an approval rendered before freeze cannot append after revalidation');
  check(await evaluate(`fixtureReports.at(-1).sessions[0].pending_requirements && fixtureReports.at(-1).tasks[0].requests===${budget}`),'uncommitted approval and genuine pause remain pending without request consumption');
  await evaluate(`window.retiredApproval=document.querySelector('[data-requirements-decision="approve"]')`);
  await reopen('lock');
  const retired=await journal();
  await evaluate('retiredApproval.click()');
  check((await journal()).records===retired.records,'an approval rendered by a retired worker cannot append in its replacement');
  check(await evaluate(`fixtureReports.at(-1).tasks[0].status==='paused' && fixtureReports.at(-1).tasks[0].requests===${budget}`),'replacement preserves the genuine approval pause');
  check(await evaluate('!fixtureReports.at(-1).sessions[0].pending_requirements'),'uncommitted approval is absent after retirement');
  await configure(normal);await wait('fixtureReports.at(-1)?.poc_configuration?.key_set');
  await click('[data-poc-propose]');
  await wait("document.querySelector('[data-requirements-decision=\"approve\"]')");
  const beforeQueued=await journal();
  const paused=await evaluate('fixtureReports.at(-1).tasks[0]');
  const resumes=await evaluate('fixtureEvents.filter(e=>e.fixture_action===\'resume\').length');
  await hold('poc_inference_writer');
  await hold('requirements_committed');
  await click('[data-requirements-decision="approve"]');await point('requirements_committed');
  await message({task:{action:'resume',id:paused.id,session}});
  await message({lifecycle:'freeze'});await message({lifecycle:'resume'});
  await release('requirements_committed');
  await wait(`fixtureReports.at(-1)?.lifecycle_state==='running' && (fixtureEvents.filter(e=>e.fixture_action==='resume').length>${resumes} || fixtureReports.at(-1)?.tasks?.[0]?.requests>${paused.requests})`);
  await point('poc_inference_writer');
  const afterQueued=await journal();
  const activated={...paused,status:'running',pause_reason:null,revision:beforeQueued.records};
  check(await evaluate(`JSON.stringify(fixtureReports.at(-1).tasks[0])===${JSON.stringify(JSON.stringify(activated))}`),'committed approval activates its task; retired queued Resume leaves its budget and work unchanged');
  check(afterQueued.records===beforeQueued.records+2 && afterQueued.poc_requests===beforeQueued.poc_requests+1 && afterQueued.poc_pauses===beforeQueued.poc_pauses,'approval and its one fresh Request append; retired Resume appends no extra Request, proposal or Pause');
  const queuedEffects=await control({inspect:true});
  check(queuedEffects.inference_requests===0 && queuedEffects.contacts===0 && queuedEffects.launches.length===0,'retired Resume makes no inference or relay contact');
  await release('poc_inference_writer');
 }
 if(pendingCases.includes(name)) await hold('pending_launch_committed');
 if(name!=='resume-approval') await click('[data-requirements-decision="approve"]');
 await wait("!document.querySelector('[data-requirements-decision=\"approve\"]')");

 if(name==='start-approval') {
  await wait("fixtureReports.at(-1)?.tasks?.find(task=>task.machine==='machine-a')?.pending");
  check(await evaluate("JSON.stringify(fixtureReports.at(-1).tasks.find(task=>task.machine==='machine-b'))===JSON.stringify(fixtureNeighbor)"),'Approve resumes exactly its own declaration-paused task');
  check(await evaluate("[...document.querySelectorAll('[data-task=\"'+fixtureNeighbor.id+'\"] button')].some(button=>button.textContent==='Resume')"),'independent paused task retains Resume');
  await relayReady();await control({release:true});await wait("fixtureReports.at(-1)?.tasks?.find(task=>task.machine==='machine-a')?.status==='complete'");
  check(await evaluate("JSON.stringify(fixtureReports.at(-1).tasks.find(task=>task.machine==='machine-b'))===JSON.stringify(fixtureNeighbor)"),'other pause and budget remain unchanged through completion');
  check(await evaluate("JSON.stringify(fixtureReports.at(-1).tasks.find(task=>task.machine==='machine-c'))===JSON.stringify(fixtureSentinel) && !fixtureEvents.some(e=>e.fixture_point==='poc_automatic_resume_'+fixtureSentinel.id)"),'approval never invokes the independent eligible sentinel');
  return;
 }
 if(name==='start-defaults') {
  await wait("fixtureReports.at(-1)?.tasks?.[0]?.status==='complete'");
  const task=await evaluate('fixtureReports.at(-1).tasks[0]');
  check(task.requests===12 && task.steps===13 && task.limits.requests===100 && task.limits.steps===200,'one Start and requirements approval complete beyond the former ten-request allowance');
  check(await evaluate("!document.querySelector('[data-goal-accept]') && fixtureReports.at(-1).tasks.length===1 && fixtureReports.at(-1).mode_acceptances.some(a=>a.session===fixtureReports.at(-1).tasks[0].start_session)"),'durable acceptance and one task without a separate no-brief press');
  const snapshots=await evaluate('fixtureEvents.filter(e=>e.fixture_model_admission).map(e=>e.fixture_model_admission)');
  check(snapshots.length===12 && snapshots.every(s=>s.accepted),'acceptance is committed before every loopback model request');
  return;
 }
 if(pendingCases.includes(name)) {
  await pendingProof({...c, session, reopen, journal, relayReady, normal});
  return;
 }
 if(name==='resume-stale-fetch') {
  await point('poc_inference_writer');
  const beforeEnd=await journal();
  const beforeEndActions=await evaluate('fixtureEvents.filter(e=>e.fixture_action_complete).length');
  await click('[data-end-session]');await wait('fixtureReports.at(-1)?.sessions?.[0]?.session_state===\'ended\'');
  await wait(`fixtureEvents.filter(e=>e.fixture_action_complete).length>${beforeEndActions}`);
  const beforeReturnActions=await evaluate('fixtureEvents.filter(e=>e.fixture_action_complete).length');
  await release('poc_inference_writer');
  await wait(`fixtureEvents.filter(e=>e.fixture_action_complete).length>${beforeReturnActions}`);
  check((await control({inspect:true})).inference_requests===0,'original-session check refuses a direct fetch queued before End');
  check((await journal()).poc_pauses===beforeEnd.poc_pauses,'ended invocation appends no late Pause');
  await reopen();
  check(await evaluate('fixtureReports.at(-1).sessions[0].session_state===\'ended\''),'End survives reopen without inference credentials');
  return;
 }
 await wait('fixtureReports.at(-1)?.tasks?.[0]?.pending');
 await observe('running');
 const original=await evaluate('fixtureReports.at(-1).tasks[0]');
 const job=original.pending.job;
 check(original.start_session===session && original.machine==='machine-a','original session, task and binding own the pending job');
 let launched;
 for(let n=0;n<200;n++) {
  launched=await control({inspect:true});
  if(launched.launches.some(j=>j.job===job))break;
  await new Promise(resolve=>setTimeout(resolve,25));
 }
 check(launched.launches.length===1 && launched.launches[0].job===job,'one original remote launch');
 check(await evaluate("document.querySelectorAll('[data-pending-assumption]').length===0"),'running work offers no pending assumption');
 if(name==='resume-end') {
  await click('[data-end-session]');await wait("fixtureReports.at(-1)?.sessions?.[0]?.session_state==='ended'");
  let stopped;
  for(let n=0;n<200;n++) {
   stopped=await control({inspect:true});
   if(stopped.ssh_ends===stopped.ssh_connections)break;
   await new Promise(resolve=>setTimeout(resolve,25));
  }
  check(stopped.ssh_ends===stopped.ssh_connections,'durable selected End closes the active browser transport');
  check(stopped.launches.length===1 && stopped.inference_requests===1,'End does not repeat the accepted job or request more inference');
  await reopen();
  check(await evaluate('fixtureReports.at(-1).sessions[0].session_state===\'ended\' && fixtureReports.at(-1).tasks[0].pending!==null'),'replay preserves End and the unresolved remote-job history without keys');
  await control({release:true});
  return;
 }
 let other;
 if(name==='resume-append') {
  await hold('poc_end_committed');
  await click('[data-end-session]');await point('poc_end_committed');
  await evaluate('window.retiringWorker=fixtureWorkers.at(-1)');
  await invoke(()=>{window.fixtureLockErrors=[];addEventListener('error',event=>fixtureLockErrors.push(event.message));document.dispatchEvent(new Event('freeze'));});
  await click('#tau-lock');await wait("document.querySelector('#tau-store')?.dataset.state==='locking'");
  await invoke(()=>document.dispatchEvent(new Event('resume')));
  check(await evaluate("fixtureLockErrors.length===0 && document.querySelector('#tau-store')?.dataset.state==='locking'"),'resume during retirement keeps the held writer and visible locking without a page error');
  await evaluate('new Promise(resolve=>setTimeout(resolve,5500))');
  check(await evaluate("!retiringWorker.fixtureTerminated && document.querySelector('#tau-store-explanation').textContent.includes('finishes a write')"),'Lock waits visibly past the explanation bound without terminating a held append');
  const target=await call('Target.createTarget',{url:'about:blank'});
  const attached=await call('Target.attachToTarget',{targetId:target.targetId,flatten:true});
  other={...target,...attached};
  await call('Page.enable',{},other.sessionId);
  await call('Page.addScriptToEvaluateOnNewDocument',{source:observerSource},other.sessionId);
  await call('Page.navigate',{url:pageOrigin+'/'},other.sessionId);
  const otherEval=async expression=>{
   const result=await call('Runtime.evaluate',{expression,awaitPromise:true,returnByValue:true},other.sessionId);
   if(result.exceptionDetails)throw Error(result.exceptionDetails.exception?.description??'second tab exception');
   return result.result.value;
  };
  const otherWait=expression=>otherEval(`new Promise((resolve,reject)=>{const start=performance.now();const poll=async()=>{try{if(${expression})return resolve(true);if(performance.now()-start>60000)return reject(Error('second tab wait'));setTimeout(poll,25);}catch(error){reject(error);}};poll();})`);
  await otherWait("document.querySelector('#tau-store')?.dataset.state==='in-use'");
  check(true,'second tab waits for the original exclusive writer during a begun append');
  await otherEval("window.waitingWorker=fixtureWorkers.at(-1);dispatchEvent(new Event('pagehide'))");
  await otherWait("document.querySelector('#tau-store')?.dataset.state==='locking' || waitingWorker.fixtureTerminated");
  await otherWait('waitingWorker.fixtureTerminated===true');
  check(await otherEval('waitingWorker.fixtureTerminated===true && fixtureEvents.some(e=>e.runtime_retired===true)'),'a waiting worker accepts retirement and acknowledges before termination without becoming an orphan writer');
  // Queue this tab's replacement before the first tab can automatically reopen and compete.
  await otherWait("fixtureWorkers.at(-1)!==waitingWorker && document.querySelector('#tau-store')?.dataset.state==='in-use' && (await navigator.locks.query()).pending.some(lock=>lock.name==='tau-web-store')");
  check(true,'current replacement queues behind the still-held predecessor append');
  await release('poc_end_committed');
  await otherWait("document.querySelector('#tau-store')?.dataset.state==='locked'");
  await otherEval("document.querySelector('#tau-passphrase').value='durable fixture passphrase';document.querySelector('#tau-unlock').click()");
  await otherWait("fixtureReports.at(-1)?.sessions?.[0]?.session_state==='ended'");
  check(await evaluate('retiringWorker.fixtureTerminated===true'),'successor acquires only after retirement acknowledgement and confirmed termination');
  check((await control({inspect:true})).launches.filter(j=>j.job===job).length===1,'held End neither repeats nor cancels the original remote job');
  await control({release:true});
  await call('Target.closeTarget',{targetId:other.targetId});
  return;
 }
 if(['resume-lock','resume-reload','resume-loss','resume-configuration'].includes(name)) {
  await reopen(name==='resume-configuration'?'reload':name.slice('resume-'.length));
  const restored=await evaluate('fixtureReports.at(-1)');
  const task=restored.tasks[0];
  check(task.id===original.id && task.start_session===session && task.machine===original.machine && task.pending?.job===job,'interruption restores exact original identities and pending job');
  check(task.requests===original.requests && task.steps===original.steps && JSON.stringify(task.limits)===JSON.stringify(original.limits),'restoration preserves consumed requests, steps and limits');
  check(!restored.poc_configuration.key_set && restored.sessions[0].inference_configuration.endpoint===inferenceEndpoint,'replacement restores public configuration while waiting for the original key');
  check((await control({inspect:true})).inference_requests===1,'key-resupply wait consumes no new Request or inference send');
 }
 if(name==='resume-freeze') await hold('poc_model_return');
 await relayReady();
 await control({verify:true});await control({release:true});
 if(name==='resume-freeze') {
  await point('poc_model_return');
  const before=await journal();
  await message({lifecycle:'freeze'});await wait("fixtureReports.at(-1)?.lifecycle_state==='reconciling'");
  await message({lifecycle:'resume'});await wait("fixtureReports.at(-1)?.lifecycle_state==='running'");
  await release('poc_model_return');
  await wait("['complete','paused'].includes(fixtureReports.at(-1)?.tasks?.[0]?.status)");
  const after=await journal();
  check(after.poc_pauses===before.poc_pauses,'retired invocation cannot append a late semantic Pause');
  check(await evaluate("!fixtureReports.at(-1).tasks[0].completed.some(step=>step[0]==='loopback-call-1')"),'discarded inference result never becomes an actionable proposal');
 } else {
  if(['resume-lock','resume-reload','resume-loss','resume-configuration'].includes(name)) {
   await wait(`fixtureReports.at(-1)?.tasks?.[0]?.completed?.some(step=>step[0]===${JSON.stringify(original.proposal.call_id)}) && !fixtureReports.at(-1)?.tasks?.[0]?.pending`);
   check((await control({inspect:true})).inference_requests===1,'original job collected and settled before another inference request');
   await relayReady();
   if(name==='resume-configuration') {
    const edited=inferenceEndpoint.replace(/:(\d+)\//, ':0$1/');
    await invoke(values=>{document.querySelector('#tau-poc-endpoint').value=values.endpoint;document.querySelector('#tau-poc-model').value='model-a';document.querySelector('#tau-poc-key').value=values.key;document.querySelector('#tau-poc-inference-form').requestSubmit();},{endpoint:edited,key:normal});
    await wait("fixtureReports.at(-1)?.store_error?.includes('admitted endpoint')");
    const waiting=await evaluate('fixtureReports.at(-1)');
    check(waiting.poc_configuration.key_set && waiting.poc_configuration.configuration.endpoint===edited && waiting.tasks[0].requests===original.requests,'endpoint edit is accepted while automatic continuation preserves the admitted configuration and request budget');
    check((await control({inspect:true})).inference_requests===1,'automatic continuation never sends to a substituted endpoint');
    await invoke(()=>[...document.querySelectorAll('[data-task] button')].find(b=>b.textContent==='Resume').click());
   } else await configure(normal);
  }
  await wait("fixtureReports.at(-1)?.tasks?.[0]?.status==='complete'");
 }
 await observe('delivery');
 const completed=await evaluate('fixtureReports.at(-1).tasks[0]');
 const seen=await control({inspect:true});
 check(completed.id===original.id && completed.start_session===session && completed.verification.every(v=>v.exit_status===0),'eligible continuation and verification complete the same task');
 check(seen.launches.filter(j=>j.job===job).length===1 && seen.launches.length===2,'one original launch plus one distinct verification command');
 if(name==='resume-freeze') {
  await hold('publication_prepared');
  await message({fixture:{publish:session}});await point('publication_prepared');
  await message({lifecycle:'freeze'});
  await release('publication_prepared');
  await wait("fixtureReports.at(-1)?.lifecycle_state==='reconciling'");
  check(await evaluate('fixtureReports.every(report=>report.goal_outcome?.outcome?.done!==true)'),'late prepared publication cannot publish actionable done after suspension');
  await message({lifecycle:'resume'});await wait("fixtureReports.at(-1)?.lifecycle_state==='running'");
  await hold('poc_end_writer');
  const beforeEnd=await journal();
  const endedActions=await evaluate("fixtureEvents.filter(e=>e.fixture_action==='end-session').length");
  await click('[data-end-session]');await point('poc_end_writer');
  await message({lifecycle:'freeze'});await wait("fixtureReports.at(-1)?.lifecycle_state==='reconciling'");
  await release('poc_end_writer');
  await wait(`fixtureEvents.filter(e=>e.fixture_action==='end-session').length>${endedActions}`);
  check((await journal()).records===beforeEnd.records && await evaluate(`fixtureReports.at(-1).endable_sessions.some(s=>s.identity===${JSON.stringify(session)})`),'an End queued before suspension appends nothing after its execution generation changes');
  check(await evaluate("!document.querySelector('[data-end-session]').disabled"),'a fresh End control remains available during suspension');
 }
 await click('[data-end-session]');
 await wait(name==='resume-freeze' ? 'fixtureReports.at(-1)?.endable_sessions?.length===0' : "fixtureReports.at(-1)?.sessions?.[0]?.session_state==='ended'");
 await observe('ended');
 await reopen();
 await observe('reopened-ended');
 check(await evaluate('fixtureReports.at(-1).sessions[0].session_state===\'ended\' && fixtureReports.at(-1).tasks[0].status===\'complete\''),'selected End survives reopening with its task history');
 check((await control({inspect:true})).launches.filter(j=>j.job===job).length===1,'reopening ended history launches nothing');
}

async function pendingProof(c) {
 const {name,info,session,evaluate,invoke,wait,click,message,hold,point,release,configure,check,control,journal,relayReady,normal}=c;
 await point('pending_launch_committed');
 const pending=await evaluate('fixtureReports.at(-1).tasks[0]');
 const {call,job}=pending.pending;
 check((await control({inspect:true})).launches.length===0,'deterministic cut after task intent and before any launch bytes');
 await evaluate('window.cutWorker=fixtureWorkers.at(-1)');
 await click('#tau-lock');
 await release('pending_launch_committed');
 await wait("document.querySelector('#tau-store')?.dataset.state==='locked'");
 await relayReady();
 await invoke(()=>{document.querySelector('#tau-passphrase').value='durable fixture passphrase';document.querySelector('#tau-unlock').click();});
 await wait("fixtureReports.at(-1)?.tasks?.[0]?.status==='paused' && document.querySelectorAll('[data-pending-assumption]').length===2");
 const task=await evaluate('fixtureReports.at(-1).tasks[0]');
 check(task.pending.call===call && task.pending.job===job,'Lock and Unlock preserve pending identity');
 check(await evaluate("document.querySelector('[data-task]').textContent.includes('no record found')"),'paused card retains no-record sentence');
 if(['pending-context','pending-ended'].includes(name)) {
  await message({fixture:{pending_context:session,kind:name==='pending-context'?'incomplete':'ended'}});
  await wait(`fixtureReports.at(-1)?.tasks?.[0]?.disposition_offer?.read===${JSON.stringify(name==='pending-context'?'incomplete':'ended')}`);
 }
 const before=await journal();
 const assumption=name==='pending-done'?'as_if_done':'as_if_not_done';
 await click(`[data-pending-assumption="${assumption}"]`);
 const text=await evaluate('document.querySelector("[data-pending-confirmation]").textContent');
 for(const expected of [String(call),job,'machine-a',name==='pending-context'?'incomplete':name==='pending-ended'?'ended':'missing','outcome stays unknown','your assumption',assumption,'same command again, as a new command','overlap later commands','page will never show it']) check(text.includes(expected),`confirmation contains ${expected}`);
 if(name==='pending-context') {
  const offer=await evaluate('fixtureReports.at(-1).tasks[0].disposition_offer');
  check(text.includes('may still be running'),'incomplete warning names live-command risk');
  check(text.includes(offer.remaining.join(', ')) && text.includes('machine remains held'),'confirmation names remaining holds');
  check(text.includes(String(offer.standing.number)) && text.includes(offer.standing.continuation) && text.includes(offer.standing.calls.join(', ')) && text.includes('Dropped calls retain their unknown outcome'),'confirmation names replacement and dropped unknown calls');
 }
 for(const label of ['Resume','Stop task','Raise limits']) check(await evaluate(`[...document.querySelectorAll('[data-task] button')].some(b=>b.textContent===${JSON.stringify(label)})`),`confirmation retains ${label}`);
 check((await journal()).records===before.records,'opening confirmation appends nothing');
 await invoke(()=>[...document.querySelectorAll('[data-task] button')].find(b=>b.textContent==='Cancel assumption').click());
 check((await journal()).records===before.records,'Cancel appends nothing');
 check(await evaluate('!document.querySelector("[data-pending-confirmation]").textContent'),'Cancel dismisses inside the card');
 await configure(normal);await wait('fixtureReports.at(-1)?.poc_configuration?.key_set');
 await relayReady();
 await control({verify:true});
 await click(`[data-pending-assumption="${assumption}"]`);
 const actions=await evaluate('fixtureEvents.filter(e=>e.fixture_action_complete).length');
 if(name==='pending-ceremony') {
  const confirmation=await evaluate('fixtureReports.at(-1).tasks[0].disposition_offer');
  await click('#tau-redisplay');
  await wait("document.querySelector('#tau-store')?.dataset.state==='locked'");
  await invoke(()=>{document.querySelector('#tau-passphrase').value='durable fixture passphrase';document.querySelector('#tau-unlock').click();});
  await wait("fixtureReports.at(-1)?.seed_backup_stage==='showing_words'");
  const files=await journal();
  await message({task:{action:'dispose-pending',id:confirmation.task,session,confirmation,continuation:assumption}});
  await wait(`fixtureEvents.filter(e=>e.fixture_action_complete).length>${actions}`);
  check((await journal()).records===files.records,'seed backup ceremony refuses a current-generation disposition without append');
  check((await control({inspect:true})).launches.length===0,'seed backup ceremony launches nothing');
  return;
 }
 if(name==='pending-stale') await hold('pending_disposition_writer');
 await invoke(()=>[...document.querySelectorAll('[data-task] button')].find(b=>b.textContent==='Confirm unknown outcome').click());
 if(name==='pending-stale') {
  await point('pending_disposition_writer');
  const files=await journal();
  await message({lifecycle:'freeze'});await wait("fixtureReports.at(-1)?.lifecycle_state==='reconciling'");
  await message({lifecycle:'resume'});await wait("fixtureReports.at(-1)?.lifecycle_state==='running'");
  await release('pending_disposition_writer');
  await wait(`fixtureEvents.filter(e=>e.fixture_action_complete).length>${actions}`);
  check((await journal()).records===files.records,'lifecycle-stale confirmation appends nothing');
  check(await evaluate('fixtureReports.at(-1).tasks[0].pending!==null'),'lifecycle-stale confirmation retains pending call');
  return;
 }
 await wait(`fixtureEvents.filter(e=>e.fixture_action_complete).length>${actions}`);
 check(await evaluate('fixtureReports.at(-1).tasks[0].completed.some(step=>step[2]?.content?.outcome===\'unknown\')'),'confirmation reaches the worker and completes the pending tool');
 if(name==='pending-context') {
  const final=await evaluate('fixtureReports.at(-1).tasks[0]');
  check(final.completed[0][2].content.machine_held && final.completed[0][2].content.remaining_unresolved.length===1,'result retains remaining hold');
  check(await evaluate('document.querySelector("[data-task]").textContent.includes("machine remains held by other unresolved calls")'),'card retains remaining hold');
  check((await control({inspect:true})).launches.length===0,'remaining hold prevents another launch');
  return;
 }
 await wait("fixtureReports.at(-1)?.tasks?.[0]?.status==='complete'");
 const final=await evaluate('fixtureReports.at(-1).tasks[0]');
 const result=final.completed.find(step=>step[0]===pending.proposal.call_id)?.[2];
 check(result?.type==='untrusted' && result.source==='tool_output' && result.content.outcome==='unknown','original tool receives one untrusted unknown outcome');
 check(result.content.continuation===assumption && !JSON.stringify(result).includes('exit_status'),'selected assumption retained without exit field');
 check(final.completed.filter(step=>step[0]===pending.proposal.call_id).length===1 && !final.pending,'original proposal consumed once');
 check((await journal()).dispositions===before.dispositions+1,'confirmation appends exactly one disposition');
 const observed=await control({inspect:true});
 check(observed.inference_requests===2,'confirmation automatically makes a new model request');
 check(observed.launches.every(launch=>launch.job!==job),'disposed job is never launched');
 check(observed.launches.length===1 && observed.launches[0].job!==job,'only the distinct normal verification job launches');
 check(JSON.stringify(observed.inference_bodies.at(-1)).includes('outcome') && JSON.stringify(observed.inference_bodies.at(-1)).includes('unknown') && JSON.stringify(observed.inference_bodies.at(-1)).includes(job),'new request carries disposed outcome history');
 check(await evaluate(`document.querySelector('[data-task]').textContent.includes(${JSON.stringify(assumption)})`),'card retains selected assumption');
}

const pendingCases = ['pending-not-done', 'pending-done', 'pending-context', 'pending-ended', 'pending-stale', 'pending-ceremony'];
const name = process.argv[2] ?? 'interruption';
if (name === 'list-pending') { console.log(JSON.stringify(pendingCases)); process.exit(0); }
if (name === 'list-layout') { console.log(JSON.stringify([...layoutCases, 'layout-purchase', 'layout-credit'])); process.exit(0); }
if (name === 'list-credit') { console.log(JSON.stringify(creditCases)); process.exit(0); }
if (name === 'layout-credit') {
 const result=spawnSync(process.execPath,[new URL(import.meta.url).pathname,'credit-key'],{stdio:'inherit',env:{...process.env,TAU_LAYOUT_CREDIT:'1'}});
 process.exit(result.status??1);
}
if (name === 'layout-purchase') {
 for (const scenario of ['fixed', 'custom-caps-network', 'custom-caps-uncapped', 'fixed-terms', 'custom-terms']) {
  const result=spawnSync('nix',['shell','nixpkgs#openssl','-c',process.execPath,new URL('./check-provisioning.mjs',import.meta.url).pathname,scenario],{stdio:'inherit',env:{...process.env,TAU_LAYOUT_PROOF:'1'}});
  if(result.status!==0)process.exit(result.status??1);
 }
 process.exit(0);
}
const creditCase = creditCases.includes(name);
const credit = fixtureCredit();
if (name==='wire') {
  for (const row of ['wire-12000','wire-largest','wire-too-long']) {
    const result=spawnSync(process.execPath,[new URL(import.meta.url).pathname,row],{stdio:'inherit',env:process.env});
    if(result.status!==0)process.exit(result.status??1);
  }
  process.exit(0);
}
const startCases=['start-defaults','start-approval','start-interruption','start-approval-configuration'];
if(name==='list-start'){console.log(JSON.stringify(startCases));process.exit(0);}
const resumeCases=[...startCases,...pendingCases,'resume-lock','resume-reload','resume-loss','resume-stale-fetch','resume-freeze','resume-append','resume-approval','resume-end','resume-configuration'];
const realResume=resumeCases.includes(name) || creditCase || layoutCases.includes(name);
if (![...layoutCases,...creditCases,...resumeCases,'resume-envelopes','approval-refusal','goal-span','job-span','future-revision','metadata-key','mismatched-terminal','first-key','rotation','publication','progress','interruption','aggregate','resolver','configuration','wire-12000','wire-largest','wire-too-long','first-key-checks','reload-key','reload-control','keyless-collection','reload-progress'].includes(name)) throw Error('unknown page case');
const keyless=['goal-span','job-span','first-key','first-key-checks','reload-key','reload-control','keyless-collection','reload-progress','mismatched-terminal'].includes(name);
const fixture = spawn(process.env.TAU_POC_TRACER ?? 'target/debug/tracer', ['poc-fixtures'], {stdio:['pipe','pipe','inherit']});
const lines = createInterface({input:fixture.stdout});
const responses = [], pending = [];
lines.on('line', line => {const value=JSON.parse(line); const resolve=pending.shift(); if(resolve)resolve(value);else responses.push(value);});
const read = () => responses.length ? Promise.resolve(responses.shift()) : new Promise(resolve=>pending.push(resolve));
const control = async value => {fixture.stdin.write(JSON.stringify(value)+'\n');return read();};
const info = await read();
const inferenceEndpoint = realResume ? info.inference : 'https://inference.invalid/v1/chat/completions';
const injection = `
import * as fixtureApi from './pkg/tau_web.js';
const fixtureHolds=new Map();
globalThis.fixtureCreditRelease=name=>fixtureHolds.get(name)?.release();
let fixtureCommand='true', fixtureCalls=0, fixtureCommands=['true'];
const fixturePoint=async name=>{const held=fixtureHolds.get(name);if(held){postMessage({fixture_point:name});await held.promise;}};
const originalFetch=globalThis.fetch.bind(globalThis);
globalThis.fetch=async(input,options)=>{
 const request=input instanceof Request?input:new Request(input,options);
 const creditOrigin='https://127.0.0.1:'+new URL(location.href).port;
 if(${creditCase} && request.url.startsWith(creditOrigin+'/')){
  const url=new URL(request.url),headers=new Headers(request.headers);
  if(request.method==='POST' && (url.pathname==='/keys'||url.pathname==='/topup/create/btc-lightning')){
   const evidence=JSON.parse(await fixtureApi.test_poc_journal(${JSON.stringify(creditId)}));
   headers.set('x-fixture-credit-evidence',JSON.stringify(evidence));
  }
  return originalFetch(new Request(location.origin+'/credit'+url.pathname+url.search,{method:request.method,headers,body:['GET','HEAD'].includes(request.method)?undefined:await request.arrayBuffer(),credentials:'omit',cache:'no-store',redirect:'error',signal:request.signal}));
 }
 if(request.url.startsWith(location.origin+'/'))return originalFetch(input,options);
 if(globalThis.fixtureCreditRefusal && request.url===${JSON.stringify(inferenceEndpoint)})return new Response(JSON.stringify({error:fixtureCreditRefusal.error}),{status:fixtureCreditRefusal.status});
 if(${realResume} && request.url===${JSON.stringify(inferenceEndpoint)}){const report=JSON.parse(await fixtureApi.open());postMessage({fixture_model_admission:{accepted:report.tasks?.every(task=>report.mode_acceptances?.some(a=>a.session===task.start_session&&a.mode==='Acting on a goal with no brief'))}});return originalFetch(input,options);}
 if(request.url!=='https://inference.invalid/v1/chat/completions')throw Error('external request refused');
 const body=JSON.parse(await request.text());
 const machine='machine-a', command=fixtureCommands[fixtureCalls]??fixtureCommand;
 const tool=fixtureCalls++<fixtureCommands.length?'exec':'done';
 return new Response(JSON.stringify({choices:[{finish_reason:'tool_calls',message:{role:'assistant',content:null,tool_calls:[{id:'call-'+fixtureCalls,type:'function',function:{name:tool,arguments:JSON.stringify(tool==='done'?{machine}:{machine,command})}}]}}]}),{status:200});
};
`;
const hook = `
fixtureApi.test_poc_configuration(${JSON.stringify(inferenceEndpoint)},'model-a');
if(${creditCase})fixtureApi.test_credit_origin('https://127.0.0.1:'+new URL(location.href).port);
if(${name.startsWith('credit-restart-')}){const runGoal=fixtureApi.TaskPublication.prototype.run_goal;fixtureApi.TaskPublication.prototype.run_goal=function(session,checks){postMessage({fixture_start_run:{session,checks:JSON.parse(checks)}});return runGoal.call(this,session,checks);};}
const productionMessage=onmessage;
onmessage=async event=>{
 const value=event.data?.request?.fixture;
 if(!value){const result=await productionMessage(event);if(event.data?.request?.credit_request)postMessage({fixture_credit_complete:event.data.request.credit_request.action});if(event.data?.request?.unlock)postMessage({fixture_unlock_complete:true});if(event.data?.request?.lifecycle)postMessage({fixture_lifecycle_complete:event.data.request.lifecycle});if(event.data?.request?.task||event.data?.request?.goal_accept||event.data?.request?.requirements_answer)postMessage({fixture_action_complete:true,fixture_action:event.data.request.task?.action??(event.data.request.requirements_answer?'requirements':'goal')});return result;}
 if(value.append_credit_probe){postMessage({fixture_credit_probe:JSON.parse(await fixtureApi.test_credit_append_probe(value.append_credit_probe))});return;}
 if(value.publish){const report=JSON.parse(await fixtureApi.open());report.goal_outcome={session:value.publish,outcome:{done:true}};await fixtureApi.publish_report(fixtureApi.publication_generation(),value.publish,JSON.stringify(report));return;}
 if(value.approval_neighbor){const report=await fixtureApi.test_approval_neighbor();await fixtureApi.publish_report(fixtureApi.publication_generation(),'',report);postMessage({fixture_neighbor:true});return;}
 if(value.pending_context){const report=await fixtureApi.test_pending_context(value.kind);await fixtureApi.publish_report(fixtureApi.publication_generation(),value.pending_context,report);return;}
 if(value.probe){postMessage({fixture_protected:JSON.parse(await fixtureApi.test_poc_protect_output(JSON.stringify(value.probe)))});return;}
 if(value.credential){await fixtureApi.test_poc_register_credential(new TextEncoder().encode(value.credential));postMessage({fixture_registered:true});return;}
 if(value.command!==undefined){fixtureCommand=value.command;fixtureCommands=[value.command];fixtureCalls=0;}
 if(value.commands){fixtureCommands=value.commands;fixtureCalls=0;}
 if(value.profile)await fixtureApi.test_poc_profile('machine-a',value.profile);
 if(value.done)fixtureCalls=1;
 if(value.unconfigured)fixtureApi.test_poc_model(value.command);
 if(value.hold){let release;const promise=new Promise(resolve=>release=resolve);fixtureHolds.set(value.hold,{promise,release});
 if(!value.hold.startsWith('worker_'))fixtureApi.test_hold_session_point(value.hold,promise,()=>postMessage({fixture_point:value.hold}));}
 if(value.release){fixtureHolds.get(value.release)?.release();}
 if(value.counts){postMessage({fixture_counts:JSON.parse(await fixtureApi.test_poc_release_counts())});}
 if(value.journal!==undefined){postMessage({fixture_journal:JSON.parse(await fixtureApi.test_poc_journal(value.journal))});}
 if(value.inspect){postMessage({fixture_inspect:JSON.parse(await fixtureApi.store_state())});}
 postMessage({fixture_ack:value});
};
`;
// Only the loopback fixture response is instrumented; the shipped page/worker stay intact.
const server=createServer(async(req,res)=>{
 try {
  const requestUrl=new URL(req.url,'http://fixture.invalid');
  if(requestUrl.pathname.endsWith('/poc-defaults.json'))credit.state.defaultsPaths.push(requestUrl.pathname);
  if(name==='credit-defaults-directory'&&!requestUrl.pathname.startsWith('/nested/')){res.writeHead(404).end();return;}
  const path=name==='credit-defaults-directory'?requestUrl.pathname.slice('/nested'.length):requestUrl.pathname;
  if(await credit.handler(req,res,path+requestUrl.search))return;
  if(path==='/poc-defaults.json' && name!=='credit-defaults-missing'){
    const value={provider_origin:'https://provider.example',relay_url:'wss://relay.example/',chat_endpoint:'https://credit.example/v1/chat/completions',model:'example-model',topup_sat:name==='credit-defaults-invalid'?99:1200,...credit.state.defaultsOverride};
    if(!name.startsWith('credit-defaults')){res.writeHead(404).end();return;}
    if(name==='credit-defaults-late')await new Promise(resolve=>{credit.state.releaseDefaults=resolve;});
    res.setHeader('Content-Type','application/json');res.end(JSON.stringify(value));return;
  }
  const file=path==='/'?'index.html':path.slice(1);
  if(!/^(index.html|boot.js|worker.js|pkg\/[a-zA-Z0-9_.-]+)$/.test(file)){res.writeHead(404).end();return;}
  let data=await readFile(new URL('../'+(file.startsWith('pkg/')||name.startsWith('edge-')||layoutCases.includes(name)||process.env.TAU_LAYOUT_CREDIT==='1'?'dist/tracer/':'www/')+file,import.meta.url));
  if(name.startsWith('edge-'))console.log(JSON.stringify({artifact:file,sha256:createHash('sha256').update(data).digest('hex')}));
  if(file==='index.html')data=data.toString().replace(/<meta http-equiv="Content-Security-Policy"[^>]*>\n/,'');
  if(file==='worker.js') {
   if(name.startsWith('credit-restart-'))data=data.toString().replace('const value = JSON.parse(await credit_request(JSON.stringify(data.credit_request)));', `const value = JSON.parse(await credit_request(JSON.stringify(data.credit_request))); if(data.credit_request.action==='start'){value.tasks?.sort((a,b)=>Number(value.sessions.some(s=>s.identity===b.start_session&&s.session_state==='ended'))-Number(value.sessions.some(s=>s.identity===a.start_session&&s.session_state==='ended')));postMessage({fixture_start_order:value.tasks?.map(t=>t.start_session)});}`);
   assert.ok(data.toString().includes('const finalGeneration = publication_generation();'),'goal return hook exists');
   assert.ok(data.toString().includes('await publication.publish(generation, session, report);'),'task return hook exists');
   data=(credit.state.clockMs===undefined?'':`Date.now=()=>${credit.state.clockMs};\n`)+injection+data.toString()
   .replace('const finalGeneration = publication_generation();','await fixturePoint("worker_return"); const finalGeneration = publication_generation();')
   .replace('await publication.publish(generation, session, report);','await fixturePoint("worker_return"); await publication.publish(generation, session, report);')+hook;
  }
  res.setHeader('Content-Type',file.endsWith('.wasm')?'application/wasm':file.endsWith('.html')?'text/html':'text/javascript');res.end(data);
 }catch(error){res.writeHead(500).end(String(error));}
});
let browser,socket,profile;
const watchdog=setTimeout(()=>{
 console.error('durable page watchdog');
 if(browser?.pid&&browser.exitCode===null&&browser.signalCode===null)browser.kill('SIGKILL');
 if(fixture.exitCode===null&&fixture.signalCode===null)fixture.kill('SIGKILL');
},240000);
try{
 if(!process.env.CHROME||!process.env.TMPDIR)throw Error('CHROME and TMPDIR required');
 profile=await mkdtemp(join(process.env.TMPDIR,'poc-page-'));
 server.listen(0,'127.0.0.1');await once(server,'listening');
 browser=spawn(process.env.CHROME,['--headless','--no-sandbox','--disable-gpu','--disable-background-networking','--disable-component-update','--disable-sync','--disable-default-apps','--no-first-run','--remote-debugging-port=0','--ignore-certificate-errors-spki-list='+info.spki,'--user-data-dir='+profile,'about:blank'],{stdio:['ignore','ignore','pipe']});
 const endpoint=await new Promise((resolve,reject)=>{let text='';browser.stderr.on('data',chunk=>{text=(text+chunk).slice(-8192);const match=text.match(/DevTools listening on (ws:\/\/[^\s]+)/);if(match)resolve(match[1]);});browser.once('exit',()=>reject(Error('browser exited')));});
 socket=new WebSocket(endpoint);await once(socket,'open');let sequence=0;const calls=new Map();
 socket.addEventListener('message',event=>{const message=JSON.parse(event.data);const resolve=calls.get(message.id);if(resolve){calls.delete(message.id);message.error?resolve.reject(Error(JSON.stringify(message.error))):resolve.resolve(message.result);}});
 const call=(method,params={},sessionId)=>new Promise((resolve,reject)=>{const id=++sequence;calls.set(id,{resolve,reject});socket.send(JSON.stringify({id,method,params,...(sessionId?{sessionId}:{})}));});
 const {targetId}=await call('Target.createTarget',{url:'about:blank'});
 const {sessionId}=await call('Target.attachToTarget',{targetId,flatten:true});
 await call('Page.enable',{},sessionId);
 if(layoutCases.includes(name)||name.startsWith('edge-focus')||process.env.TAU_LAYOUT_CREDIT==='1')await call('Emulation.setDeviceMetricsOverride',{width:390,height:844,deviceScaleFactor:1,mobile:true},sessionId);
 if(creditCase||layoutCases.includes(name)){await call('Target.setDiscoverTargets',{discover:true});await call('Target.setAutoAttach',{autoAttach:true,waitForDebuggerOnStart:false,flatten:true},sessionId);}
 const observerSource=`const pageFetch=fetch.bind(window);window.fetch=(input,options)=>{const u=new URL(input instanceof Request?input.url:input,location.href);if(!['127.0.0.1','localhost','[::1]'].includes(u.hostname))throw Error('external page request refused');return pageFetch(input,options);};window.fixtureReports=[];window.fixtureEvents=[];window.fixtureWorkers=[];const OriginalWorker=Worker;window.Worker=class extends OriginalWorker{constructor(...args){super(...args);fixtureWorkers.push(this);this.addEventListener('message',event=>{if(event.data.store)fixtureReports.push(event.data.store);else {fixtureEvents.push(event.data);if(Object.keys(event.data).some(key=>key.startsWith('fixture_')))event.stopImmediatePropagation();}});}terminate(){this.fixtureTerminated=true;super.terminate();}};`;
 await call('Page.addScriptToEvaluateOnNewDocument',{source:observerSource},sessionId);
 const evaluate=async expression=>{const result=await call('Runtime.evaluate',{expression,awaitPromise:true,returnByValue:true},sessionId);if(result.exceptionDetails)throw Error(result.exceptionDetails.exception?.description??JSON.stringify(result.exceptionDetails));return result.result.value;};
 const workerEvaluate=async expression=>{
  const {targetInfos}=await call('Target.getTargets');
  const target=targetInfos.find(t=>t.type==='worker'&&t.url.startsWith(`http://127.0.0.1:${server.address().port}/`));
  if(!target)throw Error('fixture worker unavailable: '+JSON.stringify(targetInfos.map(t=>({type:t.type,url:t.url}))));
  const attached=await call('Target.attachToTarget',{targetId:target.targetId,flatten:true});
  try{const result=await call('Runtime.evaluate',{expression,awaitPromise:true,returnByValue:true},attached.sessionId);if(result.exceptionDetails)throw Error(result.exceptionDetails.exception?.description??JSON.stringify(result.exceptionDetails));return result.result.value;}
  finally{await call('Target.detachFromTarget',{sessionId:attached.sessionId});}
 };
 const invoke=async(fn,...args)=>evaluate(`(${fn.toString()})(...${JSON.stringify(args)})`);
 const wait=async expression=>evaluate(`new Promise((resolve,reject)=>{const start=performance.now();const poll=()=>{const value=(${expression});if(value)return resolve(value);if(performance.now()-start>60000)return reject(Error('page wait: '+${JSON.stringify(expression)}));setTimeout(poll,25);};poll();})`);
 const click=async selector=>invoke(selector=>{const e=document.querySelector(selector);if(!e)throw Error('missing '+selector);e.click();},selector);
 const message=async data=>invoke(data=>fixtureWorkers.at(-1).postMessage(data),data);
 const hold=async point=>{await message({fixture:{hold:point}});await wait(`fixtureEvents.some(e=>e.fixture_ack?.hold===${JSON.stringify(point)})`);};
 const point=async name=>wait(`fixtureEvents.some(e=>e.fixture_point===${JSON.stringify(name)})`);
 const release=async name=>message({fixture:{release:name}});
 const configure=async key=>{await invoke((key,endpoint)=>{for(const [id,value]of [['endpoint',endpoint],['model','model-a'],['key',key]])document.querySelector('#tau-poc-'+id).value=value;document.querySelector('#tau-poc-inference-form').requestSubmit();},key,inferenceEndpoint);};
 const check=(ok,label)=>{if(!ok)throw Error(label);console.log(JSON.stringify({case:name,check:label}));};
 if(creditCase){
  try { await creditProof({name,info,inferenceEndpoint,call,sessionId,evaluate,workerEvaluate,invoke,wait,click,message,hold,point,release,configure,check,control,credit,pageOrigin:`http://127.0.0.1:${server.address().port}`}); }
  catch(error){console.error(JSON.stringify({last:await evaluate('(()=>{const r=fixtureReports.at(-1);return {tasks:r?.tasks,error:r?.store_error,credit_error:r?.credit_error,lifecycle:r?.lifecycle_state,sessions:r?.sessions?.map(s=>({identity:s.identity,state:s.session_state,pending:s.pending_requirements}))};})()'),counts:{mints:credit.state.mintCalls,deletes:credit.state.deletes.length},fixture:await control({inspect:true})}));throw error;}
  assert.deepEqual(credit.state.orderingFailures,[], 'mint name committed before request');
  for(const needle of [creditId,'synthetic-default-credential-482700',...credit.state.keys.map(k=>k.api_key)]){
   check(!await evaluate(`JSON.stringify(fixtureEvents).includes(${JSON.stringify(needle)}) || JSON.stringify(fixtureReports).includes(${JSON.stringify(needle)}) || document.body.textContent.includes(${JSON.stringify(needle)})`),'credit credentials stay out of page, messages and reports');
  }
  await evaluate('fixtureWorkers.at(-1).terminate()');await call('Browser.close');await once(browser,'exit');
 } else if(name==='layout-fixture'||name==='layout-keys'){
  await (name==='layout-fixture'?fixtureLayout:publicKeysLayout)({name,info,call,sessionId,evaluate,workerEvaluate,invoke,wait,click,message,check,pageOrigin:`http://127.0.0.1:${server.address().port}`});
  await evaluate('fixtureWorkers.at(-1).terminate()');await call('Browser.close');await once(browser,'exit');
 } else if(realResume){
  try { await resumeProof({name,info,inferenceEndpoint,call,sessionId,evaluate,workerEvaluate,invoke,wait,click,message,hold,point,release,configure,check,control,observerSource,pageOrigin:`http://127.0.0.1:${server.address().port}`}); }
  catch(error) {
   console.error(JSON.stringify({last:await evaluate('(()=>{const r=fixtureReports.at(-1);return {tasks:r?.tasks,error:r?.store_error,lifecycle:r?.lifecycle_state,sessions:r?.sessions?.map(s=>({identity:s.identity,state:s.session_state,pending:s.pending_requirements}))};})()'),fixture:await control({inspect:true})}));
   throw error;
  }
  await evaluate('fixtureWorkers.at(-1).terminate()');await call('Browser.close');await once(browser,'exit');
 } else {
 await call('Page.navigate',{url:`http://127.0.0.1:${server.address().port}/`},sessionId);
 await wait(`document.querySelector('#tau-store')?.dataset.state==='none'`);
 await invoke(()=>{document.querySelector('#tau-passphrase').value=document.querySelector('#tau-confirm').value='durable fixture passphrase';document.querySelector('#tau-create').click();});
 await wait(`document.querySelector('#tau-seed-backup-answer')&&!document.querySelector('#tau-seed-backup-answer').disabled`);
 await click('#tau-seed-backup-answer');await wait(`!document.querySelector('#tau-seed-backup-skip').disabled`);await click('#tau-seed-backup-skip');
 await wait(`!document.querySelector('#tau-poc-inference-form button').disabled`);
 const normal='normal-synthetic-key-482700';
 if(!keyless&&!['resolver','configuration'].includes(name)) {await configure(normal);await wait(`document.querySelector('#tau-poc-key-status').textContent==='Key set.'`);}
 await invoke(info=>{for(const [id,value]of Object.entries({machine:'machine-a',relay:info.relay,profile:'v1',host:'127.0.0.1',port:info.port,user:'tracer',elevation:'none',pin:info.pin,class:'no'}))document.querySelector('#tau-poc-'+id).value=value;document.querySelector('#tau-poc-approve-existing').checked=document.querySelector('#tau-poc-approve-access').checked=true;document.querySelector('#tau-poc-target-form').requestSubmit();},info);
 await wait(`fixtureReports.at(-1)?.poc_targets?.length===1`);
 await invoke(()=>[...document.querySelectorAll('#tau-poc-targets button')].find(b=>b.textContent==='Show public keys machine-a').click());
 const keys=await wait(`fixtureReports.at(-1)?.poc_keys`);check((await control({keys})).installed,'fixture keys installed from page');
 // Acceptance without configuration first pauses before a command. Requirements remain explicit.
 const packageOutput=size=>'Package abc012345 xyz789 installed successfully.\n'.repeat(Math.ceil(size/47)).slice(0,size);
 const output=['rotation','publication','progress','aggregate'].includes(name)?Array.from(new TextEncoder().encode(packageOutput(170000)),b=>b.toString(16).padStart(2,'0')).join(''):packageOutput(2097152);
 const command=name==='job-span'?`while [ ! -f '${info.directory}/continue' ]; do sleep 0.1; done; printf done`:name==='keyless-collection'?`while [ ! -f '${info.directory}/continue' ]; do sleep 0.1; done; `+(await control({output})).command:name==='interruption'?`while [ ! -f '${info.directory}/continue' ]; do sleep 0.1; done; printf installed`:['goal-span','future-revision','resolver','configuration','metadata-key'].includes(name)?'true':name.startsWith('wire-')?'true #'+ 'x'.repeat((name==='wire-12000'?12000:info.largest+(name==='wire-too-long'?1:0))-6):(await control({output})).command;
 const selectedCommand=name==='mismatched-terminal'?`find '${info.directory}' -type f -name command -exec sh -c 'printf \"\\n# changed\\n\" >> \"$1\"' _ {} \\; ; printf done`:command;
 await message({fixture:{command:selectedCommand,unconfigured:keyless}});
 let secondOutput;
 if(name==='aggregate') {
   secondOutput=output.replaceAll('5061636b616765','41726368697665');
   const second=await control({output:secondOutput,second:true});
   await message({fixture:{commands:['sleep 1; '+command,'sleep 1; '+second.command]}});
 }
 await invoke(checks=>{document.querySelector('#tau-poc-targets [data-start-goal]').value='Install and check a small service';document.querySelector('#tau-poc-targets [data-start-checks]').value=checks;[...document.querySelectorAll('#tau-poc-targets button')].find(b=>b.textContent==='Start session machine-a').click();},name==='interruption'?`sleep 1; test -f '${info.directory}/verified'`:name==='first-key-checks'?'sleep 1; false':'');
 await wait(`fixtureReports.at(-1)?.tasks?.length===1 && fixtureReports.at(-1)?.tasks[0].pause_reason`);
 await wait(`document.querySelector('[data-poc-propose]')`);
 await click('[data-poc-propose]');await wait(`document.querySelector('[data-requirements-decision="approve"]')`);
 if(name==='approval-refusal') {
  const key='"setup":{"requirements":';
  let count=await evaluate('fixtureReports.length');
  await configure(key);await wait('fixtureReports.length>'+count);
  const configured=await evaluate('fixtureReports.at(-1)');
  check(!configured.store_error&&configured.poc_configuration.key_set,'setup-envelope configuration accepted');
  // Registration independently reaches commit if future admission rejects the fixture.
  await message({fixture:{credential:key}});await wait('fixtureEvents.some(e=>e.fixture_registered)');
  const inspect=async()=>{await evaluate('fixtureEvents=fixtureEvents.filter(e=>!e.fixture_journal)');await message({fixture:{journal:key}});return wait('fixtureEvents.find(e=>e.fixture_journal)?.fixture_journal');};
  const before=await inspect();
  const pending=await evaluate('fixtureReports.at(-1).sessions.map(s=>s.pending_requirements)');
  const setup=await evaluate('fixtureReports.at(-1).setup');
  count=await evaluate('fixtureReports.length');
  await click('[data-requirements-decision="approve"]');await wait('fixtureReports.length>'+count);
  const after=await inspect();
  const report=await evaluate('fixtureReports.at(-1)');
  check(report.store_error==='journal refused'&&!report.store_error.includes(key),'approval refusal is key-free');
  check(JSON.stringify(before)===JSON.stringify(after)&&!after.contains,'approval refusal preserves authenticated journal and allocations');
  check(JSON.stringify(pending)===JSON.stringify(report.sessions.map(s=>s.pending_requirements)),'approval refusal preserves exact pending proposal');
  check(JSON.stringify(setup)===JSON.stringify(report.setup),'approval refusal preserves declaration state');
  check(await evaluate(`!!document.querySelector('[data-requirements-decision="approve"]')`),'approval card remains visible');
  check((await control({inspect:true})).launches.length===0,'refused approval launches no command');
  count=await evaluate('fixtureReports.length');await click('[data-requirements-decision="reject"]');await wait('fixtureReports.length>'+count);
  check(await evaluate('fixtureReports.at(-1).sessions.every(s=>!s.pending_requirements)'),'explicit local rejection remains usable');
  await evaluate('fixtureWorkers.at(-1).terminate()');await call('Browser.close');await once(browser,'exit');
 } else {
 const beforeApprovalOnly=['goal-span','future-revision','metadata-key','resume-envelopes'].includes(name);
 if(['first-key','first-key-checks','rotation','progress'].includes(name)) { await hold('poc_terminal_append');await hold('poc_execution_return'); }
 if(name==='publication')await hold('worker_return');
 if(['reload-key','reload-control','reload-progress','mismatched-terminal'].includes(name)){await hold('poc_terminal_append');await hold('poc_execution_return');}
 if(name==='resolver'){await message({fixture:{profile:'unsupported-key-4827'}});await wait("fixtureEvents.some(event=>event.fixture_ack?.profile==='unsupported-key-4827')");await configure('unsupported-key-4827');await wait("document.querySelector('#tau-poc-key-status').textContent==='Key set.'");}
 if(!beforeApprovalOnly) {
 await click('[data-requirements-decision="approve"]');
 await wait(`!document.querySelector('[data-requirements-decision="approve"]')`);
 }



 // The first-key case still has no usable credential; other cases have a recorded exec proposal.
 let actionCount=0;
 const resume=async()=>{actionCount=await evaluate('fixtureEvents.filter(e=>e.fixture_action_complete).length');return invoke(()=>{const button=[...document.querySelectorAll('[data-task] button')].find(b=>b.textContent==='Resume');if(!button)throw Error('Resume unavailable');button.click();});};
 const actionComplete=()=>wait(`fixtureEvents.filter(e=>e.fixture_action_complete).length>${actionCount}`);
  const journal=async n=>{await evaluate('fixtureEvents=fixtureEvents.filter(e=>!e.fixture_journal)');await message({fixture:{journal:n}});return wait('fixtureEvents.find(e=>e.fixture_journal)?.fixture_journal');};
  const reloadUnlock=async()=>{
   await evaluate('fixtureWorkers.at(-1).terminate()');await call('Page.reload',{},sessionId);
   await wait("document.querySelector('#tau-store')?.dataset.state==='locked'");
   await invoke(()=>{document.querySelector('#tau-passphrase').value='durable fixture passphrase';document.querySelector('#tau-unlock').click();});
   await wait('fixtureReports.at(-1)?.tasks?.length===1');
   const restored=await evaluate('fixtureReports.at(-1)');
   check(restored.sessions.some(s=>s.identity===restored.tasks[0].start_session),'unlock restores the original session');
  };
  const conf=async key=>{const before=await evaluate('fixtureReports.length');await configure(key);await wait('fixtureReports.length>'+before);return evaluate('fixtureReports.at(-1)');};
  const acceptActing=async()=>{check(await evaluate('fixtureReports.at(-1).mode_acceptances.some(a=>a.session===fixtureReports.at(-1).tasks[0].start_session)'),'original no-brief approval is retained');};

 if(name==='resume-envelopes') {
  const original=await evaluate('fixtureReports.at(-1)');
  const keys=['","running":true}}}}}', '","running":false}}}}}', 'again","running":true', '{"command":{"binding":{"task":"', '"call":18446744073709551615,"machine":', 'abcdef012345","provenance":{', info.pin.slice(-8)+'"}},"job":"'];
  for(const key of keys) {
   const before=await journal(key);
   const configured=await conf(key);
   const after=await journal(key);
   check(configured.store_error?.includes('task references')&&configured.poc_configuration.key_set,'Resume envelope key refused retaining configuration');
   check(JSON.stringify(before)===JSON.stringify(after),'admission refusal preserves journal and allocations');
   check(JSON.stringify(configured.tasks)===JSON.stringify(original.tasks),'admission refusal preserves task projection');
   await evaluate('fixtureEvents=fixtureEvents.filter(e=>!e.fixture_protected)');
   await message({fixture:{probe:{candidate:key,previous:normal}}});
   const protectedValue=await wait('fixtureEvents.find(e=>e.fixture_protected)?.fixture_protected');
   check(protectedValue.candidate===key&&protectedValue.previous==='<redacted>','refused credential does not enter inventory');
  }
  const approvals=await evaluate("fixtureEvents.filter(e=>e.fixture_action==='requirements').length");
  await click('[data-requirements-decision="approve"]');
  await wait(`fixtureEvents.filter(e=>e.fixture_action==='requirements').length>${approvals}`);
  check((await control({inspect:true})).launches.length===1,'approval continues the ordinary accepted key once');
  await resume();await actionComplete();
  check((await control({inspect:true})).launches.length===1,'ordinary accepted key runs Command once');
  await resume();await actionComplete();
  check((await control({inspect:true})).launches.length===1,'Resume never duplicates original command');
 }else if(name==='goal-span'){
  await reloadUnlock();
  const report=await evaluate('fixtureReports.at(-1)');
  const task=report.tasks[0];
  const session=report.sessions.find(s=>s.identity===task.start_session);
  const key=session.identity.slice(-8)+'","text":"';
  const before=await journal(key);
  const configured=await conf(key);
  await acceptActing();
  const after=await journal(key);
  const end=await evaluate('fixtureReports.at(-1)');
  console.log(JSON.stringify({probe:'goal-span',keyBytes:key.length,keySet:configured.poc_configuration.key_set,configError:configured.store_error??null,before,after,storeError:end.store_error??null,session:end.tasks[0].start_session}));
  check(configured.store_error && JSON.stringify(before)===JSON.stringify(after), 'original goal envelope collision refuses without another append');
  check(configured.store_error?.includes('task references') && !configured.poc_configuration.key_set, 'original-goal configuration collision refuses before key custody');
  check(end.tasks[0].start_session===task.start_session && end.sessions.some(s=>s.identity===task.start_session && s.session_state!=='ended'),'original session remains admitted after configuration refusal');
  actionCount=await evaluate('fixtureEvents.filter(e=>e.fixture_action_complete).length');
  await message({task:{action:'abandon',id:task.id}});await actionComplete();
  check(await evaluate("fixtureReports.at(-1).tasks[0].status==='abandoned'"),'Stop task remains effective');
 }else if(name==='job-span'){
  for(let attempt=0;attempt<600;attempt++){if((await control({inspect:true})).launches.length===1)break;await new Promise(r=>setTimeout(r,100));}
  await reloadUnlock();
  await acceptActing();
  const report=await evaluate('fixtureReports.at(-1)');
  const task=report.tasks[0];
  const key=task.pending.job.slice(-8)+'","record"';
  const before=await journal(key);
  const configured=await conf(key);
  // Exercise the append boundary independently when admission conservatively refuses first.
  await message({fixture:{credential:key}});await wait('fixtureEvents.some(e=>e.fixture_registered)');
  await control({release:true});
  await new Promise(r=>setTimeout(r,1500));
  await resume();await actionComplete();
  const after=await journal(key);
  const end=await evaluate('fixtureReports.at(-1)');
  const posted=await evaluate('fixtureEvents.filter(e=>e.command_result).length');
  console.log(JSON.stringify({probe:'job-span',keyBytes:key.length,keySet:configured.poc_configuration.key_set,configError:configured.store_error??null,before,after,storeError:end.store_error??null,status:end.tasks[0].status,pause:end.tasks[0].pause_reason,pending:!!end.tasks[0].pending,posted}));
  check(!before.contains && !after.contains,'job envelope never appends accepted credential');
  check(end.tasks[0].pending?.job===task.pending.job,'refused evidence retains original pending job');
  actionCount=await evaluate('fixtureEvents.filter(e=>e.fixture_action_complete).length');
  await message({task:{action:'abandon',id:task.id}});await actionComplete();
  check(await evaluate("fixtureReports.at(-1).tasks[0].status==='abandoned'"),'local Abandon after job refusal remains effective');
  check((await control({inspect:true})).launches.length===1,'original job launched only once');
 }else if(name==='future-revision'){
  const task=await evaluate('fixtureReports.at(-1).tasks[0]');
  const key=task.id.slice(-4)+'","expected":'+(task.revision+1)+',';
  const reports=await evaluate('fixtureReports.length');await configure(key);await wait(`fixtureReports.length>${reports}`);
  const configured=await evaluate('fixtureReports.at(-1)');
  check(configured.store_error?.includes('task references')&&configured.poc_configuration.key_set,'future-envelope credential rejected retaining previous custody');
  await message({fixture:{probe:{candidate:key,previous:normal}}});
  const protectedValue=await wait('fixtureEvents.find(e=>e.fixture_protected)?.fixture_protected');
  check(protectedValue.candidate===key&&protectedValue.previous==='<redacted>','rejection preserves prior inventory without registering rejected credential');
  const action=async(data)=>{actionCount=await evaluate('fixtureEvents.filter(e=>e.fixture_action_complete).length');await message({task:{id:task.id,...data}});await actionComplete();return evaluate('fixtureReports.at(-1)');};
  const raised=await action({action:'raise',limits:task.limits});
  check(!raised.store_error&&raised.tasks[0].revision===task.revision+1,'Raise remains usable');
  const abandoned=await action({action:'abandon'});
  check(!abandoned.store_error&&abandoned.tasks[0].status==='abandoned','Abandon remains usable');
  check((await control({inspect:true})).launches.length===0,'metadata controls launch no command');
 }else if(name==='metadata-key'){
  const task=await evaluate('fixtureReports.at(-1).tasks[0]');
  const needle=JSON.stringify({poc:{change:{id:task.id,expected:task.revision,change:'abandon'}}});
  const journal=async()=>{await evaluate('fixtureEvents=fixtureEvents.filter(e=>!e.fixture_journal)');await message({fixture:{journal:needle}});return wait('fixtureEvents.find(e=>e.fixture_journal)?.fixture_journal');};
  const before=await journal();
  const reports=await evaluate('fixtureReports.length');await configure(task.id);await wait(`fixtureReports.length>${reports}`);
  const configured=await evaluate('fixtureReports.at(-1)');
  actionCount=await evaluate('fixtureEvents.filter(e=>e.fixture_action_complete).length');
  await message({task:{action:'abandon',id:task.id}});await actionComplete();
  const after=await journal();
  console.log(JSON.stringify({before,after,configurationRefused:!!configured.store_error,keySet:configured.poc_configuration.key_set}));
  check(!before.contains&&!(after.contains&&!configured.store_error),'no newly appended event contains an accepted credential');
  check(configured.store_error?.includes('task references')&&configured.poc_configuration.key_set,'colliding configuration refuses before replacing usable custody');
  check(await evaluate(`document.querySelector('#tau-poc-key').value===''&&fixtureReports.at(-1).tasks[0].status==='abandoned'`),'input clears and Abandon remains usable after collision refusal');
  check(after.contains&&after.records===before.records+1,'safe complete Abandon event appended exactly once');
  check((await control({inspect:true})).launches.length===0,'metadata controls launch no command');
 }else if(['reload-key','reload-control','keyless-collection','reload-progress','mismatched-terminal'].includes(name)){
  const collecting=name==='keyless-collection';

  if(collecting){
    for(let attempt=0;attempt<600;attempt++){
      if((await control({inspect:true})).launches.length===1)break;
      await new Promise(resolve=>setTimeout(resolve,100));
    }
  }else{await point('poc_terminal_append');await release('poc_terminal_append');await point('poc_execution_return');}
  await message({fixture:{counts:true}});
  const beforeLoss=await wait('fixtureEvents.find(e=>e.fixture_counts)?.fixture_counts');
  const original=(await control({inspect:true})).launches[0];
  check(original&&beforeLoss.terminals===(collecting?0:1)&&beforeLoss.collectable===(collecting?1:0),'crash boundary retains original durable job');
  check(await evaluate('fixtureEvents.filter(e=>e.command_result).length===0'),'worker lost before first result post');
  await evaluate('fixtureWorkers.at(-1).terminate()');await call('Page.reload',{},sessionId);
  await wait(`document.querySelector('#tau-store')?.dataset.state==='locked'`);
  await new Promise(resolve=>setTimeout(resolve,info.relay_spacing_ms+50));
  if(['reload-key','reload-progress'].includes(name))await hold('poc_progress_publication');
  await invoke(()=>{document.querySelector('#tau-passphrase').value='durable fixture passphrase';document.querySelector('#tau-unlock').click();});
  await wait(`fixtureReports.at(-1)?.tasks?.length===1`);
  if(name==='mismatched-terminal'){
    await wait("fixtureEvents.filter(e=>e.command_result).length===1 && fixtureReports.at(-1)?.tasks?.[0]?.pause_reason?.includes('Stop task')");
    const configureReport=async(refused=true)=>{const before=await evaluate('fixtureReports.length');await configure(normal);return wait(`fixtureReports.slice(${before}).find(r=>${refused?"r.store_error?.includes('Stop task')":"!r.store_error && r.poc_configuration?.key_set"})`);};
    const beforeResume=await configureReport();
    await acceptActing();
    const paused=await evaluate('fixtureReports.at(-1).tasks[0]');
    const afterResume=await configureReport();
    actionCount=await evaluate('fixtureEvents.filter(e=>e.fixture_action_complete).length');
    await invoke(()=>[...document.querySelectorAll('[data-task] button')].find(b=>b.textContent==='Stop task').click());await actionComplete();
    const abandoned=await evaluate('fixtureReports.at(-1).tasks[0]');
    const configured=await configureReport(false);
    const released=await evaluate('fixtureEvents.filter(e=>e.command_result).map(e=>e.command_result)');
    console.log(JSON.stringify({beforeRefusal:beforeResume.store_error,afterRefusal:afterResume.store_error,pause:paused.pause_reason,releases:released.length}));
    check(released.length===1&&released[0].agreement==='finding','mismatched original terminal releases protected advisory finding');
    check(paused.completed.length===0&&JSON.stringify(paused.pending)===JSON.stringify(abandoned.pending)&&abandoned.status==='abandoned','Abandon retains original pending identity without settling mismatched work');
    check(!configured.store_error&&configured.poc_configuration.key_set,'configuration succeeds after explicit Abandon');
    check((await control({inspect:true})).launches.length===1,'mismatch recovery never relaunches command');
    check([beforeResume,afterResume].every(r=>r.store_error?.includes('Stop task')&&r.store_error?.includes('holds remain')&&!r.poc_configuration.key_set),'mismatch configuration refusal gives actionable Abandon guidance');
    check(paused.pause_reason.includes('Stop task')&&paused.pause_reason.includes('holds remain'),'mismatch pause explains local escape and retained remote effects');
  }else{
  if(['reload-key','reload-progress'].includes(name)){
    await point('poc_progress_publication');
    const before=await evaluate('fixtureReports.length');await configure(normal);await wait(`fixtureReports.length>${before}`);
    const report=await evaluate('fixtureReports.at(-1)');
    console.log(JSON.stringify({configuration:report.store_error,key_set:report.poc_configuration?.key_set}));
    check(report.store_error?.includes('command response pending')&&!report.poc_configuration.key_set,'configuration gives explicit recovery before registering any credential');
    check(await evaluate(`document.querySelector('#tau-poc-key').value===''`),'refused recovery configuration clears input');
    await release('poc_progress_publication');
  }
  await acceptActing();
  if(collecting){
    for(let attempt=0;attempt<600;attempt++){
      if((await control({inspect:true})).execs.some(e=>e.startsWith('# tau-web job read '+original.job)))break;
      await new Promise(resolve=>setTimeout(resolve,100));
    }
    const before=await evaluate('fixtureReports.length');await configure(normal);await wait(`fixtureReports.length>${before}`);
    check(await evaluate(`fixtureReports.at(-1).store_error==='inference configuration refused: command response pending; retry after it completes'&&!fixtureReports.at(-1).poc_configuration.key_set`),'keyless production collection reserves inventory without inference');
    await control({release:true});
  }
  await wait('fixtureReports.at(-1)?.tasks?.[0]?.pending===null && fixtureEvents.filter(e=>e.command_result).length===1');
  const recovered=await evaluate('fixtureReports.at(-1).tasks[0]');
  const released=await evaluate('fixtureEvents.filter(e=>e.command_result).map(e=>e.command_result)');
  console.log(JSON.stringify({recovered,releases:released.length,fixture:await control({inspect:true})}));
  check(recovered.pending===null&&recovered.completed.length===1&&recovered.status==='running'&&recovered.requests===1,'original result checkpoints without spending a request while the key is missing');
  check(released.length===1&&released[0].stdout===output&&released[0].exit_status===0,'recovery releases one useful full result');
  check(await evaluate(`Array.from(document.querySelectorAll('[data-command-result] pre')).some(e=>e.textContent===${JSON.stringify(output)})`),'recovered result renders in actual page');
  await resume();await actionComplete();
  check(await evaluate('fixtureEvents.filter(e=>e.command_result).length===1'),'second Resume does not republish or relaunch');
  const seen=await control({inspect:true});
  check(seen.launches.length===1&&seen.launches[0].job===original.job,'recovery never repeats original execution');
  check(seen.execs.filter(e=>e.startsWith('# tau-web job read '+original.job)).length===(collecting?1:0),'only unresolved remote job uses collection');
  await message({fixture:{done:true}});
  const before=await evaluate('fixtureReports.length');await configure(normal);await wait(`fixtureReports.length>${before}`);
  check(await evaluate('!fixtureReports.at(-1).store_error&&fixtureReports.at(-1).poc_configuration.key_set'),'configuration accepted after original result recovery');
  if(name==='reload-key'){
    const history=recovered.completed;
    await wait("fixtureReports.at(-1)?.tasks?.[0]?.status==='paused' && fixtureReports.at(-1)?.tasks?.[0]?.pause_reason?.includes('verification checks')");
    const report=await evaluate('fixtureReports.at(-1)');
    console.log(JSON.stringify({afterConfiguredResume:{error:report.store_error,status:report.tasks[0].status,pause:report.tasks[0].pause_reason,completed:report.tasks[0].completed.length}}));
    check(!report.store_error&&report.tasks[0].status==='paused'&&report.tasks[0].pause_reason?.includes('verification checks'),'configured inference continues from retained history to explicit verification pause');
    check(JSON.stringify(report.tasks[0].completed.slice(0,history.length))===JSON.stringify(history),'configured inference preserves original history');
    check((await control({inspect:true})).launches.length===1,'configured continuation never repeats the completed command');
    const before=await evaluate('fixtureEvents.filter(e=>e.fixture_action_complete).length');
    await invoke(()=>[...document.querySelectorAll('[data-task] button')].find(b=>b.textContent==='Stop task').click());
    await wait(`fixtureEvents.filter(e=>e.fixture_action_complete).length>${before}`);
    check(await evaluate(`!fixtureReports.at(-1).store_error&&fixtureReports.at(-1).tasks[0].status==='abandoned'&&fixtureReports.at(-1).poc_configuration.key_set`),'Abandon remains usable after configured inference continuation');
  }

  }
 }else if(['first-key','first-key-checks','rotation','publication','progress'].includes(name)){
  const appendPoint='poc_terminal_append';
  await point(name==='publication'?'worker_return':appendPoint);
  const attempted=['rotation','publication','progress'].includes(name)?['previous-normal-key-482700','third-normal-key-482700','fourth-normal-key-482700']:[normal];
  const errors=[];
  for(const key of attempted){const before=await evaluate('fixtureReports.length');await configure(key);if(name!=='publication') {await release(appendPoint);} await wait(`fixtureReports.length>${before}`);errors.push(await evaluate('fixtureReports.at(-1).store_error'));}
  await message({fixture:{counts:true}});const counts=await wait('fixtureEvents.find(e=>e.fixture_counts)?.fixture_counts');
  console.log(JSON.stringify({counts,errors,fixture:await control({inspect:true}),lastReport:await evaluate('fixtureReports.at(-1)')}));
  if(name!=='publication')await point('poc_execution_return');
  check(errors.every(e=>e==='inference configuration refused: command response pending; retry after it completes'),'configuration refuses throughout runner response');
  check(await evaluate(`document.querySelector('#tau-poc-key').value===''`),'page clears attempted key');
  check(await evaluate(`document.querySelector('#tau-poc-key-status').textContent===${JSON.stringify(keyless?'Key unset.':'Key set.')}`),'busy response retains truthful key custody');
  if(name==='progress') {
    await hold('poc_progress_publication');
    await release('poc_execution_return');
    await point('poc_progress_publication');
    const before=await evaluate('fixtureReports.length');await configure(attempted[0]);await wait(`fixtureReports.length>${before}`);
    check(await evaluate(`fixtureReports.at(-1).store_error==='inference configuration refused: command response pending; retry after it completes'`),'progress publication retains response reservation');
    await release('poc_progress_publication');
  } else await release(name==='publication'?'worker_return':'poc_execution_return');
  await actionComplete();
  await wait(`fixtureReports.at(-1)?.tasks?.[0]?.status==='paused'`);
  check(await evaluate(`fixtureReports.at(-1).tasks[0].completed.length>0`),'committed result survives page publication');
  const released=await evaluate('fixtureEvents.filter(event=>event.command_result).map(event=>event.command_result)');
  check(released.length===(name==='first-key-checks'?2:1)&&released[0].stdout===output&&released[0].stderr===''&&released[0].exit_status===0,'full terminal output survives actual final result publication');
  check(await evaluate(`Array.from(document.querySelectorAll('[data-command-result] pre')).some(element=>element.textContent===${JSON.stringify(output)})`),'actual page renders the complete released output');
  check(counts.terminals===1&&counts.launches===1&&counts.collectable===0,'one terminal and one original launch');
  const before=await evaluate('fixtureReports.length');await configure(attempted.at(-1));await wait(`fixtureReports.length>${before}`);
  check(await evaluate(`!fixtureReports.at(-1).store_error && document.querySelector('#tau-poc-key-status').textContent==='Key set.'`),'same configuration succeeds after final release');
  if(['first-key','first-key-checks'].includes(name)){
    const saved=await evaluate('fixtureReports.at(-1).tasks[0]');
    await resume();await actionComplete();
    const resumed=await evaluate('fixtureReports.at(-1)');
    console.log(JSON.stringify({postConfiguration:resumed}));
    const resumedUsable=!resumed.store_error&&resumed.tasks[0].revision>saved.revision&&resumed.tasks[0].status==='paused';
    check(resumed.tasks[0].completed.length===saved.completed.length&&JSON.stringify(resumed.tasks[0].completed)===JSON.stringify(saved.completed),'Resume retains complete original task history');
    if(name==='first-key-checks')check(saved.verification.length===1&&saved.verification[0].exit_status!==0,'nonempty operator check executed through production verification');
    const before=await evaluate('fixtureEvents.filter(e=>e.fixture_action_complete).length');
    await invoke(()=>[...document.querySelectorAll('[data-task] button')].find(b=>b.textContent==='Stop task').click());
    await wait(`fixtureEvents.filter(e=>e.fixture_action_complete).length>${before}`);
    const abandoned=await evaluate('fixtureReports.at(-1)');
    const abandonedUsable=!abandoned.store_error&&abandoned.tasks[0].status==='abandoned'&&abandoned.poc_configuration.key_set;
    console.log(JSON.stringify({metadataActions:{resume:resumedUsable,abandon:abandonedUsable,resumeError:resumed.store_error,abandonError:abandoned.store_error}}));
    check(resumedUsable&&abandonedUsable,'post-configuration Resume records a concrete pause and Abandon succeeds with configured custody');
  }

 }else if(name==='configuration'){
  await wait("fixtureEvents.some(e=>e.fixture_action==='requirements')");
  check(await evaluate('fixtureReports.at(-1).tasks[0].requests===0 && !fixtureReports.at(-1).poc_configuration.key_set'),'missing key withholds Request and consumes no budget');
  const before=await evaluate('fixtureReports.length');await configure(normal);await wait(`fixtureReports.slice(${before}).some(r=>r.poc_configuration?.key_set&&!r.store_error)`);
  const report=await evaluate(`fixtureReports.slice(${before}).find(r=>r.poc_configuration?.key_set&&!r.store_error)`);
  console.log(JSON.stringify({configuration:report.store_error,key_set:report.poc_configuration?.key_set,pending:report.tasks[0].pending,fixture:await control({inspect:true})}));
  check(!report.store_error&&report.poc_configuration.key_set===true,'missing inference prerequisite has no command reservation and accepts configuration');
  check(await evaluate(`document.querySelector('#tau-poc-key').value==='' && document.querySelector('#tau-poc-key-status').textContent==='Key set.'`),'page clears the new key and reports actual custody');
  await wait(`fixtureReports.at(-1)?.tasks?.[0]?.status==='paused' && fixtureReports.at(-1).tasks[0].completed.length===2`);
  check(await evaluate('fixtureReports.at(-1).tasks[0].completed.length===2'),'key resupply continues the approved task successfully');
 }else if(name==='resolver'){
  await wait("fixtureEvents.some(e=>e.fixture_action==='requirements')");
  const report=await evaluate('fixtureReports.at(-1)');
  const text=JSON.stringify(report), secret='unsupported-key-4827';
  check(report.store_error?.includes('unsupported relay profile')&&report.tasks[0].status==='running'&&!report.tasks[0].pending,'runner reports unsupported-profile refusal after releasing only the declaration pause');
  check(!text.includes(secret)&&!text.includes(Buffer.from(secret).toString('base64').replace(/=+$/,'')),'runner protects both dynamic profile and composed refusal under current inventory');
  check((await control({inspect:true})).contacts===0&&report.tasks[0].requests===0,'runner resolver refuses before contact or inference');
 }else if(name==='aggregate'){
  await wait("fixtureEvents.some(e=>e.fixture_action==='requirements')");
  await message({fixture:{counts:true}});const counts=await wait('fixtureEvents.find(event=>event.fixture_counts)?.fixture_counts');
  const report=await evaluate('fixtureReports.at(-1)');
  console.log(JSON.stringify({counts,report}));
  check(counts.terminals===2&&counts.collectable===0&&counts.launches===2,'both distinct results committed once without inventory changes');
  const released=await evaluate('fixtureEvents.filter(event=>event.command_result).map(event=>event.command_result)');
  check([output,secondOutput].every(output=>released.some(row=>row.stdout===output)),'each full committed result leaves the real worker despite aggregate history capacity');
  check(released.length===2&&new Set(released.map(row=>row.call)).size===2,'one individual publication for each committed result');
  check(await evaluate('document.querySelectorAll("[data-command-result]").length===2'),'actual page displays both independently released results');
 }else if(name==='interruption'){
  await resume();await wait(`fixtureReports.at(-1)?.tasks?.[0]?.pending`);
  let seen;
  for(let attempt=0;attempt<600;attempt++){
    seen=await control({inspect:true});if(seen.launches.length===1)break;
    await new Promise(resolve=>setTimeout(resolve,100));
  }
  check(seen.launches.length===1,'one original launch before interruption');
  const originalJob=seen.launches[0].job;
  await evaluate('fixtureWorkers.at(-1).terminate()');await call('Page.reload',{},sessionId);
  await wait(`document.querySelector('#tau-store')?.dataset.state==='locked'`);
  await new Promise(resolve=>setTimeout(resolve,info.relay_spacing_ms+50));
  if(['reload-key','reload-progress'].includes(name))await hold('poc_progress_publication');
  await invoke(()=>{document.querySelector('#tau-passphrase').value='durable fixture passphrase';document.querySelector('#tau-unlock').click();});
  await wait(`fixtureReports.at(-1)?.tasks?.length===1`);
  await acceptActing();
  await message({fixture:{command:'true'}}); // Resumed transcript must drive done, never another exec.
  await message({fixture:{command:undefined,done:true}});
  for(let attempt=0;attempt<600;attempt++){
    seen=await control({inspect:true});if(seen.execs.some(exec=>exec.startsWith('# tau-web job read '+originalJob)))break;
    await new Promise(resolve=>setTimeout(resolve,100));
  }
  console.log(JSON.stringify({resumeReport:await evaluate('fixtureReports.at(-1)'),seen}));
  check(seen.execs.some(exec=>exec.startsWith('# tau-web job read '+originalJob)),'Resume collects the original pending job');
  const busyBefore=await evaluate('fixtureReports.length');await configure(normal);
  const busy=await wait(`fixtureReports.slice(${busyBefore}).find(r=>r.store_error==='inference configuration refused: command response pending; retry after it completes')`);
  check(!busy.poc_configuration.key_set && await evaluate(`document.querySelector('#tau-poc-key').value==='' && document.querySelector('#tau-poc-key-status').textContent==='Key unset.'`),'page configuration stays truthful and clears input while collection waits');
  await control({release:true});
  await wait('fixtureReports.at(-1)?.tasks?.[0]?.pending===null && fixtureReports.at(-1)?.tasks?.[0]?.completed?.length===1');
  await new Promise(resolve=>setTimeout(resolve,info.relay_spacing_ms+50));
  await configure(normal);await wait(`fixtureReports.at(-1)?.poc_configuration?.key_set`);
  let afterCollection=await evaluate('fixtureReports.at(-1).tasks[0]');
  console.log(JSON.stringify({afterCollection}));
  if(afterCollection.pause_reason?.includes('pace')&&afterCollection.proposal?.check===0){
    await new Promise(resolve=>setTimeout(resolve,1100));await resume();await actionComplete();
  }
  await wait(`fixtureReports.at(-1)?.tasks?.[0]?.pause_reason?.includes('verification command failed')`);
  seen=await control({inspect:true});
  check(seen.launches.filter(l=>l.command===command).length===1,'Resume never relaunches original command');
  check(seen.execs.filter(exec=>exec.startsWith('# tau-web job read '+originalJob)).length===1,'original job collected exactly once');
  const task=await evaluate('fixtureReports.at(-1).tasks[0]');
  check(task.verification[0].exit_status!==0&&task.status==='paused','failed verification keeps task resumable');
  const freeBefore=await evaluate('fixtureReports.length');await configure(normal);await wait(`fixtureReports.length>${freeBefore}`);
  check(await evaluate('!fixtureReports.at(-1).store_error'),'configuration succeeds after collection response');
  await control({verify:true});
  await invoke(()=>[...document.querySelectorAll('[data-task] button')].find(button=>button.textContent==='Prepare verification retry').click());
  await wait(`fixtureReports.at(-1)?.tasks?.[0]?.verification?.length===0`);
  await resume();await actionComplete();await wait(`fixtureReports.at(-1)?.tasks?.[0]?.status==='complete'`);
  check(true,'only passing verification completes the task');
 }else{
  console.log(JSON.stringify({case:name,command_bytes:command.length,largest_accepted_command:info.largest}));
  const revision=await evaluate('fixtureReports.at(-1).tasks[0].revision');
  await resume();await actionComplete();await wait(`fixtureReports.at(-1)?.tasks?.[0]?.revision>${revision} && fixtureReports.at(-1)?.tasks?.[0]?.status==='paused'`);
  const task=await evaluate('fixtureReports.at(-1).tasks[0]');console.log(JSON.stringify({task,fixture:await control({inspect:true})}));
  const seen=await control({inspect:true});
  if(name==='wire-too-long') {
    check(task.completed.length===0&&task.pending===null&&task.pause_reason.includes('too long'),'one byte above largest command refuses with LaunchTooLong');
    check(seen.contacts===0&&seen.execs.length===0,'oversized launch refuses before any relay contact');
  } else {
    check(task.completed.length>0,'accepted command reaches bounded relay: '+task.pause_reason);
    check(seen.launches.length===1&&seen.launches[0].command===command,'boundary command launched exactly once');
    check(seen.binary_sizes.length>0&&Math.max(...seen.binary_sizes)<=65536&&seen.wire_errors.length===0,'every message and frame remains within 65536 bytes');
  }
 }
 console.log(JSON.stringify({case:name,fixture:await control({inspect:true})}));
 await evaluate('fixtureWorkers.at(-1).terminate()');
 await call('Browser.close');await once(browser,'exit');
 }
 }
}finally{
 clearTimeout(watchdog);socket?.close();
 if(browser?.pid&&browser.exitCode===null&&browser.signalCode===null){const exited=once(browser,'exit');browser.kill('SIGKILL');await exited;}
 await new Promise(resolve=>server.close(resolve));
 if(profile)await rm(profile,{recursive:true,maxRetries:10,retryDelay:50});
 if(fixture.exitCode===null&&fixture.signalCode===null){const exited=once(fixture,'exit');fixture.stdin.end('{"stop":true}\n');await exited;}
}
