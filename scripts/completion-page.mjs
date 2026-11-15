import assert from 'node:assert/strict';
export const completionCases = ['delivery-web','delivery-local','delivery-report-failure','delivery-report-stopped','delivery-reject','delivery-unknown'];
export const minimum = {version:2,listeners:{inbound:[{proto:'tcp',port:22,from:'any'}],outbound:[]},services:[],key_material:{spendable:false,permitted:[]},drift_checks:[],required:[],default_credentials:'none'};
export async function completionProof(c) {
 const {name,info,inferenceEndpoint,call,sessionId,evaluate,invoke,wait,click,configure,control,check,pageOrigin,message,hold,point,release}=c;
 const local=name==='delivery-local', service=local?'redis':'nginx',port=local?6379:80;
 const d=structuredClone(minimum);
 d.listeners.inbound.push({proto:'tcp',port,from:local?'none':'any'});
 d.services.push({name:service,scope:{kind:'system'},lifecycle:'enabled-survives-reboot'});
 const reports=name==='delivery-report-failure'?[`sleep ${info.relay_spacing_ms/1000+0.05}; printf functional-output-482700; exit 1`]:name==='delivery-report-stopped'?[`systemctl stop ${service}; printf success`]:[];
 await control({reads:{listeners:`tcp LISTEN 0 128 ${local?'127.0.0.1':'0.0.0.0'}:${port} *:*\n`}});
 await control({inference:{key:'normal-synthetic-key-482700',declaration:d,commands:[{checks:reports}]}});
 await call('Page.navigate',{url:pageOrigin+'/'},sessionId);
 await wait("document.querySelector('#tau-store')?.dataset.state==='none'");
 await invoke(()=>{document.querySelector('#tau-passphrase').value=document.querySelector('#tau-confirm').value='durable fixture passphrase';document.querySelector('#tau-create').click();});
 await wait("!document.querySelector('#tau-seed-backup-answer').disabled");await click('#tau-seed-backup-answer');
 await wait("!document.querySelector('#tau-seed-backup-skip').disabled");await click('#tau-seed-backup-skip');
 await configure('normal-synthetic-key-482700');await wait('fixtureReports.at(-1)?.poc_configuration?.key_set');
 await invoke(info=>{for(const [id,value]of Object.entries({machine:'machine-a',relay:info.relay,profile:'v1',host:'127.0.0.1',port:info.port,user:'tracer',elevation:'none',pin:info.pin,class:'no'}))document.querySelector('#tau-poc-'+id).value=value;document.querySelector('#tau-poc-approve-existing').checked=document.querySelector('#tau-poc-approve-access').checked=true;document.querySelector('#tau-poc-target-form').requestSubmit();},info);
 await wait('fixtureReports.at(-1)?.poc_targets?.length===1');
 await invoke(()=>[...document.querySelectorAll('#tau-poc-targets button')].find(b=>b.textContent==='Show public keys machine-a').click());
 const keys=await wait('fixtureReports.at(-1)?.poc_keys');assert.equal((await control({keys})).installed,true);
 await invoke(goal=>{document.querySelector('#tau-poc-targets [data-start-goal]').value=goal;[...document.querySelectorAll('#tau-poc-targets button')].find(b=>b.textContent==='Start session machine-a').click();},local?'Run a Redis server for programs on this machine only, started at boot':'Serve a small page with nginx, started at boot');
 await wait("document.querySelector('[data-requirements-decision=approve]')");
 assert.equal(await evaluate("document.querySelectorAll('[data-start-checks],[data-poc-declaration],[data-poc-propose]').length"),0);
 assert.equal((await control({inspect:true})).launches.length,0);
 const preview=await evaluate("document.querySelector('[data-requirements-card]').innerText");
 assert.ok(preview.includes(service)&&preview.includes(`TCP port ${port}`)&&preview.includes('not checked in this PoC'));
 assert.ok(await evaluate(`document.querySelector('[data-requirements-card] strong').textContent.includes(${JSON.stringify(service)})`));
 assert.deepEqual(await evaluate("JSON.parse(document.querySelector('[data-requirements-card] details pre').textContent)"),d);
 if(name==='delivery-reject') {
  await click('[data-requirements-decision=reject]');
  await wait("fixtureReports.at(-1)?.tasks?.[0]?.pause_reason?.includes('rejected')");
  assert.equal((await control({inspect:true})).launches.length,0);
  assert.equal(await evaluate('fixtureReports.at(-1).tasks[0].completed[0][2].content.rejected.includes("rejected")'),true);
  await invoke(()=>[...document.querySelectorAll('[data-task] button')].find(b=>b.textContent==='Resume').click());
  await wait("document.querySelector('[data-requirements-decision=approve]')");
  assert.ok(JSON.stringify((await control({inspect:true})).inference_bodies.at(-1)).includes('rejected'));
  assert.equal((await control({inspect:true})).launches.length,0);
 }
 if(name==='delivery-unknown')await hold('pending_launch_committed');
 await click('[data-requirements-decision=approve]');
 if(name==='delivery-unknown') {
  await point('pending_launch_committed');
  const original=await evaluate('fixtureReports.at(-1).tasks[0]');
  assert.equal(original.proposal.check,0);
  await click('#tau-lock');await release('pending_launch_committed');
  await wait("document.querySelector('#tau-store')?.dataset.state==='locked'");
  await new Promise(resolve=>setTimeout(resolve,info.relay_spacing_ms+50));
  await invoke(()=>{document.querySelector('#tau-passphrase').value='durable fixture passphrase';document.querySelector('#tau-unlock').click();});
  await wait("fixtureReports.at(-1)?.tasks?.[0]?.status==='paused' && document.querySelector('[data-pending-assumption]')");
  assert.equal(await evaluate('fixtureReports.at(-1).tasks[0].pending.job'),original.pending.job);
  await configure('normal-synthetic-key-482700');
  await wait('fixtureReports.at(-1)?.poc_configuration?.key_set');
  await click('[data-pending-assumption=as_if_not_done]');
  await invoke(()=>[...document.querySelectorAll('[data-task] button')].find(b=>b.textContent==='Confirm unknown outcome').click());
  await wait("fixtureReports.at(-1)?.tasks?.[0]?.pause_reason==='Findings unknown until a complete re-check'");
  const task=await evaluate('fixtureReports.at(-1).tasks[0]');
  assert.equal(task.verdict,null);assert.equal(task.status,'paused');
  assert.equal(task.verification[0].observation,null);
  await assertVisibleResult(task,'Findings unknown until a complete re-check',false);
  assert.equal((await control({inspect:true})).launches.length,0);
  check(true,'unsettled harness read shows unknown wording in the visible task card');
  return;
 }
 async function assertVisibleResult(task,words,enabled=true) {
  const visible=await invoke(({id,words})=>{
   const card=[...document.querySelectorAll('[data-task]')].find(e=>e.dataset.task===id);
   const result=[...card.children].find(e=>e.tagName==='P'&&e.textContent===words);
   return {result:!!result?.checkVisibility(),notes:[...card.children].filter(e=>e.tagName==='P'&&e.checkVisibility()).map(e=>e.textContent),text:card.innerText};
  },{id:task.id,words});
  assert.equal(visible.result,true,`visible task card must show exact result: ${words}`);
  if(enabled)assert.ok(visible.notes.includes(`${service}: enabled, restart not demonstrated`),'enabled note beside task result');
  if(words==='Handed over with findings')for(const finding of task.findings)assert.ok(visible.notes.includes(finding.detail),'finding visible on its task card');
 }
 const stopped=name==='delivery-report-stopped';
 await wait('fixtureReports.at(-1)?.tasks?.[0]?.verdict');
 let task=await evaluate('fixtureReports.at(-1).tasks[0]');
 assert.equal(task.verdict,stopped?'Handed over with findings':'Delivered (service and TCP checks only)');
 assert.equal(task.status,stopped?'paused':'complete');
 await assertVisibleResult(task,task.verdict,!stopped);
 assert.deepEqual(task.verification.map(v=>v.command),[`systemctl is-active -- '${service}'.service`,`systemctl is-enabled -- '${service}'.service`,'ss -H -n -l -t -u']);
 assert.ok(task.verification.every(v=>v.job&&v.exit_status!==null&&v.observation));
 assert.ok(task.completed.findIndex(s=>s[1].name==='done')<task.completed.findIndex(s=>s[0].startsWith('$verify:')));
 if(reports.length) {
  const placement=await invoke(id=>{
   const card=[...document.querySelectorAll('[data-task]')].find(e=>e.dataset.task===id);
   const reports=[...card.children].find(e=>e.tagName==='SECTION'&&e.firstElementChild?.textContent==='Checks the AI wrote — not part of Delivered');
   const outside=card.cloneNode(true);[...outside.children].find(e=>e.tagName==='SECTION'&&e.firstElementChild?.textContent==='Checks the AI wrote — not part of Delivered')?.remove();
   return {labelVisible:!!reports?.firstElementChild.checkVisibility(),inside:reports?.textContent,outside:outside.textContent,done:[...card.querySelectorAll('details pre')].map(e=>JSON.parse(e.textContent)).find(e=>e.tool?.name==='done')};
  },task.id);
  assert.equal(placement.labelVisible,true);
  for(const report of task.reports) {
   for(const text of [report.command,report.excerpt]) {
    assert.ok(placement.inside.includes(text));
    assert.ok(!placement.outside.includes(text),'optional command/output occurs only under its neutral label, including collapsed Details');
   }
   assert.ok(placement.inside.includes(`${report.command}; ${report.status}; exit ${report.exit_status}`));
  }
  assert.equal(placement.done.tool.arguments.machine,'machine-a');
  assert.equal(placement.done.tool.arguments.checks,undefined);
  assert.equal(placement.done.outcome.content.verification_required,true);
  assert.equal(task.reports[0].exit_status,stopped?0:1);
 }
 if(stopped) {
  assert.ok(task.findings.some(f=>f.detail.includes('declared lifecycle')));
  await control({reads:{active:'active'}});
  await invoke(()=>[...document.querySelectorAll('[data-task] button')].find(b=>b.textContent==='Prepare complete re-check').click());
  await wait('fixtureReports.at(-1)?.tasks?.[0]?.verification?.length===0');
  await invoke(()=>[...document.querySelectorAll('[data-task] button')].find(b=>b.textContent==='Resume').click());
  await wait("fixtureReports.at(-1)?.tasks?.[0]?.status==='complete'");
  task=await evaluate('fixtureReports.at(-1).tasks[0]');
  assert.equal(task.completed.filter(s=>s[0].startsWith('$report:')).length,1);
  await assertVisibleResult(task,'Delivered (service and TCP checks only)');
 }
 assert.ok(await evaluate("document.querySelector('[data-task]').innerText.includes('enabled, restart not demonstrated')"));
 const observed=await control({inspect:true});
 assert.deepEqual(observed.inference_bodies[0].tools.map(t=>t.function.name),['propose_declaration']);
 assert.ok(observed.inference_bodies.slice(name==='delivery-reject'?2:1).every(b=>b.tools.map(t=>t.function.name).join(',')==='exec,done'));
 check(true,'goal-only Start, exact installation preview, explicit approval, journaled reads and qualified delivery');
}
