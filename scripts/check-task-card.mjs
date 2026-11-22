// Offline page render regression: real DOM/CSS at phone widths, no worker or service calls.
import assert from 'node:assert/strict';
import {readFile, writeFile, mkdtemp, rm} from 'node:fs/promises';
import {spawn} from 'node:child_process';
import {join, resolve} from 'node:path';
import {pathToFileURL} from 'node:url';

const boot = await readFile('www/boot.js', 'utf8');
const prefix = boot.slice(0, boot.indexOf('\nlet worker;'));
const html = (await readFile('www/index.html', 'utf8'))
  .replace(/<meta http-equiv="Content-Security-Policy"[^>]*>/, '')
  .replace('<script type="module" src="boot.js"></script>', '');
function checkCard(expectedWidth) {
  if (innerWidth !== expectedWidth) throw Error(`wrong phone viewport: ${innerWidth}`);
  const check = (ok, label) => { if (!ok) throw Error(label); };
  const task = {id:'task-a', machine:'test machine', start_session:'session-a', status:'running', goal:'Install a service.',
    template:'control-center@1', block_origins:{}, requests:10, steps:23, limits:{requests:100,steps:200},
    completed:[], verification:[], cycle_timings:[{cycle:1}], reply_tools:['run_step_block']};
  const store = {state:'unlocked', seed_backup_stage:'inactive', lifecycle_state:'running', lifecycle_generation:1,
    credit:{can_start:true}, procurement:{machine:'test machine',phase:'handed_off'},
    poc_targets:[{machine:'test machine'}],
    sessions:[{identity:'session-a',session_state:'active',bound_set:['test machine']}], tasks:[task]};
  const append = (step, block, exit = 0) => {
    const id = 'call-' + task.completed.length;
    task.completed.push([id, {name:'exec', arguments:{command:'true # ' + id}}, {content:{exit_status:exit,job:id}}]);
    task.block_origins[id] = {step,block};
  };
  for (let i = 1; i <= 5; i++) { append(i,'Do'); append(i,'Wait'); append(i,'Check'); }
  const card = () => document.querySelector('[data-task="task-a"]');
  const rows = () => [...card().querySelectorAll('p')].map(p => p.textContent);
  const button = text => [...card().querySelectorAll('button')].find(b=>b.textContent===text);
  const renderCard = () => render(store, true);
  const measure = () => ({nodes:card().querySelectorAll('*').length, status:card().querySelector('[data-task-status]').getBoundingClientRect().height,
    help:button('What if I close this page?').getBoundingClientRect().top, resume:button('Resume').getBoundingClientRect().top});
  // Count creations, not just the final DOM: building then throwing away 60 rows must fail too.
  const createElement = document.createElement.bind(document);
  let created = 0;
  document.createElement = (...args) => { created++; return createElement(...args); };
  renderCard();
  check(!rows().some(s=>s.startsWith('Ran: ')), 'raw commands start folded');
  check(card().dataset.completedCommands==='15', 'numeric harness fallback count');
  check(card().querySelectorAll('details')[0].open===false, 'completed steps start folded');
  check(rows().filter(s=>/^Step \d+:/.test(s)).length===5, 'one summary per step');
  check(rows().includes('Step 5: install the AI agent and its dashboard, done. '), 'named step completion');
  check(button('Resume').checkVisibility(), 'controls are visible at the phone viewport');
  const base = measure();
  const counts = [];
  for (let i=0;i<70;i++) {
    append(5, 'Check');
    created=0; renderCard();
    counts.push(created);
    check(JSON.stringify(measure())===JSON.stringify(base), 'folded 60+ commands keep node count, status height and controls fixed');
  }
  check(new Set(counts).size===1, 'same small creation count on each update');
  // An unchanged poll must not traverse the completed-command array.
  const entries = task.completed;
  task.completed = new Proxy(entries, {get(target,key) {
    if (['filter','find','slice','some',Symbol.iterator].includes(key)) throw Error('history scan during folded poll');
    return Reflect.get(target,key);
  }});
  for (let i=0;i<3;i++) { created=0; renderCard(); check(created===counts[0], 'unchanged poll creates no command rows'); }
  task.completed=entries;
  append(6,'Do');
  task.block_origins.next={step:6,block:'Wait'};
  const proposal={call_id:'next',tool:{name:'exec',arguments:{command:'sleep 240'}}};
  const inspecting='inspecting the recorded job; collection may wait for completion; an active collection must finish or be interrupted before Resume';
  const waiting='recorded job is running; Resume inspects it again';
  // Compare every visible element below each area, including the outer heading, help and controls.
  // Status text itself may wrap inside its reserved area. No scroll anchoring can mask these document coordinates.
  const positionsBelow = area => {
    const bottom=area.getBoundingClientRect().bottom;
    return [...document.querySelectorAll('body *')].filter(node =>
      !node.closest('[data-task-status]') && node.getClientRects().length &&
      node.getBoundingClientRect().height && node.getBoundingClientRect().top>=bottom
    ).map(node => ({tag:node.tagName,id:node.id,top:node.getBoundingClientRect().top+scrollY,bottom:node.getBoundingClientRect().bottom+scrollY}));
  };
  const layout = () => ({belowProgress:positionsBelow($('progress')),belowStatus:positionsBelow(card().querySelector('[data-task-status]'))});
  task.proposal=proposal; renderCard();
  const cycleBase=layout();
  const cycleErrors=[];
  const cycle = (label, update) => {
    update(); renderCard();
    const setup=document.querySelector('[data-progress-step="setup"]');
    if (setup?.dataset.progressState!=='current' || !setup.querySelector('[data-progress-line]')?.textContent.startsWith('Step 6:') || setup.querySelectorAll('[data-progress-strip] > span').length!==12) cycleErrors.push(label+': setup row lost its step or strip');
    const actual=layout();
    for (const key of Object.keys(cycleBase)) if (JSON.stringify(actual[key])!==JSON.stringify(cycleBase[key])) cycleErrors.push(label+': '+key+' moved');
    if (task.pause_reason && !card().querySelector('[data-task-status]').textContent.includes(plainPause(task.pause_reason))) cycleErrors.push(label+': running reason is outside the status area');
  };
  cycle('proposal',()=>{});
  cycle('pending',()=>{task.status='waiting';task.pending={call:86,job:'job-86'};});
  cycle('Inspect',()=>{task.pause_reason=inspecting;});
  cycle('Wait',()=>{task.pause_reason=waiting;});
  cycle('Inspect again',()=>{task.pause_reason=inspecting;});
  cycle('settle',()=>{append(6,'Wait');task.status='running';task.proposal=null;task.pending=null;delete task.pause_reason;});
  cycle('model read',()=>{task.proposal={call_id:'read',tool:{name:'exec',arguments:{command:'true'}}};});
  cycle('read settled',()=>{append(undefined,undefined);delete task.block_origins[task.completed.at(-1)[0]];task.proposal=null;});
  cycle('next proposal',()=>{task.proposal=proposal;});
  check(!cycleErrors.length, 'full Wait cycle at '+expectedWidth+'px: '+cycleErrors.join('; '));
  const sameText=card().querySelector('[data-task-status]').textContent;
  renderCard(); check(card().querySelector('[data-task-status]').textContent===sameText, 'still-running poll has identical text');
  check(card().querySelector('[data-task-status]').textContent.includes('Step 6 of 12'), 'current playbook step');
  const recoveryErrors=[];
  const recovery = (label, update, expected) => {
    update(); renderCard();
    const top=document.querySelector('[data-progress-step="setup"] [data-progress-line]').textContent;
    const current=card().querySelector('[data-task-status] p').textContent;
    if (!top.startsWith(expected==='recovery' ? 'Fixing a problem.' : expected==='numbered' ? 'Step 6:' : 'The AI is working;')) recoveryErrors.push(label+': top progress: '+top);
    if (!current.startsWith(expected==='recovery' ? 'Fixing a problem · ' : expected==='numbered' ? 'Step 6 of 12 · ' : `${taskProgress(task).ran} commands run`)) recoveryErrors.push(label+': card progress: '+current);
  };
  task.block_origins.recovery={step:0,block:'R2'};
  const recoveryProposal={call_id:'recovery',tool:{name:'exec',arguments:{command:'true # recovery'}}};
  recovery('R2 proposal',()=>{task.proposal=recoveryProposal;},'recovery');
  recovery('R2 pending',()=>{task.status='waiting';task.pending={call:87,job:'recovery'};},'recovery');
  recovery('R2 settled',()=>{append(0,'R2');task.status='running';task.proposal=null;task.pending=null;},'recovery');
  recovery('R2 inference gap',()=>{},'recovery');
  recovery('unlabelled read after R2',()=>{append(undefined,undefined);delete task.block_origins[task.completed.at(-1)[0]];},'recovery');
  // Step zero alone is not the recovery label.
  task.block_origins.other={step:0,block:'Do'};
  recovery('non-R2 proposal',()=>{task.proposal={...recoveryProposal,call_id:'other'};},'plain');
  recovery('R2 gap after non-R2 proposal',()=>{task.proposal=null;},'recovery');
  recovery('numbered proposal after R2',()=>{task.proposal=proposal;},'numbered');
  recovery('numbered pending after R2',()=>{task.status='waiting';task.pending={call:88,job:'next'};},'numbered');
  recovery('numbered settled after R2',()=>{append(6,'Wait');task.status='running';task.proposal=null;task.pending=null;},'numbered');
  recovery('numbered inference gap',()=>{},'numbered');
  check(!recoveryErrors.length, 'recovery cycle at '+expectedWidth+'px: '+recoveryErrors.join('; '));
  task.status='running'; task.proposal=null; task.pending=null;
  append(6,'Do',7); task.status='paused'; task.pause_reason='The build failed.'; renderCard();
  check(rows().some(s=>s.startsWith('Failed: step 6,')&&s.includes('failed with code 7')), 'stopped failure visible folded');
  check([...card().querySelectorAll(':scope > p')].some(p=>p.textContent==='The build failed.'), 'real pause keeps its visible reason');
  append(6,'Wait',4); append(6,'Check'); task.status='running'; delete task.pause_reason; renderCard();
  check(rows().includes('2 commands failed; the AI went on.'), 'continued failures visible folded');
  task.completed.push(['key', {name:'request_ai_key',arguments:{application:'Hermes Agent'}}, {content:{status:'created',limit_usd:0.25}}]);
  renderCard(); check(card().querySelectorAll('[data-ai-key-created]').length===1, 'key outcome marker exists while folded');
  check([...card().querySelectorAll('details span')].some(n=>n.textContent.startsWith('Created an AI key for Hermes Agent')), 'key note stays one tap away');
  task.completed.push(['answer',{name:'ask_operator',arguments:{}},{answer:'Later'}]);
  renderCard();
  check([...card().querySelectorAll(':scope > p')].filter(p=>p.textContent==='Answered: Later.').length===1, 'question numbering preserved folded');
  // Exercise the real page dispatcher and button handlers as well as direct report updates.
  button('Show commands').click();
  check(rows().some(s=>s==='Ran: step 6, let the agent install more later (failed with code 7)'), 'original raw line text');
  check(card().querySelectorAll('[data-ai-key-created]').length===1, 'no duplicate key outcome marker expanded');
  const raw= [...card().querySelectorAll('pre[data-raw-json]')].map(p=>JSON.parse(p.textContent));
  check(raw.filter(v=>v.tool?.name==='exec').length===entries.filter(([,t])=>t.name==='exec').length, 'all raw command records retained');
  renderCard(); check(button('Hide commands'), 'commands choice survives redraw');
  check([...card().querySelectorAll(':scope > p')].filter(p=>p.textContent==='Answered: Later.').length===1, 'question numbering preserved expanded');
  store.tasks.push({...task,id:'task-b',completed:[],block_origins:{}}); renderCard();
  check(document.querySelector('[data-task="task-b"] [data-commands]').textContent==='Show commands', 'commands fold is per card');
  store.tasks.pop();
  button('Hide commands').click();
  button('What if I close this page?').click();
  check(rows().includes('Unlock and enter any key the page asks for. Work that can continue picks up then. The task keeps the same session, machine, approvals and limits. If it stays paused, press Resume.'), 'closure disclosure keeps its meaning');
  check(card().dataset.replyTools===JSON.stringify(task.reply_tools)&&card().dataset.cycleTimings===JSON.stringify(task.cycle_timings), 'timing and reply attributes preserved');
  check(card().querySelector('p').textContent==='Setting up test machine: working.', 'first paragraph harness status');
  check(rows().includes('10 of 100 AI replies used; 23 of 200 steps used.'), 'harness limit sentence unchanged');
  taskCardChoices.get(task.id).closeHelp=false;
  task.proposal={call_id:'$rerun:retry',tool:{name:'exec',arguments:{command:'true'}}};
  task.pending={call:99,job:'retry'}; renderCard();
  check([...card().querySelectorAll(':scope > p')].some(p=>p.textContent.startsWith('Running again: ')), 'lane reissue detection preserved');
  check(card().querySelector('[data-task-status]').textContent.includes('Running again: '), 'reissued state stays visible');
  task.proposal=null; task.pending=null;
  task.template=null; renderCard();
  check(card().querySelector('[data-task-status] p').textContent===`${taskProgress(task).ran} commands run`, 'other tasks get plain count');
  task.ai_key_renewal=true; renderCard();
  check(!card().querySelector('[data-commands]')&&!card().querySelector('[data-task-status]'), 'renewal remains step names only');
  check(card().querySelector('p').textContent.startsWith("Renewing Hermes's AI key"), 'renewal wording retained');
  task.ai_key_renewal=false; task.template='control-center@1'; task.completed=[]; task.block_origins={};
  append(1,'Do'); renderCard();
  check(card().querySelector('[data-task-status] p').textContent.endsWith('1 command run'), 'singular command count');
  check(rows().includes('Step 1: look at the machine, done. '), 'Step 1 Do is also its check');
  append(1,'Do',7); renderCard();
  check(rows().some(s=>s==='Step 1: look at the machine, failed with code 7. '), 'failed Step 1 Do is not done');
  return {nodes:base.nodes, created_per_update:counts[0], commands:entries.filter(([,tool])=>tool.name==='exec').length, status_height:base.status};
}
function checkDemoPage() {
  const check = (ok, label) => { if (!ok) throw Error(label); };
  const sent = [];
  const originalPost = worker.postMessage;
  const originalGeneration = worker.generation;
  worker.postMessage = request => sent.push(request);
  const declaration = {version:1, listeners:{inbound:[],outbound:[]}, services:[],
    key_material:{spendable:false,permitted:[]}, drift_checks:[], required:[], default_credentials:'none'};
  const session = {identity:'requirements-session',session_state:'active',bound_set:['demo-machine'],
    goal:{text:'Install a small service',source:'operator'},standing_modes:[],
    pending_requirements:{candidate:'candidate-a',proposal:{kind:'declaration',machine:'demo-machine',declaration}}};
  const store = {state:'unlocked',seed_backup_stage:'inactive',lifecycle_state:'running',lifecycle_generation:1,
    provider_configuration:{key_set:true},procurement:{phase:'email_verification'},
    setup:[{entry:{machine:'demo-machine',vendor:'provider',product:'small',region:'test',cost:{amount:'100',unit:'sat',period:'month'}},
      class:'single-purpose',answer:'no',access:{},declaration:null}],sessions:[session],tasks:[]};
  const report = () => render(structuredClone(store), true);
  const approval = () => document.querySelector('[data-requirements-decision="approve"]');
  const rejection = () => document.querySelector('[data-requirements-decision="reject"]');
  const decisions = () => sent.filter(request => request.requirements_answer);
  try {
    report();
    const fetchButton = $('provider-catalogue');
    check(!$('step-machine-fold').open && !fetchButton.closest('details') && fetchButton.checkVisibility(),
      'fetch is visible with no offers and Machine options closed, even when another machine action is offered');
    const first = approval(), firstReject = rejection();
    report();
    check(approval() === first && rejection() === firstReject, 'identical reports keep both requirements button nodes');
    first.click();
    check(first.disabled && firstReject.disabled, 'a press disables both decision controls on the same card');
    first.click(); firstReject.click();
    check(decisions().length === 1, 'repeat presses on the same card before the next report send exactly one decision');
    report();
    check(approval() !== first && rejection() !== firstReject && !approval().disabled && !rejection().disabled,
      'the next identical report rebuilds a pressed card with enabled buttons');
    check(JSON.stringify(decisions()[0]) === JSON.stringify({requirements_answer:{session:session.identity,machine:'demo-machine',candidate:'candidate-a',decision:'approve'}}),
      'the decision names the displayed session, machine and candidate');
    const beforeCandidate = approval();
    session.pending_requirements.candidate = 'candidate-b'; report();
    check(approval() !== beforeCandidate && !approval().disabled, 'a new candidate updates immediately');
    const second = approval();
    session.pending_requirements.proposal.declaration.services = [{name:'demo-service',scope:{kind:'system'},lifecycle:'running-at-delivery'}];
    report();
    check(approval() !== second && approval().closest('[data-requirements-card]').textContent.includes('demo-service must be running'),
      'changed requirements update their text even when the candidate is unchanged');
    second.click();
    check(decisions().length === 1, 'a replaced card cannot send a stale decision');
    rejection().click(); rejection().click(); approval().click();
    check(decisions().length === 2 && decisions()[1].requirements_answer.decision === 'reject', 'Reject also sends once before the next report');
    const pressedReject = rejection(); report();
    check(rejection() !== pressedReject && !approval().disabled && !rejection().disabled,
      'the next identical report also rebuilds a rejected card with enabled buttons');
    session.pending_requirements = null; report();
    check(!approval() && !rejection(), 'a recorded decision removes the requirements controls immediately');
    session.pending_requirements = {candidate:'candidate-c',proposal:{kind:'tighten_class',machine:'demo-machine'}}; report();
    const beforeGeneration = approval();
    worker.generation = 'replacement-generation'; report();
    check(approval() !== beforeGeneration, 'a worker authority change replaces the controls');
    beforeGeneration.click();
    const beforeLifecycle = approval(); store.lifecycle_generation++; report();
    check(approval() !== beforeLifecycle, 'a lifecycle authority change replaces the controls');
    beforeLifecycle.click();
    check(decisions().length === 2, 'retired controls cannot answer in a new authority context');
    // Refusals leave the pending proposal intact; even repeated refusal text must permit another decision.
    store.store_error = 'journal refused'; store.page_error_step = 'task'; report();
    for (const refusals of [1, 2]) {
      const beforeRefusals = decisions().length;
      for (let attempt = 1; attempt <= refusals; attempt++) {
        const refusedApprove = approval(), refusedReject = rejection();
        refusedApprove.click(); refusedApprove.click(); refusedReject.click();
        check(decisions().length === beforeRefusals + attempt
          && decisions().at(-1).requirements_answer.decision === 'approve',
          `refused Approve ${attempt} of ${refusals} sends exactly one decision on its card`);
        report();
        check(approval() !== refusedApprove && rejection() !== refusedReject && !approval().disabled && !rejection().disabled,
          `identical report after refusal ${attempt} of ${refusals} gives enabled replacement buttons`);
      }
      rejection().click(); rejection().click(); approval().click();
      check(decisions().length === beforeRefusals + refusals + 1
        && JSON.stringify(decisions().at(-1)) === JSON.stringify({requirements_answer:{session:session.identity,machine:'demo-machine',candidate:'candidate-c',decision:'reject'}}),
        `Reject after ${refusals} refused Approves sends exactly one decision for the pending proposal`);
      report();
    }
    delete store.store_error; delete store.page_error_step;
    session.session_state = 'ended'; report();
    check(!approval(), 'ending the session removes the requirements controls');
    session.session_state = 'active'; session.pending_requirements = null;
    const task = {id:'t3-delivery',machine:'demo-machine',start_session:session.identity,status:'complete',goal:session.goal.text,
      requests:1,steps:1,limits:{requests:100,steps:200},verification:[],verdict:'Delivered',
      completed:[['done',{name:'done',arguments:{urls:[{url:'https://app.t3.codes',label:'T3 Code'}]}},{content:{verification_required:true}}]]};
    store.tasks = [task]; report();
    const hint = "If the machine isn't listed in T3 Code yet, pull down to refresh the list.";
    const taskCard = () => document.querySelector('[data-task="t3-delivery"]');
    check(taskCard().textContent.includes(hint) && taskCard().querySelector('[data-delivered-url]').href === 'https://app.t3.codes/',
      'the delivered T3 link includes the exact refresh hint');
    task.completed[0][1].arguments.urls = [{url:'https://service.example',label:'Service'}]; report();
    check(!taskCard().textContent.includes(hint), 'other delivered services keep their wording');
    store.state = 'locked'; report();
    check(!approval(), 'locking leaves no requirements controls');
    return {requirements:'passed',fetch:'passed',t3_hint:'passed',decisions:decisions().length};
  } finally {
    worker.postMessage = originalPost;
    worker.generation = originalGeneration;
  }
}
const directory = await mkdtemp(resolve('.quietprog-card-'));
try {
  // A file URL, stubbed fetch and Worker, and disabled browser networking keep this check offline.
  const script = `globalThis.setInterval=()=>0; globalThis.Worker=class {postMessage(){}}; globalThis.fetch=async()=>({ok:false});\n${prefix}\nconst worker=firstWorker;\n${checkCard.toString()}\n${checkDemoPage.toString()}\nglobalThis.runQuietCardCheck=width=>({...checkCard(width),demo:checkDemoPage()});`;
  const file = join(directory,'card.html');
  await writeFile(file,html.replace('</body>',()=>`<script type="module">${script.replace(/<\/script/gi,'<\\/script')}</script></body>`));
  const failures=[];
  for (const width of [320,390,430]) {
    const args=['--headless','--no-sandbox','--disable-gpu','--disable-background-networking','--disable-component-update','--disable-sync','--disable-default-apps','--no-first-run','--no-proxy-server','--host-resolver-rules=MAP * ~NOTFOUND','--user-data-dir='+join(directory,'profile-'+width),'--remote-debugging-pipe','about:blank'];
    const child=spawn(process.env.CHROME??'/var/tmp/tau-web-manager/ggw14/tools/chromium/bin/chromium',args,{stdio:['ignore','ignore','ignore','pipe','pipe']});
    const stopped=new Promise(resolve=>child.once('exit',resolve));
    let sequence=0, buffer=''; const calls=new Map();
    const timeout=setTimeout(()=>child.kill('SIGKILL'),20000);
    child.stdio[4].on('data',chunk=>{
      buffer+=chunk;
      let end;
      while ((end=buffer.indexOf('\0'))!==-1) {
        const message=JSON.parse(buffer.slice(0,end)); buffer=buffer.slice(end+1);
        if (calls.has(message.id)) {
          const {resolve,reject}=calls.get(message.id); calls.delete(message.id);
          message.error?reject(Error(JSON.stringify(message.error))):resolve(message.result);
        }
      }
    });
    child.once('exit',()=>{for(const {reject} of calls.values())reject(Error('browser exited'));});
    const call=(method,params={},sessionId)=>new Promise((resolve,reject)=>{
      const id=++sequence; calls.set(id,{resolve,reject});
      child.stdio[3].write(JSON.stringify({id,method,params,...(sessionId?{sessionId}:{})})+'\0');
    });
    try {
      const {targetId}=await call('Target.createTarget',{url:'about:blank'});
      const {sessionId}=await call('Target.attachToTarget',{targetId,flatten:true});
      await call('Page.enable',{},sessionId);
      await call('Emulation.setDeviceMetricsOverride',{width,height:844,deviceScaleFactor:1,mobile:true},sessionId);
      await call('Page.navigate',{url:pathToFileURL(file).href},sessionId);
      const result=await call('Runtime.evaluate',{expression:`new Promise(resolve=>{const run=()=>{try{resolve(runQuietCardCheck(${width}));}catch(error){resolve({error:error.stack});}};if(document.readyState==='complete')run();else addEventListener('load',run,{once:true});})`,awaitPromise:true,returnByValue:true},sessionId);
      assert.equal(result.exceptionDetails,undefined,JSON.stringify(result.exceptionDetails));
      if (result.result.value?.error) failures.push({width,error:result.result.value.error});
      console.log(JSON.stringify({width,...result.result.value}));
    } finally {child.kill('SIGTERM'); await stopped; clearTimeout(timeout);}

  }
  assert.deepEqual(failures,[],JSON.stringify(failures));
} finally {await rm(directory,{recursive:true,force:true});}
