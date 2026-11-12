import assert from 'node:assert/strict';

export const edgeCases = ['edge-start-wording', 'edge-paid-invoices', 'edge-focus-provider', 'edge-focus-target', 'edge-focus-goal', 'edge-focus-verification', 'edge-focus-limits', ...['reload', 'lock', 'loss', 'answered', 'cutoffs', 'failed'].map(kind => `edge-end-cancel-${kind}`)];

const startButton = "[...document.querySelectorAll('#tau-poc-targets button')].find(b=>b.textContent==='Start session machine-a')";

async function pageReport(c, value) {
  await c.invoke(value => fixtureWorkers.at(-1).dispatchEvent(new MessageEvent('message', {data:{store:value}})), value);
}

async function reopen(c, kind = 'reload') {
  if (kind === 'lock') await c.click('#tau-lock');
  else {
    if (kind === 'loss') await c.evaluate('fixtureWorkers.at(-1).terminate()');
    await c.call('Page.reload', {}, c.sessionId);
  }
  await c.wait("document.querySelector('#tau-store')?.dataset.state==='locked'");
  await c.invoke(() => {
    document.querySelector('#tau-passphrase').value = 'durable fixture passphrase';
    document.querySelector('#tau-unlock').click();
  });
  await c.wait("fixtureReports.at(-1)?.store_state==='unlocked'");
}

export async function edgePaidInvoices(c, {request, report}) {
  await c.message({lifecycle:'hidden'});
  await c.wait("fixtureEvents.some(e=>e.fixture_lifecycle_complete==='hidden')");
  const base = await report();
  const statuses = {paid:'Payment seen; inference credit read.', seen:'Payment seen; balance not read yet.', pending:'Waiting for external payment.', unknown:'Payment status unknown.', expired_unpaid:'This invoice expired unpaid, according to the credit service.', abandoned:'Invoice marked abandoned.'};
  for (const [outcome, sentence] of Object.entries(statuses)) {
    const value = structuredClone(base);
    value.credit.invoices[0].outcome = outcome;
    await pageReport(c, value);
    const actual = await c.evaluate(`(() => {const row=document.querySelector('[data-credit-invoice]');return {text:row.textContent,wallet:row.querySelectorAll('a[href^="lightning:"]').length,copy:[...row.querySelectorAll('button')].filter(n=>n.textContent==='Copy').length,countdown:row.querySelectorAll('[data-invoice-expires]').length,check:document.querySelector('#tau-credit-check').disabled};})()`);
    assert.ok(actual.text.includes('1000 sat. ' + sentence));
    const controls = ['paid', 'seen'].includes(outcome) ? 0 : 1;
    assert.deepEqual([actual.wallet, actual.copy, actual.countdown], [controls, controls, controls], outcome + ' invoice controls');
    assert.equal(actual.check, false, 'account-wide checking stays available');
  }
  for (const is_paid of [false, true]) {
    const value = structuredClone(base);
    value.procurement = {phase:'initial_invoice', vm_id:7, payment:{id:8,vm_id:7,is_paid,expires:new Date(Date.now()+60000).toISOString(),amount:100,tax:2,processing_fee:3,currency:'BTC',data:{lightning:'lnbc1000synthetic'}}};
    await pageReport(c, value);
    const actual = await c.evaluate(`(() => {const row=document.querySelector('#tau-provider-progress');return {text:row.textContent,wallet:row.querySelectorAll('a[href^="lightning:"]').length,copy:[...row.querySelectorAll('button')].filter(n=>n.textContent==='Copy').length,countdown:row.querySelectorAll('[data-invoice-expires]').length,check:[...row.querySelectorAll('button')].filter(n=>n.textContent==='Check now').length};})()`);
    assert.ok(actual.text.includes(`Payment 8 for VM 7: ${is_paid?'paid':'payment pending'};`));
    assert.ok(actual.text.includes('Amount 100, tax 2, processing fee 3 (millisats).'));
    assert.deepEqual([actual.wallet,actual.copy,actual.countdown,actual.check], Array(4).fill(is_paid?0:1), 'machine invoice controls');
  }
  const value = structuredClone(base);
  value.procurement = {phase:'initial_invoice', vm_id:7, payment:{is_paid:false,expires:new Date(Date.now()+1800).toISOString()}};
  // Keep the saved payment shape intact while testing the existing eligibility clock.
  value.procurement.payment = {...base.procurement?.payment,...value.procurement.payment,id:8,vm_id:7,data:{lightning:'lnbc1000synthetic'}};
  await pageReport(c,value);
  await c.wait("document.querySelector('#tau-provider-close').hidden");
  const reports = await c.evaluate('fixtureReports.length');
  await c.wait("!document.querySelector('#tau-provider-close').hidden && !document.querySelector('#tau-provider-close').disabled");
  assert.equal(await c.evaluate('fixtureReports.length'), reports, 'expiry offers Close without another report');
  const sent=await c.evaluate(`(() => {const worker=fixtureWorkers.at(-1),original=worker.postMessage,sent=[];worker.postMessage=data=>sent.push(data);try{document.querySelector('#tau-provider-close').click();}finally{worker.postMessage=original;}return sent;})()`);
  assert.deepEqual(sent,[{provider_request:{action:'close'}}],'expiry retains the same explicit Close handler');
  const expired = structuredClone(value);
  expired.procurement.payment.expires = new Date(Date.now()-60000).toISOString();
  const assertClose = async (value, hidden, disabled, label) => {
    const actual = await c.invoke(value => {
      fixtureWorkers.at(-1).dispatchEvent(new MessageEvent('message', {data:{store:value}}));
      const button = document.querySelector('#tau-provider-close');
      return {hidden:button.hidden,disabled:button.disabled};
    }, value);
    assert.deepEqual(actual,{hidden,disabled},label+' during the report dispatch, before another timer tick');
    console.log(JSON.stringify({closeReport:label,...actual}));
  };
  await assertClose(expired,false,false,'expired unpaid purchase offers Close');
  for (const [label, purchase] of [
    ['paid payment', {...expired.procurement,payment:{...expired.procurement.payment,is_paid:true}}],
    ['saved target', {...expired.procurement,target:{pin:'saved synthetic pin'}}],
    ['cleared purchase', undefined],
    ['closed purchase', {closed:'Purchase closed.'}],
    ['unexpired invoice', {...expired.procurement,payment:{...expired.procurement.payment,expires:new Date(Date.now()+60000).toISOString()}}],
  ]) {
    await assertClose({...expired,procurement:purchase},true,true,label+' withdraws Close');
    await assertClose(expired,false,false,label+' replaced by an eligible purchase restores Close');
  }
  await assertClose({...expired,procurement:{phase:'initial_invoice',vm_id:7}},false,false,'associated VM without a saved invoice offers Close');
  for (const [label, change] of [
    ['locked store', {store_state:'locked'}],
    ['reconciling lifecycle', {lifecycle_state:'reconciling'}],
    ['seed-backup ceremony', {seed_backup_stage:'showing_words'}],
  ]) {
    await assertClose({...expired,...change},false,true,label+' disables eligible Close');
    await assertClose(expired,false,false,label+' completion enables eligible Close');
  }
  await request({action:'check'});
  c.check(true,'paid invoice rows retain amount and status; other rows retain their controls; expiry offers Close without a report');
}

async function startWording(c, {request, report, session}) {
  const assertCredit = async (disabled, reading = false) => {
    const value = await c.evaluate(`({text:document.querySelector('#tau-poc-targets').textContent,byoLine:[...document.querySelectorAll('#tau-poc-targets p:not([data-inference-approval])')].some(n=>n.textContent.startsWith('Inference endpoint:')),disabled:${startButton}.disabled})`);
    assert.ok(!value.text.includes('Start session approves inference using'), 'credit session omits the BYO approval sentence');
    assert.equal(value.byoLine,false, 'credit session omits the BYO endpoint line');
    assert.equal(value.disabled, disabled, 'credit Start eligibility');
    if (reading) assert.ok(value.text.includes('Reading inference credit balance…'), 'balance reading state');
  };
  for (const kind of ['lock','reload']) {
    let releaseBalance, entered;
    const held = new Promise(resolve => entered = resolve);
    c.credit.state.onBalance = () => new Promise(resolve => {releaseBalance = resolve; entered();});
    await reopen(c,kind); await held;
    await assertCredit(true,true);
    releaseBalance(); c.credit.state.onBalance = null;
    await c.wait('fixtureEvents.some(e=>e.fixture_unlock_complete)');
    await c.wait('fixtureReports.at(-1)?.credit?.can_start');
    await assertCredit(false);
  }
  for (const [mode,balance] of [['balance-fail',0.78],['normal',0],['normal',0.78]]) {
    Object.assign(c.credit.state,{mode,balance});
    const before = await report();
    const counts = {invoices:c.credit.state.invoiceCalls,mints:c.credit.state.mintCalls,balance:c.credit.state.requests.filter(r=>r.route==='/credits/balance').length};
    await request(mode==='balance-fail'?{action:'invoice',amount:1000}:{action:'refresh'});
    const base = await report();
    if(mode==='balance-fail') {
      assert.equal(base.credit_error,"Couldn't read inference credit balance.",'actual failed balance read reaches the page');
      assert.equal(base.credit.balance,null);
      assert.equal(base.credit.can_start,false);
      assert.ok(c.credit.state.requests.filter(r=>r.route==='/credits/balance').length>counts.balance,'fixture observed the balance read');
      assert.equal(c.credit.state.invoiceCalls,counts.invoices,'failed preflight creates no invoice');
      assert.equal(c.credit.state.mintCalls,counts.mints,'failed preflight mints no key');
      assert.deepEqual(base.credit.invoices,before.credit.invoices,'paid invoice history stays unchanged');
      assert.deepEqual(base.sessions,before.sessions,'failed balance read preserves the current session');
    }
    for (const selected of [false,true]) for (const key_set of [false,true]) {
      const value = structuredClone(base);
      value.credit.selected = selected;
      value.poc_configuration = {key_set,configuration:{endpoint:c.inferenceEndpoint,model:'example-model'}};
      await pageReport(c,value);
      await assertCredit(mode!=='normal'||balance===0);
      const sent = await c.evaluate(`(() => {const worker=fixtureWorkers.at(-1), original=worker.sendAt, sent=[];worker.sendAt=data=>sent.push(data);try{${startButton}.click();}finally{worker.sendAt=original;}return sent;})()`);
      assert.ok(sent.every(data=>data.credit_request?.action==='start'), 'credit session cannot send poc_bind');
      assert.equal(sent.length,mode==='normal'&&balance>0?1:0,'disabled Start sends nothing');
    }
  }
  const base = await report();
  for (const kind of ['no-account','absent-credit','ended-session']) {
    const ended = kind === 'ended-session';
    const value = structuredClone(base);
    value.credit = ended ? {...base.credit,selected:false} : {account:false,selected:false,can_start:false,balance:null,invoices:[]};
    if (kind === 'absent-credit') delete value.credit;
    value.poc_configuration = {key_set:true,configuration:{endpoint:c.inferenceEndpoint,model:'example-model'}};
    value.sessions = ended ? value.sessions.map(s=>({...s,session_state:'ended'})) : [];
    await pageReport(c,value);
    assert.ok(await c.evaluate("document.querySelector('#tau-poc-targets').textContent.includes('Start session approves inference using example-model on machine-a.')"), 'no account and ended session retain BYO approval');
    assert.equal(await c.evaluate("[...document.querySelectorAll('#tau-poc-targets p')].find(n=>n.textContent.startsWith('Inference endpoint:'))?.textContent"),`Inference endpoint: ${c.inferenceEndpoint}; model: example-model.`,kind+' retains the BYO endpoint and model line');
    assert.equal(await c.evaluate(startButton+'.disabled'),false,kind+' retains enabled BYO Start');
    const sent = await c.evaluate(`(() => {const worker=fixtureWorkers.at(-1),original=worker.sendAt,sent=[];worker.sendAt=data=>sent.push(data);try{${startButton}.click();}finally{worker.sendAt=original;}return sent;})()`);
    assert.deepEqual(sent,[{poc_bind:{machine:'machine-a'}}]);
  }
  assert.equal(base.sessions[0].identity,session);
  c.check(true,'Lock and reload balance holds, failed and zero reads, configuration choices and ended-session boundary retain the correct Start path');
}

async function endedCleanup(c, {request, report, session}) {
  const kind = c.name.slice('edge-end-cancel-'.length);
  const state = c.credit.state;
  if(kind==='cutoffs')return cleanupCutoffs(c,{request,report,session});
  const before = state.deletes.length;
  if (kind !== 'answered' && kind !== 'cutoffs') state.onDelete = () => new Promise(()=>{});
  await c.click('[data-end-session]');
  await c.wait("fixtureReports.at(-1)?.sessions?.[0]?.session_state==='ended'");
  for(let n=0;n<200&&state.deletes.length===before;n++)await new Promise(resolve=>setTimeout(resolve,25));
  assert.ok(state.deletes.length>before,'End attempts immediate cleanup');
  const id = state.deletes.at(-1), mints = state.mintCalls;
  if(kind==='failed') {
    await c.click('#tau-lock');
    await c.wait("document.querySelector('#tau-store')?.dataset.state==='locked'");
    await c.invoke(()=>{document.querySelector('#tau-passphrase').value='incorrect fixture passphrase';document.querySelector('#tau-unlock').click();});
    await c.wait("fixtureReports.at(-1)?.store_state==='refused'");
    assert.equal(state.deletes.length,before+1,'failed Unlock grants no cleanup attempt');
    await c.call('Page.reload',{},c.sessionId);
    await c.wait("document.querySelector('#tau-store')?.dataset.state==='locked'");
    await c.invoke(()=>{document.querySelector('#tau-passphrase').value='durable fixture passphrase';document.querySelector('#tau-unlock').click();});
    await c.wait("fixtureReports.at(-1)?.store_state==='unlocked'");
  } else await reopen(c,['lock','loss'].includes(kind)?kind:'reload');
  await c.wait('fixtureEvents.some(e=>e.fixture_unlock_complete)');
  for(let n=0;n<200&&state.deletes.filter(value=>value===id).length<2;n++)await new Promise(resolve=>setTimeout(resolve,25));
  assert.equal(state.deletes.filter(value=>value===id).length,2,'Unlock retries the same journaled DELETE id');
  assert.equal(state.mintCalls,mints,'ended session cleanup never mints');
  assert.equal(await c.workerEvaluate("(async()=>{const m=await import(new URL('./pkg/tau_web.js',location.href));return m.poc_key_is_set();})()"),false,'cleanup never restores a session key');
  assert.equal((await report()).sessions.find(s=>s.identity===session).session_state,'ended');
  c.check(true,'Unlock retries ended-session cleanup from durable metadata without minting or reviving authority');
}

async function cleanupCutoffs(c, {request, report, session}) {
  const state=c.credit.state;
  state.mintMode='lost';
  await request({action:'new_key',session});
  assert.equal(state.keys.length,2,'lost mint retains its journaled name');
  state.mintMode='normal';
  const firstExpiry=Date.parse(state.keys[0].expire_at);
  state.clockMs=firstExpiry-86400000+120000;
  await c.workerEvaluate(`Date.now=()=>${state.clockMs}`);
  await request({action:'new_key',session});
  assert.equal(state.keys.length,3);
  await c.click('[data-end-session]');
  await c.wait("fixtureReports.at(-1)?.sessions?.[0]?.session_state==='ended'");
  for(let n=0;n<200&&!state.deletes.includes('key-3');n++)await new Promise(resolve=>setTimeout(resolve,25));
  const mints=state.mintCalls;
  for(const [clock,expected] of [
    [firstExpiry+30000,['key-2','key-3']],
    [Date.parse(state.keys[1].expire_at)+60000,['key-3']],
    [Date.parse(state.keys[2].expire_at),[]],
  ]) {
    state.clockMs=clock;
    const before=state.deletes.length, lists=state.listCalls;
    await reopen(c);
    await c.wait('fixtureEvents.some(e=>e.fixture_unlock_complete)');
    // Await the one scheduled retry, including all its bounded exchanges.
    await c.workerEvaluate('new Promise(resolve=>setTimeout(resolve,250))');
    assert.deepEqual(state.deletes.slice(before).sort(),expected,'only eligible ids or name matches enter the delete set');
    assert.equal(state.listCalls-lists,expected.length?1:0,'no key listing once all retry cutoffs pass');
    assert.equal(state.mintCalls,mints,'cutoff handling never mints');
    assert.equal((await report()).sessions.find(s=>s.identity===session).session_state,'ended');
  }
  c.check(true,'returned expiry wins; name-only tolerance stops exactly at its cutoff; expired ids and expired names stay out of mixed-session cleanup');
}

export async function edgeSession(c, helpers) {
  if(c.name==='edge-start-wording')return startWording(c,helpers);
  if(c.name.startsWith('edge-end-cancel-'))return endedCleanup(c,helpers);
  return edgeFocusSession(c,helpers);
}

export async function edgeFocusPending(c, helpers) {
  return focusPending(c,helpers);
}

function withoutTimer(value) {
  const {payment_timer, ...content} = value;
  assert.equal(payment_timer,true,'real timer tag arrives through publication');
  return content;
}

async function settlePolls(c) {
  const before = await c.evaluate('fixtureReports.filter(r=>r.payment_timer).length');
  await c.wait(`fixtureReports.filter(r=>r.payment_timer).length>=${before+2}`);
  const values = await c.evaluate('fixtureReports.filter(r=>r.payment_timer).slice(-2)');
  assert.deepEqual(withoutTimer(values[0]),withoutTimer(values[1]),'successive actual credit polls compare equal apart from the timer tag');
}

export async function focusField(c, selector, {reports='fixtureReports', ticks=3, composition=true, afterTicks} = {}) {
  await c.invoke(selector => {
    const node = document.querySelector(selector);
    assertField(node);
    function assertField(node) { if(!node)throw Error('missing editable field '+selector); }
    for(let parent=node.parentElement;parent;parent=parent.parentElement)if(parent.tagName==='DETAILS'&&!parent.open)parent.querySelector('summary').click();
    node.focus();
    if(node.tagName==='SELECT')node.selectedIndex=node.options.length-1;
    else if(node.type==='number')node.value='97';
    else {node.value='draft-value';node.setSelectionRange(2,5,'backward');}
    node.dispatchEvent(new Event('input',{bubbles:true}));
    window.focusProbe = {node,blur:0,focusout:0,focus:0,starts:0,ends:0,invoice:document.querySelector('[data-credit-invoice]')};
    for(const kind of ['blur','focusout','focus'])node.addEventListener(kind,()=>focusProbe[kind]++);
    node.addEventListener('compositionstart',()=>focusProbe.starts++);
    node.addEventListener('compositionend',()=>focusProbe.ends++);
  },selector);
  const text = await c.evaluate("!['number','SELECT'].includes(focusProbe.node.type==='number'?'number':focusProbe.node.tagName)");
  if(composition && text)await c.call('Input.imeSetComposition',{text:'xy',selectionStart:2,selectionEnd:2},c.sessionId);
  const snapshot = await c.evaluate('({value:focusProbe.node.value,start:focusProbe.node.selectionStart,end:focusProbe.node.selectionEnd,direction:focusProbe.node.selectionDirection,index:focusProbe.node.selectedIndex,starts:focusProbe.starts,ends:focusProbe.ends})');
  const before = await c.evaluate(`${reports}.filter(r=>r.payment_timer).length`);
  const statusBefore = c.credit?.state.statusCalls;
  await c.wait(`${reports}.filter(r=>r.payment_timer).length>=${before+ticks}`);
  const observed = await c.evaluate('({blur:focusProbe.blur,focusout:focusProbe.focusout,focus:focusProbe.focus,same:document.activeElement===focusProbe.node,connected:focusProbe.node.isConnected,value:focusProbe.node.value,start:focusProbe.node.selectionStart,end:focusProbe.node.selectionEnd,direction:focusProbe.node.selectionDirection,index:focusProbe.node.selectedIndex,starts:focusProbe.starts,ends:focusProbe.ends,invoiceSame:focusProbe.invoice===document.querySelector(\'[data-credit-invoice]\')})');
  assert.equal(observed.blur,0,'unchanged payment polls cause zero blur events: '+selector);
  assert.equal(observed.focusout,0,'zero focusout events: '+selector);
  assert.equal(observed.focus,0,'zero compensating refocus: '+selector);
  assert.equal(observed.same,true,'same focused element reference: '+selector);
  assert.equal(observed.connected,true,'focused node stays connected: '+selector);
  for(const field of Object.keys(snapshot))assert.equal(observed[field],snapshot[field],selector+' retains '+field);
  if(c.credit) {
    assert.ok(c.credit.state.statusCalls>=statusBefore+ticks,'observed actual fixture poll requests');
    assert.equal(observed.invoiceSame,true,'unchanged timer publications do not render invoice rows');
  }
  if(afterTicks) {
    await afterTicks();
    const rendered=await c.evaluate('({blur:focusProbe.blur,focusout:focusProbe.focusout,focus:focusProbe.focus,same:document.activeElement===focusProbe.node,connected:focusProbe.node.isConnected,value:focusProbe.node.value,start:focusProbe.node.selectionStart,end:focusProbe.node.selectionEnd,direction:focusProbe.node.selectionDirection,index:focusProbe.node.selectedIndex,starts:focusProbe.starts,ends:focusProbe.ends})');
    assert.equal(rendered.blur,0,'required render causes zero blur events: '+selector);
    assert.equal(rendered.focusout,0,'required render causes zero focusout: '+selector);
    assert.equal(rendered.focus,0,'required render causes zero refocus: '+selector);
    assert.equal(rendered.same,true,'required render keeps the same focused reference: '+selector);
    assert.equal(rendered.connected,true,'required render leaves the field connected: '+selector);
    for(const field of Object.keys(snapshot))assert.equal(rendered[field],snapshot[field],selector+' retains '+field+' during required render');
    assert.equal(await c.evaluate("focusProbe.invoice===document.querySelector('[data-credit-invoice]')"),false,'explicit action actually rendered while composition stayed open');
    console.log(JSON.stringify({field:selector,requiredRender:rendered}));
  }
  if(composition && text) {
    assert.equal(observed.starts,1,'composition remains open through poll ticks');
    assert.equal(observed.ends,0,'no composition commit during polling');
    await c.call('Input.insertText',{text:'xy'},c.sessionId);
    assert.equal(await c.evaluate('focusProbe.ends'),1,'composition commits once');
    assert.equal(await c.evaluate('focusProbe.node.value'),snapshot.value,'composition commit never doubles text');
  }
  console.log(JSON.stringify({field:selector,ticks,before,after:await c.evaluate(`${reports}.filter(r=>r.payment_timer).length`),snapshot,observed}));
}

async function focusPending(c, {request}) {
  const options={afterTicks:()=>request({action:'check'})};
  await settlePolls(c);
  assert.equal(await c.evaluate("document.querySelector('#tau-step-machine-action').contains(document.querySelector('#tau-provider-catalogue'))"),true,'generating provider action is the main action');
  assert.equal(await c.evaluate("!document.querySelector('#tau-provider-existing').open && document.querySelector('#tau-provider-existing').contains(document.querySelector('#tau-provider-key-form'))"),true,'existing-account form starts in its closed disclosure');
  for(const selector of ['#tau-step-machine-fold','#tau-provider-existing'])if(!await c.evaluate(`document.querySelector(${JSON.stringify(selector)}).open`))await c.click(selector+' > summary');
  for(const field of ['#tau-provider-origin','#tau-provider-key'])await focusField(c,field,options);
  const lockedStructure=()=>c.evaluate(`(() => {
    const form=document.querySelector('#tau-provider-key-form');
    const disclosure=document.querySelector('#tau-provider-existing');
    const home=disclosure.parentElement;
    const ancestors=[];
    for(let node=form.parentElement;node;node=node.parentElement)ancestors.push({tag:node.tagName,id:node.id,classes:node.className,hidden:node.hidden});
    return {atHome:form.parentElement===disclosure && home===document.querySelector('#tau-provider-selection-form').parentElement,homeHidden:home.hidden,actionChildren:document.querySelector('#tau-step-machine-action').childElementCount,ancestors};
  })()`);
  await c.click('#tau-lock');
  await c.wait("document.querySelector('#tau-store')?.dataset.state==='locked'");
  const locked=await lockedStructure();
  assert.equal(locked.atHome,true,'Lock keeps the provider form in its disclosure at the original home');
  assert.equal(locked.homeHidden,true,'the original home is hidden while locked');
  assert.equal(locked.actionChildren,0,'no disabled provider form escapes its hidden home');
  await c.call('Page.reload',{},c.sessionId);
  await c.wait("document.querySelector('#tau-store')?.dataset.state==='locked'");
  assert.deepEqual(await lockedStructure(),locked,'same-tab Lock and fresh locked page have the same form structure');
  await c.invoke(()=>{document.querySelector('#tau-passphrase').value='durable fixture passphrase';document.querySelector('#tau-unlock').click();});
  await c.wait('fixtureEvents.some(e=>e.fixture_unlock_complete)');
  await settlePolls(c);
  await c.invoke(port => {
    document.querySelector('#tau-provider-origin').value='https://127.0.0.1:'+port;
    document.querySelector('#tau-provider-key').value='31'.repeat(32);
    document.querySelector('#tau-provider-key-form').requestSubmit();
  },new URL(c.pageOrigin).port);
  await c.wait('fixtureReports.at(-1)?.provider_configuration?.key_set');
  await c.click('#tau-provider-catalogue');
  await c.wait('fixtureReports.at(-1)?.provider_catalogue');
  await settlePolls(c);
  assert.equal(await c.evaluate("document.querySelector('#tau-step-machine-action').contains(document.querySelector('#tau-provider-selection-form'))"),true,'offer-selection form is the main action');
  for(const field of ['#tau-provider-resources','#tau-provider-offer','#tau-provider-image'])await focusField(c,field,options);
  await c.invoke(() => {
    document.querySelector('#tau-provider-offer').value='fixed:1';
    document.querySelector('#tau-provider-image').value='3';
    document.querySelector('#tau-provider-selection-form').requestSubmit();
  });
  await c.wait('fixtureReports.at(-1)?.procurement?.selection');
  await settlePolls(c);
  assert.equal(await c.evaluate("document.querySelector('#tau-provider-approval-form button').classList.contains('main-action') && document.querySelector('#tau-purchase-review-slot #tau-purchase-review').contains(document.querySelector('#tau-provider-approval-form'))"),true,'approval is the main action beside its purchase facts');
  for(const field of ['#tau-provider-machine','#tau-provider-relay'])await focusField(c,field,options);
  await request({action:'check'});
  c.check(true,'phone fields in existing-account, selection and approval forms survive actual unchanged credit polls and composition');
}

async function edgeFocusSession(c, {request, report, session}) {
  if(c.name==='edge-focus-goal') {
    await c.click('[data-end-session]');
    await c.wait("fixtureReports.at(-1)?.sessions?.[0]?.session_state==='ended'");
    await c.invoke(endpoint => {
      document.querySelector('#tau-poc-endpoint').value=endpoint;
      document.querySelector('#tau-poc-model').value='example-model';
      document.querySelector('#tau-poc-key').value='synthetic-typed-credential-482700';
      document.querySelector('#tau-poc-inference-form').requestSubmit();
    },c.inferenceEndpoint);
    await c.wait('fixtureReports.at(-1)?.poc_configuration?.key_set && !fixtureReports.at(-1)?.credit?.selected');
    await c.evaluate(startButton+'.click()');
    await c.wait("document.querySelector('[data-goal-text]')");
  }
  if(['edge-focus-target','edge-focus-limits'].includes(c.name)) {
    await c.invoke(() => {
      document.querySelector('[aria-label="Verification commands, one per line"]').value='true';
      document.querySelector('[data-goal-accept]').click();
    });
    await c.wait('fixtureReports.at(-1)?.tasks?.[0]?.pause_reason');
    await c.wait("document.querySelector('[data-poc-declaration]')");
  }
  c.credit.state.status='New';
  await request({action:'invoice',amount:1000});
  await settlePolls(c);
  const fields = {
    'edge-focus-target':['[data-credit-goal]','[data-poc-declaration]'],
    'edge-focus-goal':['[data-goal-text]','[data-document-source]'],
    'edge-focus-verification':['[data-credit-goal]','[aria-label="Verification commands, one per line"]'],
    'edge-focus-limits':['[aria-label="Task request limit"]','[aria-label="Task step limit"]'],
  }[c.name];
  for(const field of fields)await focusField(c,field);
  const drafts = await c.evaluate(`Object.fromEntries(${JSON.stringify(fields)}.map(selector=>[selector,document.querySelector(selector).value]))`);
  const folds=await c.evaluate("[...document.querySelectorAll('[data-step] > details')].map(n=>({id:n.id,open:n.open}))");
  const focusCurrent=()=>c.evaluate(`document.querySelector(${JSON.stringify(fields[0])}).focus()`);
  const invoice = await c.evaluate("document.querySelector('[data-credit-invoice]')===focusProbe.invoice");
  assert.equal(invoice,true);
  await request({action:'check'});
  assert.equal(await c.evaluate("document.querySelector('[data-credit-invoice]')===focusProbe.invoice"),false,'explicit action renders even when content is unchanged');
  assert.deepEqual(await c.evaluate(`Object.fromEntries(${JSON.stringify(fields)}.map(selector=>[selector,document.querySelector(selector).value]))`),drafts,'explicit action retains all drafts');
  c.credit.state.mode='balance-fail';c.credit.state.status='Settled';c.credit.state.amountPaid=0.00001;
  await focusCurrent();
  let tick=await c.evaluate('fixtureReports.filter(r=>r.payment_timer).length');
  await c.wait(`fixtureReports.filter(r=>r.payment_timer).length>${tick}`);
  assert.equal((await report()).credit.invoices.at(-1).outcome,'seen','seen payment renders immediately while focused');
  assert.equal(await c.evaluate("document.querySelector('[data-credit-invoice]:last-child a')===null"),true,'seen payment removes wallet controls immediately');
  assert.ok(await c.evaluate("document.querySelector('[data-credit-invoice]:last-child').textContent.includes('Payment seen; balance not read yet.')"),'changed timer report updates the status sentence');
  c.credit.state.mode='normal';
  c.credit.state.status='Settled';c.credit.state.amountPaid=0.00001;
  await focusCurrent();
  tick=await c.evaluate('fixtureReports.filter(r=>r.payment_timer).length');
  await c.wait(`fixtureReports.filter(r=>r.payment_timer).length>${tick}`);
  assert.equal((await report()).credit.invoices.at(-1).outcome,'paid','changed payment renders immediately');
  assert.ok(await c.evaluate("document.querySelector('[data-credit-invoice]:last-child').textContent.includes('Payment seen; inference credit read.')"),'paid timer report renders immediately');
  c.credit.state.mode='balance-fail';
  await focusCurrent();
  await request({action:'invalid'});
  assert.ok(await c.evaluate("document.querySelector('#tau-credit-status').textContent.includes('Invalid credit request.')"),'error renders while field is focused');
  const failed=await report();failed.payment_timer=true;
  await pageReport(c,failed);
  await c.evaluate("window.errorInvoice=document.querySelector('[data-credit-invoice]')");
  await pageReport(c,failed);
  assert.equal(await c.evaluate("errorInvoice===document.querySelector('[data-credit-invoice]')"),false,'repeated timer error still renders');
  await focusCurrent();
  assert.equal(await c.evaluate(`document.activeElement===document.querySelector(${JSON.stringify(fields[0])})`),true,'editable field is focused immediately before lifecycle transition');
  await c.message({lifecycle:'freeze'});
  await c.wait("fixtureReports.at(-1)?.lifecycle_state==='reconciling'");
  assert.equal(await c.evaluate("document.querySelector('#tau-store-state').dataset.lifecycle"),'reconciling','lifecycle report renders immediately');
  await c.message({lifecycle:'resume'});
  await c.wait("fixtureReports.at(-1)?.lifecycle_state==='running'");
  assert.deepEqual(await c.evaluate(`Object.fromEntries(${JSON.stringify(fields)}.map(selector=>[selector,document.querySelector(selector).value]))`),drafts,'changed payment, error and lifecycle reports retain every draft');
  assert.deepEqual(await c.evaluate("[...document.querySelectorAll('[data-step] > details')].map(n=>({id:n.id,open:n.open}))"),folds,'ordinary updates retain operator-opened folds');
  c.check(true,'all editable card members preserve focus, selection and composition through real timer publications; action, payment, error and lifecycle reports still render');
}
