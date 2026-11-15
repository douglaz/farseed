// The harness worker alone holds the seed and keys. Only the dedicated seed-backup display
// carries words to the page; re-entry and passphrase buffers are zero-filled by the module.
import init, { spec_commit, open, create, unlock, seed_backup_display, seed_backup_answer, seed_backup_reentry, seed_backup_skip, seed_backup_redisplay, setup_approve, setup_answer, bind, goal_request, accept_page_goal, TaskPublication, requirements_answer, delivery_request, retire_runtime, sweep_inference, lifecycle_transition, publication_generation, publish_report, verify_inference_clock, withdraw_reinstall } from './pkg/tau_web.js';
import { identify_execution, wake_tasks, poc_configure, poc_key_is_set, poc_enroll, poc_bind, poc_public_keys, poc_accept } from './pkg/tau_web.js';
import { credit_request, retry_ended_credit } from './pkg/tau_web.js';
import { deployment_configure, provider_configure, provider_key_is_set, provider_visibility, provider_action_delay, provider_request } from './pkg/tau_web.js';

const clearInput = request => {
  for (const field of ['create','unlock','seed_backup_redisplay','seed_backup_reentry']) {
    if (request?.[field] instanceof Uint8Array) request[field].fill(0);
  }
  for (const field of ['poc_configure','provider_configure','deployment']) {
    if (request?.[field]?.key instanceof Uint8Array) request[field].key.fill(0);
  }
};
// A fresh page worker gets one execution identity before it can receive authority.
let incarnation;
let deployment;
let retirementRequested = false;
const lockWait = new AbortController();
await new Promise(resolve => {
  onmessage = ({data}) => {
    if (!incarnation && data && Object.keys(data).every(k => ['initialize','deployment'].includes(k)) && typeof data.initialize === 'string') {
      incarnation = data.initialize;
      deployment = data.deployment;
      resolve();
    } else {
      // Retirement can arrive while the page is still reading deployment defaults.
      if (!incarnation && typeof data?.incarnation === 'string' && typeof data.generation === 'string' &&
          data.request && Object.keys(data.request).length === 1 && data.request.retire_runtime === true) {
        incarnation = data.incarnation;
        retirementRequested = true;
        resolve();
      }
      if (incarnation && data?.incarnation === incarnation && typeof data.generation === 'string' &&
          data.request && Object.keys(data.request).length === 1 && data.request.retire_runtime === true) {
        retirementRequested = true;
        lockWait.abort();
      }
      clearInput(data?.request ?? data);
    }
  };
});
try {
  await init();
  identify_execution(incarnation);
  try {
    const accepted = await deployment_configure(typeof deployment?.origin === 'string' ? deployment.origin : undefined,
      deployment?.key instanceof Uint8Array ? deployment.key : new Uint8Array(),
      typeof deployment?.public_fields === 'string' ? deployment.public_fields : '{}');
    postMessage({deployment_ready: accepted});
  } finally {
    if (deployment?.key instanceof Uint8Array) deployment.key.fill(0);
    deployment = undefined;
  }
  postMessage({ harness_ready: spec_commit() });
} catch (error) {
  postMessage({ harness_error: String(error) });
  throw error;
}

// STA-1 and STA-7: one writer. The lock is exclusive and store-wide, taken before the store is
// read and held for this worker's whole life; while another worker holds it, this one queues.
const held = (options) =>
  new Promise((acquired, refused) =>
    navigator.locks.request('tau-web-store', options, (lock) => {
      acquired(lock !== null);
      return lock && new Promise(() => {});
    }).catch(refused));
try {
  if (!retirementRequested && !(await held({ ifAvailable: true }))) {
    postMessage({ store: { store_state: 'in-use' } });
    await held({ signal: lockWait.signal });
  }
} catch (error) {
  if (!retirementRequested || error.name !== 'AbortError') throw error;
}
if (retirementRequested) {
  await retire_runtime();
  postMessage({ runtime_retired: true });
  // The page terminates this incarnation. It never opens the store or grants authority.
  await new Promise(() => {});
}
let paymentTimer = null;
let pageVisible = true;
let lastReport = null;
const paymentsEligible = () => !retirementRequested && pageVisible && lastReport?.state === 'unlocked' && !['suspended','reconciling','ended'].includes(lastReport?.lifecycle_state);
const pendingCredit = () => {
  const invoice = lastReport?.credit?.invoices?.at(-1);
  return paymentsEligible() && invoice && !['paid','expired_unpaid','abandoned'].includes(invoice.outcome) && Date.now()/1000 <= invoice.expires_at + 60 ? invoice.id : null;
};
const unpaidMachine = () => {
  const machine = lastReport?.procurement?.payment;
  return paymentsEligible() && machine && !machine.is_paid && !lastReport.procurement?.target && provider_key_is_set() ? machine.id : null;
};
const pendingMachine = () => unpaidMachine() && Date.now() <= Date.parse(lastReport.procurement.payment.expires) + 60000 ? unpaidMachine() : null;
const schedulePayments = () => {
  if (paymentTimer || !paymentsEligible()) return;
  const creditPending = pendingCredit();
  const machinePending = pendingMachine();
  if (!creditPending && !machinePending) return;
  paymentTimer = setTimeout(async () => {
    paymentTimer = null;
    if (!paymentsEligible()) return;
    const generation = publication_generation();
    if (creditPending && pendingCredit() === creditPending) await reportStore(await credit_request(JSON.stringify({action:'poll'})), generation, '', 'credit', true);
    if (machinePending && pendingMachine() === machinePending) await reportStore(await provider_request(JSON.stringify({action:'payment_check'})), generation, '', 'machine', true);
    schedulePayments();
  }, 5000);
};
let readinessTimer = null;
let readinessBusy = false;
let readinessIdentity = null;
let readinessReturn = null;
let readinessReads = 0;
let readinessLifecycle = 0;
const readyPurchase = () => {
  const p = lastReport?.procurement;
  return paymentsEligible() && provider_key_is_set() && p?.payment?.is_paid === true &&
    p.paid_at != null && !p.target && p.phase !== 'terms_changed' ? p : null;
};
const readinessExpired = p => Date.now()/1000 >= p.paid_at + p.readiness_wait_seconds;
const armReadiness = (p, delay) => {
  const identity = JSON.stringify(p.identity);
  readinessTimer = setTimeout(async () => {
    readinessTimer = null;
    if (!readyPurchase() || JSON.stringify(readyPurchase().identity) !== identity) { scheduleReadiness(); return; }
    if (readinessExpired(readyPurchase())) { await reportStore(await open(), publication_generation(), '', 'machine', true); return; }
    await readinessRead();
  }, Math.min(delay, Math.max(0, (p.paid_at + p.readiness_wait_seconds)*1000 - Date.now())));
};
const readinessRead = async (immediate = false) => {
  const p = readyPurchase();
  if (!p || readinessExpired(p)) return;
  const identity = JSON.stringify(p.identity);
  if (readinessBusy) { if (immediate) readinessReturn = identity; return; }
  const floor = provider_action_delay();
  if (floor > 0) { stopReadiness(); armReadiness(p, floor); return; }
  readinessBusy = true;
  readinessReads++;
  const generation = publication_generation();
  try {
    const report = await provider_request(JSON.stringify({action:'readiness_check'}));
    if (readyPurchase() && JSON.stringify(readyPurchase().identity) === identity) readinessIdentity = identity;
    await reportStore(report, generation, '', 'machine', true);
  } finally {
    readinessBusy = false;
    const queued = readinessReturn; readinessReturn = null;
    const current = readyPurchase();
    if (queued && current && JSON.stringify(current.identity) === queued && !readinessExpired(current)) {
      stopReadiness(); armReadiness(current, provider_action_delay());
    } else scheduleReadiness();
  }
};
const scheduleReadiness = () => {
  const p = readyPurchase();
  if (!p || readinessExpired(p)) { clearTimeout(readinessTimer); readinessTimer = null; return; }
  if (readinessTimer || readinessBusy) return;
  armReadiness(p, JSON.stringify(p.identity) === readinessIdentity ? p.readiness_poll_seconds * 1000 : 1000);
};
const stopReadiness = () => { clearTimeout(readinessTimer); readinessTimer = null; };
const refreshPayments = async (wake = {reads:readinessReads, lifecycle:readinessLifecycle,
  generation:publication_generation(), identity:JSON.stringify(lastReport?.procurement?.identity)}) => {
  if (retirementRequested || !pageVisible || lastReport?.state !== 'unlocked') return;
  const {generation, identity, lifecycle, reads} = wake;
  const current = () => generation === publication_generation() && lifecycle === readinessLifecycle &&
    paymentsEligible() && JSON.stringify(lastReport.procurement?.identity) === identity;
  if (!current()) return;
  const machine = unpaidMachine();
  if (lastReport.credit?.account) await reportStore(await credit_request(JSON.stringify({action:'refresh'})),generation, '', 'credit');
  if (!current()) return;
  if (machine && unpaidMachine() === machine) await reportStore(await provider_request(JSON.stringify({action:'payment_check'})),generation, '', 'machine');
  if (!current()) return;
  // A readiness read begun during this wake already satisfies it, even if credit was slow.
  // A read that predates the wake still needs the existing return-after-flight path.
  if (readinessReads !== reads) { scheduleReadiness(); return; }
  stopReadiness();
  await readinessRead(true);
};
const presentationReport = (report, step) => {
  const value = JSON.parse(report);
  if (value.error) value.page_error_step = step;
  return JSON.stringify(value);
};
const reportStore = (report, generation = publication_generation(), session = '', step = 'store', paymentTimerReport = false) => {
  report = presentationReport(report, step);
  const value = JSON.parse(report);
  lastReport = value;
  schedulePayments();
  scheduleReadiness();
  value.poc_configuration = { key_set: poc_key_is_set() };
  value.provider_configuration = { key_set: provider_key_is_set() };
  if (paymentTimerReport) value.payment_timer = true;
  return publish_report(generation, session, JSON.stringify(value));
};
const exactMembers = (value, names) => value && typeof value === 'object' &&
  !Array.isArray(value) && Object.keys(value).length === names.length &&
  names.every(name => Object.hasOwn(value, name));
const startFields = value => typeof value.goal === 'string' && (value.document_source === null || typeof value.document_source === 'string');

const startGoal = async (report, inputs, machine) => {
  let current = JSON.parse(report);
  if (current.error) return report;
  const session = current.sessions?.find(s => s.session_state !== 'ended' && s.bound_set?.length === 1 && s.bound_set[0] === machine);
  if (!session || current.tasks?.some(task => task.start_session === session.identity)) return report;
  if (!session.goal) {
    report = await goal_request(JSON.stringify({session: session.identity, text: inputs.goal, document_source: inputs.document_source || null}));
    current = JSON.parse(report);
    if (current.error) return report;
  }
  const accepted = JSON.parse(await accept_page_goal(session.identity));
  if (!accepted.error) accepted.page_start_session = session.identity;
  return JSON.stringify(accepted);
};

const publishTask = async (request, generation, session, step, automatic = false) => {
  const publication = new TaskPublication();
  try {
    let report = automatic ? await publication.continue_task(request.id, session) : await publication.request(JSON.stringify(request));
    report = presentationReport(report, step);
    await publication.publish(generation, session, report);
  } finally { publication.free(); }
};

onmessage = async ({ data: envelope }) => {
  if (!envelope || envelope.incarnation !== incarnation || typeof envelope.generation !== 'string') { clearInput(envelope?.request ?? envelope); return; }
  const data = envelope.request;
  if (envelope.generation !== publication_generation().toString() && data?.retire_runtime !== true && typeof data?.lifecycle !== 'string') { clearInput(data); return; }
  try {
  if (!data || typeof data !== 'object' || Object.keys(data).length !== 1) {
    clearInput(data);
    return;
  }
  const wake = {reads:readinessReads, lifecycle:readinessLifecycle};
  if (data.retire_runtime === true) {
    retirementRequested = true;
    clearTimeout(paymentTimer); paymentTimer = null;
    stopReadiness(); provider_visibility(false);
    await retire_runtime();
    postMessage({ runtime_retired: true });
    return;
  }
  if (typeof data.lifecycle === 'string') {
    if (data.lifecycle === 'hidden' || data.lifecycle === 'freeze') { readinessLifecycle++; pageVisible = false; clearTimeout(paymentTimer); paymentTimer = null; stopReadiness(); provider_visibility(false); }
    if (data.lifecycle === 'visible' || data.lifecycle === 'resume') { pageVisible = true; provider_visibility(true); }
    const report = await lifecycle_transition(data.lifecycle);
    Object.assign(wake, {generation:publication_generation(), identity:JSON.stringify(JSON.parse(report).procurement?.identity)});
    await reportStore(report);
    if (data.lifecycle === 'visible' || data.lifecycle === 'resume') await refreshPayments(wake);
    return;
  }
  const generation = publication_generation();
  let report;
  const step = data.poc_configure || data.credit_request ? 'credit'
    : data.provider_configure || data.provider_request || data.poc_enroll || data.setup_approve || data.setup_answer ? 'machine'
    : data.poc_bind || data.poc_public_keys || data.poc_accept || data.bind || data.verify_clock || data.withdraw_reinstall || data.task || data.goal || data.requirements_answer || data.delivery || data.goal_accept ? 'task' : 'store';
  const session = data.task?.action === 'end-session' ? '' : data.goal?.session ?? data.goal_accept?.session ?? data.requirements_answer?.session ?? data.delivery?.session ?? data.task?.session ?? '';
  if (data.create instanceof Uint8Array) report = await create(data.create);
  else if (data.unlock instanceof Uint8Array) report = await unlock(data.unlock);
  else if (data.seed_backup_redisplay instanceof Uint8Array) report = await seed_backup_redisplay(data.seed_backup_redisplay);
  else if (data.seed_backup_reentry instanceof Uint8Array) report = await seed_backup_reentry(data.seed_backup_reentry);
  else if (data.seed_backup_answer === true) report = await seed_backup_answer();
  else if (data.seed_backup_skip === true) report = await seed_backup_skip();
  else if (data.poc_configure && typeof data.poc_configure === 'object') {
    const config = data.poc_configure;
    try {
      if (exactMembers(config, ['endpoint', 'model', 'key']) &&
          typeof config.endpoint === 'string' && typeof config.model === 'string' &&
          config.key instanceof Uint8Array) {
        report = await poc_configure(config.endpoint, config.model, config.key);
      } else {
        const current = JSON.parse(await open());
        current.error = 'Invalid inference configuration.';
        report = JSON.stringify(current);
      }
    } finally {
      if (config.key instanceof Uint8Array) config.key.fill(0);
      delete config.key;
    }
  }
  else if (data.credit_request && typeof data.credit_request === 'object') {
    const value = JSON.parse(await credit_request(JSON.stringify(data.credit_request)));
    if (data.credit_request.action === 'start' && !value.credit_error) value.credit_started_machine = data.credit_request.machine;
    report = JSON.stringify(value);
  }
  else if (data.provider_configure !== undefined) {
    const config = data.provider_configure;
    try {
      if (exactMembers(config, ['key', 'origin']) && config.key instanceof Uint8Array && typeof config.origin === 'string') report = await provider_configure(config.key, config.origin);
      else { const current = JSON.parse(await open()); current.error = 'Invalid provider account entry.'; report = JSON.stringify(current); }
    } finally {
      if (config?.key instanceof Uint8Array) config.key.fill(0);
      if (config && typeof config === 'object') delete config.key;
    }
  }
  else if (data.provider_request && typeof data.provider_request === 'object') {
    const value = JSON.parse(await provider_request(JSON.stringify(data.provider_request)));
    if (data.provider_request.action === 'select' && !value.error) value.provider_selection_reviewed = true;
    report = JSON.stringify(value);
  }
  else if (data.poc_enroll !== undefined) {
    if (exactMembers(data.poc_enroll, ['target', 'approve_existing', 'class_answer', 'approve_maintained_access']) &&
        exactMembers(data.poc_enroll.target, ['machine', 'relay', 'profile', 'host', 'port', 'user', 'elevation', 'pin'])) {
      report = await poc_enroll(JSON.stringify(data.poc_enroll));
    } else {
      const current = JSON.parse(await open());
      current.error = 'Invalid existing-machine enrollment.';
      report = JSON.stringify(current);
    }
  }
  else if (typeof data.poc_bind?.machine === 'string' && (exactMembers(data.poc_bind,['machine']) || exactMembers(data.poc_bind,['machine','goal','document_source']) && startFields(data.poc_bind))) {
    if (typeof data.poc_bind.goal === 'string' && !data.poc_bind.goal.trim()) { const current=JSON.parse(await open());current.error='Enter a goal before Start session.';report=JSON.stringify(current); }
    else report = await poc_bind(data.poc_bind.machine);
    if (typeof data.poc_bind.goal === 'string') report = await startGoal(report, data.poc_bind, data.poc_bind.machine);
  }
  else if (exactMembers(data.poc_public_keys, ['machine']) && typeof data.poc_public_keys.machine === 'string') report = await poc_public_keys(data.poc_public_keys.machine);
  else if (exactMembers(data.poc_accept, ['session']) && typeof data.poc_accept.session === 'string') report = await poc_accept(JSON.stringify(data.poc_accept));
  else if (data.setup_approve === true) report = await setup_approve();
  else if (data.setup_answer && typeof data.setup_answer === 'object') report = await setup_answer(JSON.stringify(data.setup_answer));
  else if (data.bind && typeof data.bind === 'object') {
    const {goal, document_source, ...binding} = data.bind;
    if (typeof goal === 'string' && !goal.trim()) { const current=JSON.parse(await open());current.error='Enter a goal before Start session.';report=JSON.stringify(current); }
    else report = await bind(JSON.stringify(exactMembers(data.bind,['machine','inference_approval','goal','document_source']) && startFields(data.bind) ? binding : data.bind));
    if (typeof goal === 'string') report = await startGoal(report, {goal, document_source}, binding.machine);
  }
  else if (typeof data.verify_clock === 'string') {
    const result = JSON.parse(await verify_inference_clock(data.verify_clock));
    const current = JSON.parse(await open());
    if (result.refused) current.error = result.refused;
    report = JSON.stringify(current);
  }
  else if (data.withdraw_reinstall && typeof data.withdraw_reinstall === 'object') {
    const { approval, reset, entry } = data.withdraw_reinstall;
    let error;
    try { await withdraw_reinstall(String(approval), reset, entry); } catch (e) { error = String(e); }
    const current = JSON.parse(await open());
    if (error) current.error = error;
    report = JSON.stringify(current);
  }
  else if (data.task && typeof data.task === 'object') {
    await publishTask(data.task, generation, session, step);
    return;
  }
  else if (data.goal && typeof data.goal === 'object') report = await goal_request(JSON.stringify(data.goal));
  else if (data.requirements_answer && typeof data.requirements_answer === 'object') report = await requirements_answer(JSON.stringify(data.requirements_answer));
  else if (data.delivery && typeof data.delivery === 'object') report = await delivery_request(JSON.stringify(data.delivery));
  else if (data.goal_accept && typeof data.goal_accept === 'object') {
    report = await accept_page_goal(data.goal_accept.session);
    await reportStore(report, generation, session, step);
    if (!JSON.parse(report).error) {
      const publication = new TaskPublication();
      try {
        const outcome = JSON.parse(await publication.run_goal(data.goal_accept.session));
        const finalGeneration = publication_generation();
        const current = JSON.parse(await open());
        if (outcome.task && outcome.refused) current.error = outcome.refused;
        if (!outcome.task) current.goal_outcome = { session: data.goal_accept.session, outcome };
        await publication.publish(finalGeneration, data.goal_accept.session, presentationReport(JSON.stringify(current), step));
      } finally { publication.free(); }
    }
    return;
  }
  else return;
  Object.assign(wake, {generation:publication_generation(), identity:JSON.stringify(JSON.parse(report).procurement?.identity)});
  await reportStore(report, generation, session, step);
  const result = JSON.parse(report);
  if (!result.error && !result.credit_error) {
    if (data.requirements_answer?.decision === 'approve' && generation === publication_generation()) {
      const task = result.tasks?.find(task => task.start_session === data.requirements_answer.session && task.machine === data.requirements_answer.machine && ['running','verifying','waiting'].includes(task.status));
      if (task) await publishTask({action:'resume',id:task.id,session:task.start_session}, generation, task.start_session, step, true);
    }
    if (result.page_start_session) {
      const started = result.tasks?.find(task => task.start_session === result.page_start_session);
      const startSession = started?.start_session;
      if (startSession) {
        const publication = new TaskPublication();
        try {
          const outcome = JSON.parse(await publication.run_goal(startSession));
          const current = JSON.parse(await open());
          if (outcome.refused) current.error = outcome.refused;
          if (!outcome.task) current.goal_outcome = {session:startSession,outcome};
          await publication.publish(publication_generation(), startSession, presentationReport(JSON.stringify(current), step));
        } finally { publication.free(); }
      }
    }
    if (data.provider_configure) { stopReadiness(); await readinessRead(true); }
  }
  if (data.unlock instanceof Uint8Array || data.seed_backup_redisplay instanceof Uint8Array) {
    setTimeout(() => sweep_inference(), 0);
    if (data.unlock instanceof Uint8Array && JSON.parse(report).state === 'unlocked' && !JSON.parse(report).error) setTimeout(() => retry_ended_credit(), 0);
    wake_tasks();
    await refreshPayments(wake);
  }
  const display = JSON.parse(await seed_backup_display());
  if (display) postMessage(display);
  } finally {
    // Prerequisite changes wake interrupted work; task controls retain their explicit workflow.
    if (data && (data.unlock instanceof Uint8Array || data.poc_configure || data.credit_request || data.lifecycle === 'resume' ||
        Object.keys(data).some(name => name.startsWith('seed_backup_')))) wake_tasks();
  }
};
await reportStore(await open());
