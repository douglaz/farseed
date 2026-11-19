// The harness worker alone holds the seed and keys. Only the dedicated seed-backup display
// carries words to the page; re-entry and passphrase buffers are zero-filled by the module.
import init, { spec_commit, open, create, unlock, seed_backup_display, seed_backup_answer, seed_backup_reentry, seed_backup_skip, seed_backup_redisplay, setup_approve, setup_answer, bind, goal_request, accept_page_goal, TaskPublication, requirements_answer, delivery_request, retire_runtime, sweep_inference, lifecycle_transition, publication_generation, publish_report, verify_inference_clock, withdraw_reinstall } from './pkg/tau_web.js';
import { identify_execution, wake_tasks, task_presence, poc_configure, poc_key_is_set, poc_enroll, poc_bind, poc_public_keys, poc_accept, poc_download, publish_task_details, publish_delivery_details } from './pkg/tau_web.js';
import { credit_request, retry_ended_credit } from './pkg/tau_web.js';
import { deployment_configure, provider_configure, provider_token_configure, provider_key_is_set, provider_visibility, provider_action_delay, provider_request } from './pkg/tau_web.js';
import { vpsbg_poll_contexts, vpsbg_poll, vpsbg_presence } from './pkg/tau_web.js';
import { publish_unlock_worker_timings } from './pkg/tau_web.js';

const unlockNow = performance.now.bind(performance);
// Marks belong to one unlock request and are passed explicitly, so a request that interleaves
// during the awaited unlock never adds its own JSON work to them.
const unlockJson = (marks, operation, value) => {
  if (!marks) return operation(value);
  const started = unlockNow();
  try { return operation(value); }
  finally { marks.worker_json_ms += unlockNow() - started; }
};

const clearInput = request => {
  if (request?.provider_token?.token instanceof Uint8Array) request.provider_token.token.fill(0);
  if (request?.provider_request && Object.hasOwn(request.provider_request, 'email')) delete request.provider_request.email;
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
let initialPresence;
let retirementRequested = false;
const lockWait = new AbortController();
// Fetch and compile while the page prepares its deployment initialization.
// Count bytes only for an unencoded response with a known total. Otherwise keep
// the fetched Response intact: Chromium's streaming wasm code cache needs its URL
// and HTTP cache metadata, which a synthetic Response would discard. With the
// application/wasm MIME type and cacheable no-cache/ETag headers, later loads can
// revalidate and reuse compiled code; eligibility does not guarantee a cache hit.
const wasmReady = (async () => {
  const response = await fetch(new URL('./pkg/tau_web_bg.wasm', import.meta.url));
  if (!response.ok) throw Error('The app download failed.');
  const length = Number(response.headers.get('Content-Length'));
  const total = !response.headers.has('Content-Encoding') && Number.isSafeInteger(length) && length > 0 ? length : null;
  if (total === null || !response.body) {
    // No byte estimate or polling: the page keeps its static "Loading the app…".
    await init({module_or_path: response});
    postMessage({app_loading: {loaded: 0, total: null, complete: true}});
    return;
  }
  const reader = response.body.getReader();
  let loaded = 0, lastUpdate = -Infinity;
  const body = new ReadableStream({
    async pull(controller) {
      try {
        const {done, value} = await reader.read();
        if (!done) loaded += value.byteLength;
        const now = performance.now();
        if (done || now - lastUpdate >= 500) {
          postMessage({app_loading: {loaded, total, complete: done}});
          lastUpdate = now;
        }
        if (done) controller.close(); else controller.enqueue(value);
      } catch (error) { controller.error(error); }
    },
    cancel(reason) { return reader.cancel(reason); },
  });
  // wasm-bindgen uses instantiateStreaming for a Response with this MIME type.
  return init({module_or_path: new Response(body, {headers: {'Content-Type': response.headers.get('Content-Type') ?? ''}})});
})().then(() => ({error: null}), error => {
  // Settle even if defaults have not arrived yet; no unhandled rejection window.
  postMessage({app_load_failed: true});
  return {error};
});
await new Promise(resolve => {
  onmessage = ({data}) => {
    if (incarnation && data?.incarnation === incarnation && data.request?.task_presence) {
      initialPresence = data.request.task_presence;
      return;
    }
    if (!incarnation && data && Object.keys(data).every(k => ['initialize','deployment','presence'].includes(k)) && typeof data.initialize === 'string') {
      incarnation = data.initialize;
      deployment = data.deployment;
      initialPresence = data.presence;
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
  const result = await wasmReady;
  if (result.error) throw result.error;
  identify_execution(incarnation);
  task_presence(initialPresence?.visible === true, initialPresence?.online === true);
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
let pageOnline = initialPresence?.online === true;
let vpsbgVisible = initialPresence?.visible === true;
let lastReport = null;
// The newest session list from either a store report or a task publication (End publishes only through the latter),
// so a fresh key submitted after End is compared with the sessions the page shows, not with a stale store report.
let latestSessions = null;
const paymentsEligible = () => !retirementRequested && pageVisible && lastReport?.state === 'unlocked' && !['suspended','reconciling','ended'].includes(lastReport?.lifecycle_state);
// Durable VPSBG contexts include first-create continuation after settlement/coverage,
// including a wake after the settlement append but before any introduction or create.
// They never consult LNVPS's account flag, payment fields or target presence.
let vpsbgDepositTimer = null;
let vpsbgAttestTimer = null;
let vpsbgDepositBusy = false;
let vpsbgAttestBusy = false;
let vpsbgScheduling = false;
let vpsbgEpoch = 0;
let vpsbgProviderQueue = Promise.resolve();
const vpsbgEligible = () => paymentsEligible() && pageOnline && vpsbgVisible;
const stopVpsbg = () => {
  vpsbgEpoch++;
  clearTimeout(vpsbgDepositTimer); vpsbgDepositTimer = null;
  clearTimeout(vpsbgAttestTimer); vpsbgAttestTimer = null;
};
const queueVpsbg = operation => {
  const work = vpsbgProviderQueue.then(async () => {
    const delay = provider_action_delay();
    if (delay) await new Promise(resolve => setTimeout(resolve, delay));
    return operation();
  });
  vpsbgProviderQueue = work.catch(() => {});
  return work;
};
const scheduleVpsbg = async () => {
  if (!vpsbgEligible()) { stopVpsbg(); return; }
  if (vpsbgScheduling) return;
  const epoch = vpsbgEpoch;
  vpsbgScheduling = true;
  let contexts;
  try { contexts = JSON.parse(await vpsbg_poll_contexts()); }
  finally { vpsbgScheduling = false; }
  if (!vpsbgEligible() || epoch !== vpsbgEpoch) {
    if (vpsbgEligible()) queueMicrotask(() => { void scheduleVpsbg(); });
    return;
  }
  const generation = publication_generation();
  const live = () => vpsbgEligible() && epoch === vpsbgEpoch && generation === publication_generation();
  const expired = entry => entry?.introduction?.state === 'waiting' && Date.now() >= entry.introduction.deadline * 1000;
  const publishExpiry = async () => {
    const report = await open();
    if (live()) await reportStore(report, generation, '', 'machine', true);
  };
  // Rust may have dropped the context while the refresh crossed its deadline.
  // The last published waiting card still needs a terminal local report.
  if (contexts.some(expired) || [lastReport?.procurement, ...(lastReport?.procurement?.completed || [])].some(expired)) {
    clearTimeout(vpsbgAttestTimer); vpsbgAttestTimer = null;
    await publishExpiry();
    return;
  }
  const arm = (kind, selected) => {
    if (!selected.length || (kind === 'deposit' ? vpsbgDepositTimer || vpsbgDepositBusy : vpsbgAttestTimer || vpsbgAttestBusy)) return;
    const deadline = kind === 'attest' ? Math.min(...selected.filter(c => !c.accepted).map(c => c.introduction.deadline * 1000)) : Infinity;
    const accepted = kind === 'attest' && selected.some(c => c.accepted);
    const delay = Math.min(accepted ? provider_action_delay() : Math.max(5000, provider_action_delay()), Math.max(0, deadline - Date.now()));
    const timer = setTimeout(async () => {
      if (kind === 'deposit') vpsbgDepositTimer = null; else vpsbgAttestTimer = null;
      if (!live()) return;
      if (kind === 'deposit') vpsbgDepositBusy = true; else vpsbgAttestBusy = true;
      try {
        for (const context of selected) {
          await queueVpsbg(async () => {
            if (!live()) return;
            // Expiry publishes from the original durable deadline without another contact.
            if (kind === 'attest' && !context.accepted && Date.now() >= context.introduction.deadline * 1000) {
              await publishExpiry();
              return;
            }
            const current = JSON.parse(await vpsbg_poll_contexts());
            if (!live()) return;
            if (kind === 'attest' && !context.accepted && Date.now() >= context.introduction.deadline * 1000) {
              await publishExpiry();
              return;
            }
            if (!current.some(item => JSON.stringify(item) === JSON.stringify(context))) return;
            const report = await vpsbg_poll(context.purchase, kind);
            if (live()) await reportStore(report, generation, '', 'machine', true);
          });
        }
      } finally {
        if (kind === 'deposit') vpsbgDepositBusy = false; else vpsbgAttestBusy = false;
        void scheduleVpsbg();
      }
    }, delay);
    if (kind === 'deposit') vpsbgDepositTimer = timer; else vpsbgAttestTimer = timer;
  };
  arm('deposit', contexts.filter(c => c.deposit_pending));
  arm('attest', contexts.filter(c => c.attest_pending && c.installation_binding &&
    (c.accepted || c.introduction?.state === 'waiting')));
};
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
let emailTimer = null;
let emailBusy = false;
const emailPurchase = () => paymentsEligible() && provider_key_is_set() &&
  lastReport?.procurement?.phase === 'email_verification' && lastReport.procurement.email_entered
  ? lastReport.procurement : null;
const stopEmail = () => { clearTimeout(emailTimer); emailTimer = null; };
const scheduleEmail = () => {
  const purchase = emailPurchase();
  if (!purchase) { stopEmail(); return; }
  if (emailTimer || emailBusy) return;
  const identity = JSON.stringify(purchase.identity);
  emailTimer = setTimeout(async () => {
    emailTimer = null;
    if (!emailPurchase() || JSON.stringify(emailPurchase().identity) !== identity) { scheduleEmail(); return; }
    emailBusy = true;
    const generation = publication_generation();
    try {
      await reportStore(await provider_request(JSON.stringify({action:'email_check'})), generation, '', 'machine', true);
    } finally {
      emailBusy = false;
      scheduleEmail();
    }
  }, 20000);
};
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
const presentationReport = (report, step, marks = null) => {
  const value = unlockJson(marks, JSON.parse, report);
  if (value.error) value.page_error_step = step;
  return unlockJson(marks, JSON.stringify, value);
};
const reportStore = (report, generation = publication_generation(), session = '', step = 'store', paymentTimerReport = false, marks = null) => {
  report = presentationReport(report, step, marks);
  const value = unlockJson(marks, JSON.parse, report);
  lastReport = value;
  if (Array.isArray(value.sessions)) latestSessions = value.sessions;
  discardStalePocConfiguration(value);
  schedulePayments();
  scheduleReadiness();
  scheduleEmail();
  void scheduleVpsbg();
  value.poc_configuration = { key_set: poc_key_is_set() };
  value.provider_configuration = { key_set: provider_key_is_set() };
  if (paymentTimerReport) value.payment_timer = true;
  return publish_report(generation, session, unlockJson(marks, JSON.stringify, value));
};
const exactMembers = (value, names) => value && typeof value === 'object' &&
  !Array.isArray(value) && Object.keys(value).length === names.length &&
  names.every(name => Object.hasOwn(value, name));
const startFields = value => typeof value.goal === 'string' && (value.document_source === null || typeof value.document_source === 'string');
const startMembers = (value, required) => startFields(value) &&
  required.every(name => Object.hasOwn(value, name)) &&
  Object.keys(value).every(name => [...required, 'template', 'options', 'inputs'].includes(name));
const validPocConfiguration = config => exactMembers(config, ['endpoint', 'model', 'key', 'sessions']) &&
  typeof config.endpoint === 'string' && typeof config.model === 'string' &&
  config.key instanceof Uint8Array && Array.isArray(config.sessions) && config.sessions.every(session => typeof session === 'string');

// Custody outlives a temporary recovery refusal. Attempts are serialized and only
// refusals retry; a successful configure is never applied a second time.
let pendingPocConfiguration = null;
let pocConfigurationWork = Promise.resolve();
let pocConfigurationTimer = null;
let pocConfigurationEpoch = 0;
let pocConfigurationLifecycle = 0;
let pocConfigurationRevalidating = false;
const recoveryConfigurationRefusals = new Set([
  'inference configuration refused: command response pending; retry after it completes',
  'inference configuration refused: recorded task result awaits recovery; Resume collection in the original session before configuring; then retry configuration',
]);
const clearPendingPocConfiguration = () => {
  clearTimeout(pocConfigurationTimer); pocConfigurationTimer = null;
  clearInput({poc_configure: pendingPocConfiguration?.config});
  pendingPocConfiguration = null;
};
const pocSessions = sessions => (sessions ?? []).filter(session => session.session_state !== 'ended').map(session => session.identity).sort();
const discardStalePocConfiguration = (report = lastReport) => {
  const pending = pendingPocConfiguration;
  if (!pending) return;
  const sessions = report === lastReport && latestSessions ? latestSessions : report?.sessions;
  if (retirementRequested || pending.generation !== publication_generation().toString() ||
      report?.state !== 'unlocked' || report.lifecycle_state === 'ended' ||
      (Array.isArray(sessions) && JSON.stringify(pending.config.sessions) !== JSON.stringify(pocSessions(sessions)))) {
    clearPendingPocConfiguration();
    if (!retirementRequested) postMessage({poc_configure_status: 'rejected'});
  }
};
const configurePoc = (config, generation, retry = null) => {
  const epoch = pocConfigurationEpoch;
  const work = pocConfigurationWork.then(async () => {
    if (retirementRequested || epoch !== pocConfigurationEpoch) { clearInput({poc_configure: config}); return; }
    if (retry && pendingPocConfiguration !== retry) return;
    if (config) {
      if (!config.key.length) {
        if (pendingPocConfiguration) {
          postMessage({poc_configure_status: 'waiting'});
          return;
        }
        postMessage({poc_configure_status: 'cancelled'});
        const current = JSON.parse(await open());
        current.error = 'inference key missing';
        await reportStore(JSON.stringify(current), publication_generation(), '', 'credit');
        return;
      }
      clearPendingPocConfiguration();
      pendingPocConfiguration = {config, generation, refusal: null, retryStep: 0};
    }
    discardStalePocConfiguration();
    const pending = pendingPocConfiguration;
    if (!pending) return;
    clearTimeout(pocConfigurationTimer); pocConfigurationTimer = null;
    if (!paymentsEligible() || pocConfigurationRevalidating || !Array.isArray(lastReport?.sessions)) {
      postMessage({poc_configure_status: 'waiting'});
      return;
    }
    // The wasm entry point zeroes its argument even on refusal. Keep custody of
    // the original until acceptance; the temporary copy never leaves this worker.
    const key = pending.config.key.slice();
    let report;
    try { report = await poc_configure(pending.config.endpoint, pending.config.model, key, JSON.stringify(pending.config.sessions)); }
    finally { key.fill(0); }
    if (retirementRequested || epoch !== pocConfigurationEpoch || pendingPocConfiguration !== pending) return;
    const result = JSON.parse(report);
    if (!result.error) {
      clearPendingPocConfiguration();
      postMessage({poc_configure_status: 'applied'});
      wake_tasks();
    } else if (recoveryConfigurationRefusals.has(result.error)) {
      const repeatedRefusal = pending.refusal === result.error;
      pending.refusal = result.error;
      if (!repeatedRefusal) postMessage({poc_configure_status: 'waiting'});
      const delay = [100, 250, 500, 1000][pending.retryStep];
      pending.retryStep = Math.min(pending.retryStep + 1, 3);
      if (paymentsEligible() && !pocConfigurationRevalidating) {
        pocConfigurationTimer = setTimeout(() => {
          pocConfigurationTimer = null;
          void configurePoc(null, pending.generation, pending);
        }, delay);
      }
      if (repeatedRefusal) return;
    } else {
      clearPendingPocConfiguration();
      postMessage({poc_configure_status: 'rejected'});
    }
    await reportStore(report, publication_generation(), '', 'credit');
  });
  // Unexpected failures end custody and require a fresh submission.
  pocConfigurationWork = work.catch(() => {
    if (pendingPocConfiguration) {
      clearPendingPocConfiguration();
      if (!retirementRequested) postMessage({poc_configure_status: 'rejected'});
    }
  });
  return pocConfigurationWork;
};

const startGoal = async (report, inputs, machine) => {
  let current = JSON.parse(report);
  if (current.error) return report;
  const session = current.sessions?.find(s => s.session_state !== 'ended' && s.bound_set?.length === 1 && s.bound_set[0] === machine);
  if (!session || current.tasks?.some(task => task.start_session === session.identity)) return report;
  if (!session.goal) {
    report = await goal_request(JSON.stringify({session: session.identity, text: inputs.goal, document_source: inputs.document_source || null, template: inputs.template, options: inputs.options, inputs: inputs.inputs}));
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
    const published = JSON.parse(report);
    if (['suspended', 'ended'].includes(published.lifecycle_state)) stopVpsbg();
    if (Array.isArray(published.sessions)) latestSessions = published.sessions;
    discardStalePocConfiguration(published);
    report = presentationReport(report, step);
    await publication.publish(generation, session, report);
  } finally { publication.free(); }
};

onmessage = async ({ data: envelope }) => {
  if (!envelope || envelope.incarnation !== incarnation || typeof envelope.generation !== 'string') { clearInput(envelope?.request ?? envelope); return; }
  const data = envelope.request;
  const emptyPocSubmission = exactMembers(data, ['poc_configure']) && validPocConfiguration(data.poc_configure) && !data.poc_configure.key.length;
  if (emptyPocSubmission && pendingPocConfiguration) {
    // An empty retry acknowledges existing custody without consulting wasm or
    // changing the original submission, its timer, or its session binding.
    postMessage({poc_configure_status: 'waiting'});
    clearInput(data);
    return;
  }
  // Stale keys reach configurePoc only to be wiped with a plain rejection. Keep
  // the lifecycle and presence exceptions required by recovery.
  if (envelope.generation !== publication_generation().toString() && !data?.poc_configure && data?.retire_runtime !== true && typeof data?.lifecycle !== 'string' && !data?.task_presence) { clearInput(data); return; }
  let unlockMarks = null;
  let unlockMarksDone = false;
  try {
  if (!data || typeof data !== 'object' || Object.keys(data).length !== 1) {
    clearInput(data);
    return;
  }
  const wake = {reads:readinessReads, lifecycle:readinessLifecycle};
  if (data.retire_runtime === true) {
    retirementRequested = true;
    clearPendingPocConfiguration();
    clearTimeout(paymentTimer); paymentTimer = null;
    stopReadiness(); stopEmail(); provider_visibility(false);
    stopVpsbg(); vpsbg_presence(false, false);
    await retire_runtime();
    postMessage({ runtime_retired: true });
    return;
  }
  if (typeof data.lifecycle === 'string') {
    const configurationLifecycle = ++pocConfigurationLifecycle;
    pocConfigurationRevalidating = true;
    clearTimeout(pocConfigurationTimer); pocConfigurationTimer = null;
    if (data.lifecycle === 'hidden' || data.lifecycle === 'freeze') { readinessLifecycle++; pageVisible = false; clearTimeout(paymentTimer); paymentTimer = null; stopReadiness(); stopEmail(); provider_visibility(false); stopVpsbg(); }
    if (data.lifecycle === 'visible' || data.lifecycle === 'resume') { pageVisible = true; provider_visibility(true); }
    const report = await lifecycle_transition(data.lifecycle);
    Object.assign(wake, {generation:publication_generation(), identity:JSON.stringify(JSON.parse(report).procurement?.identity)});
    await reportStore(report);
    if ((data.lifecycle === 'visible' || data.lifecycle === 'resume') && configurationLifecycle === pocConfigurationLifecycle) {
      pocConfigurationRevalidating = false;
      if (pendingPocConfiguration) void configurePoc(null, pendingPocConfiguration.generation, pendingPocConfiguration);
    }
    if (data.lifecycle === 'visible' || data.lifecycle === 'resume') await refreshPayments(wake);
    return;
  }
  if (data.task_presence && exactMembers(data.task_presence, ['visible', 'online']) &&
      typeof data.task_presence.visible === 'boolean' && typeof data.task_presence.online === 'boolean') {
    task_presence(data.task_presence.visible, data.task_presence.online);
    pageOnline = data.task_presence.online;
    vpsbgVisible = data.task_presence.visible;
    vpsbg_presence(vpsbgVisible, pageOnline);
    if (!pageOnline || !data.task_presence.visible) stopVpsbg();
    else void scheduleVpsbg();
    return;
  }
  if (data.task_details) {
    const request = data.task_details;
    if (!exactMembers(request, ['id', 'request']) || typeof request.request !== 'string' || request.request.length !== 36) return;
    try {
      if (!retirementRequested && pageVisible && typeof request.id === 'string' && /^[a-f0-9]{48}$/.test(request.id))
        await publish_task_details(publication_generation(), request.id, request.request);
    } catch { /* Only the protected publisher may release a reply. */ }
    return;
  }
  if (data.delivery_details) {
    const request = data.delivery_details;
    if (!exactMembers(request, ['machine', 'request', 'kind']) ||
        typeof request.machine !== 'string' || typeof request.request !== 'string' ||
        request.request.length !== 36 || !['entry', 'commands'].includes(request.kind)) return;
    try {
      if (!retirementRequested && pageVisible)
        await publish_delivery_details(publication_generation(), request.machine, request.request, request.kind === 'commands');
    } catch { /* Only the protected publisher may release a reply. */ }
    return;
  }
  if (data.file_download) {
    const request = data.file_download;
    if (!exactMembers(request, ['id', 'offer', 'request']) ||
        !Object.values(request).every(value => typeof value === 'string')) return;
    const generation = publication_generation();
    let download;
    try {
      download = await poc_download(request.id, request.offer);
      if (retirementRequested || !pageVisible || generation !== publication_generation()) return;
      postMessage({file_download: {...request, generation: generation.toString(), ...download}}, [download.bytes.buffer]);
    } catch (error) {
      if (!retirementRequested && generation === publication_generation())
        postMessage({file_download: {...request, generation: generation.toString(), error: String(error)}});
    } finally {
      if (download?.bytes.byteLength) download.bytes.fill(0);
      download = undefined;
    }
    return;
  }
  const generation = publication_generation();
  let report;
  const step = data.poc_configure || data.credit_request ? 'credit'
    : data.provider_token || data.provider_configure || data.provider_request || data.poc_enroll || data.setup_approve || data.setup_answer ? 'machine'
    : data.poc_bind || data.poc_public_keys || data.poc_accept || data.bind || data.verify_clock || data.withdraw_reinstall || data.task || data.goal || data.requirements_answer || data.delivery || data.goal_accept ? 'task' : 'store';
  const session = data.task?.action === 'end-session' ? '' : data.goal?.session ?? data.goal_accept?.session ?? data.requirements_answer?.session ?? data.delivery?.session ?? data.task?.session ?? '';
  if (data.create instanceof Uint8Array) report = await create(data.create);
  else if (data.unlock instanceof Uint8Array || data.seed_backup_redisplay instanceof Uint8Array) {
    const marks = { unlock_call_ms: 0, worker_json_ms: 0 };
    unlockMarks = marks;
    const started = unlockNow();
    try {
      report = data.unlock instanceof Uint8Array ? await unlock(data.unlock) : await seed_backup_redisplay(data.seed_backup_redisplay);
    } finally { marks.unlock_call_ms += unlockNow() - started; }
  }
  else if (data.seed_backup_reentry instanceof Uint8Array) report = await seed_backup_reentry(data.seed_backup_reentry);
  else if (data.seed_backup_answer === true) report = await seed_backup_answer();
  else if (data.seed_backup_skip === true) report = await seed_backup_skip();
  else if (data.poc_configure && typeof data.poc_configure === 'object') {
    const config = data.poc_configure;
    try {
      if (validPocConfiguration(config)) {
        // Transfer ownership out of the request's finally cleanup.
        const retained = {endpoint: config.endpoint, model: config.model, key: config.key, sessions: [...config.sessions].sort()};
        delete config.key;
        await configurePoc(retained, envelope.generation);
        return;
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
    if (['configure', 'start', 'new_key'].includes(data.credit_request.action)) {
      // A newer explicit credit choice supersedes queued operator configuration.
      pocConfigurationEpoch++;
      clearPendingPocConfiguration();
      postMessage({poc_configure_status: 'cancelled'});
    }
    const value = JSON.parse(await credit_request(JSON.stringify(data.credit_request)));
    if (data.credit_request.action === 'start' && !value.credit_error) value.credit_started_machine = data.credit_request.machine;
    report = JSON.stringify(value);
  }
  else if (data.provider_token !== undefined) {
    const config = data.provider_token;
    try {
      if (exactMembers(config, ["vendor", "token"]) && config.vendor === "vpsbg" && config.token instanceof Uint8Array) report = await provider_token_configure(config.token);
      else { const current = JSON.parse(await open()); current.error = "Invalid VPSBG token entry."; report = JSON.stringify(current); }
    } finally {
      if (config?.token instanceof Uint8Array) config.token.fill(0);
      if (config && typeof config === "object") delete config.token;
    }
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
    try {
      const request = () => provider_request(JSON.stringify(data.provider_request));
      const addressedVpsbg = typeof data.provider_request.purchase === 'string';
      const value = JSON.parse(await (addressedVpsbg || lastReport?.procurement?.vendor?.id === 'vpsbg' ? queueVpsbg(request) : request()));
      if (data.provider_request.action === 'vendor') value.provider_selection_reviewed = false;
      if (data.provider_request.action === 'select' && !value.error) value.provider_selection_reviewed = true;
      report = JSON.stringify(value);
    } finally { delete data.provider_request.email; }
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
  else if (typeof data.poc_bind?.machine === 'string' && (exactMembers(data.poc_bind,['machine']) || startMembers(data.poc_bind,['machine','goal','document_source']))) {
    if (['template', 'options', 'inputs'].some(name => Object.hasOwn(data.poc_bind, name))) report = await poc_bind(data.poc_bind.machine, JSON.stringify(data.poc_bind));
    else if (typeof data.poc_bind.goal === 'string' && !data.poc_bind.goal.trim()) { const current=JSON.parse(await open());current.error='Enter a goal before Start session.';report=JSON.stringify(current); }
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
  Object.assign(wake, {generation:publication_generation(), identity:unlockJson(unlockMarks, JSON.stringify, unlockJson(unlockMarks, JSON.parse, report).procurement?.identity)});
  await reportStore(report, generation, session, step, false, unlockMarks);
  const result = unlockJson(unlockMarks, JSON.parse, report);
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
    if (data.unlock instanceof Uint8Array && unlockJson(unlockMarks, JSON.parse, report).state === 'unlocked' && !unlockJson(unlockMarks, JSON.parse, report).error) setTimeout(() => retry_ended_credit(), 0);
    unlockMarksDone = unlockMarks !== null;
    wake_tasks();
    await refreshPayments(wake);
  }
  const display = JSON.parse(await seed_backup_display());
  if (display) postMessage(display);
  } finally {
    // Prerequisite changes wake interrupted work; task controls retain their explicit workflow.
    if (data && (data.unlock instanceof Uint8Array || (data.poc_configure && !emptyPocSubmission) || data.credit_request || data.lifecycle === 'resume' ||
        Object.keys(data).some(name => name.startsWith('seed_backup_')))) wake_tasks();
    // Posted last and not awaited, so it orders after every original step of this request.
    if (unlockMarksDone) publish_unlock_worker_timings(unlockMarks.unlock_call_ms, unlockMarks.worker_json_ms).catch(() => {});
  }
};
task_presence(initialPresence?.visible === true, initialPresence?.online === true);
vpsbg_presence(vpsbgVisible, pageOnline);
await reportStore(await open());
