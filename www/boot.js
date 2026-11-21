// The page sends passphrase and re-entry bytes once and clears fields immediately. The only
// mnemonic display is the dedicated seed-backup ceremony; lock removes its words and inputs.
// Begin module loading before page setup or deployment-default reads.
const firstWorker = new Worker(new URL('./worker.js', import.meta.url), { type: 'module' });
const $ = (id) => document.getElementById(`tau-${id}`);
const status = $('status');
const show = (state, text) => {
  status.dataset.state = state === 'ready' ? 'harness-ready' : state;
  status.textContent = text;
  if (state === 'ready') {
    $('harness-details').hidden = false;
    $('harness-details').open = false;
    $('harness-details').append(status);
  } else {
    $('store').before(status);
    $('harness-details').hidden = true;
  }
};

// One same-directory object is validated before any value is applied.
const defaultsFields = ['provider_origin', 'relay_url', 'chat_endpoint', 'model', 'topup_sat'];
const defaultsInputs = ['provider-origin', 'provider-relay', 'poc-relay', 'poc-endpoint', 'poc-model', 'credit-amount'];
const defaultsEdited = new Set();
for (const id of defaultsInputs) $(id).addEventListener('input', () => defaultsEdited.add(id));
const validDefaults = value => {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).some(k => ![...defaultsFields, 'relay_key'].includes(k)) || !defaultsFields.every(k => Object.hasOwn(value, k))) return false;
  const ipv4 = host => host.split('.').length === 4 && host.split('.').every(p => /^(0|[1-9][0-9]{0,2})$/.test(p) && Number(p) <= 255);
  const dns = host => host.length > 0 && host.length <= 253 && host.split('.').every(p =>
    p.length <= 63 && /^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$/.test(p));
  const url = (text, kind) => {
    const prefix = kind === 'relay' ? 'wss://' : 'https://';
    if (typeof text !== 'string' || !text.startsWith(prefix) || text.length > (kind === 'provider' ? 320 : 2048) || /[^\x21-\x7e]|[\\?@#%]/.test(text)) return false;
    const rest = text.slice(prefix.length), slash = rest.indexOf('/');
    const authority = slash < 0 ? rest : rest.slice(0, slash), path = slash < 0 ? '' : rest.slice(slash);
    let host, port;
    if (kind === 'provider' && authority.startsWith('[')) {
      const match = authority.match(/^(\[[0-9a-fA-F:.]+\])(?::([0-9]+))?$/);
      if (!match) return false;
      [, host, port] = match;
    } else {
      const match = authority.match(/^([^:]+)(?::([0-9]+))?$/);
      if (!match) return false;
      [, host, port] = match;
      const name = kind === 'provider' ? host.replace(/\.$/, '') : host;
      if (!dns(name)) return false;
      if (kind === 'provider') {
        const last = name.split('.').at(-1).toLowerCase();
        if ((/^[0-9]+$/.test(last) || /^0x[0-9a-f]*$/.test(last)) && (!ipv4(host) || host !== name)) return false;
      } else if (kind === 'chat' && (name.split('.').some(p => p.toLowerCase().startsWith('xn--')) || (!ipv4(name) && !/^[A-Za-z]/.test(name.split('.').at(-1))))) return false;
    }
    if (port !== undefined && (Number(port) > 65535 || (kind !== 'provider' && Number(port) === 0))) return false;
    if (kind === 'provider' && path !== '' && path !== '/') return false;
    if (kind === 'relay' && (!path.endsWith('/') || path.split('/').some(p => p === '.' || p === '..' || !/^[A-Za-z0-9_.-]*$/.test(p)))) return false;
    if (kind === 'chat' && !/^[A-Za-z0-9/\-._~!$&'()*+,;=:]*$/.test(path)) return false;
    try { return new URL(text).protocol === (kind === 'relay' ? 'wss:' : 'https:'); } catch { return false; }
  };
  return url(value.provider_origin, 'provider') && url(value.relay_url, 'relay') &&
    url(value.chat_endpoint, 'chat') && typeof value.model === 'string' && value.model.trim() === value.model &&
    value.model.length > 0 && value.model.length <= 128 && /^[A-Za-z0-9._/:\-]+$/.test(value.model) &&
    Number.isInteger(value.topup_sat) && value.topup_sat >= 100 && value.topup_sat <= 5000;
};
const validRelayKey = key => typeof key === 'string' && /^[0-9a-f]{64}$/.test(key) &&
  BigInt('0x' + key) > 0n && BigInt('0x' + key) < 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const loadDefaults = async () => {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 3000);
  try {
    const response = await fetch(new URL('poc-defaults.json', location.href), {credentials: 'omit', cache: 'no-store', redirect: 'error', signal: controller.signal});
    if (!response.ok || new URL(response.url).origin !== location.origin) throw Error();
    const reader = response.body.getReader();
    const chunks = []; let size = 0;
    while (true) {
      const {done, value} = await reader.read(); if (done) break;
      size += value.byteLength; if (size > 16384) { controller.abort(); throw Error(); } chunks.push(value);
    }
    const bytes = new Uint8Array(size); let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    const value = JSON.parse(new TextDecoder('utf-8', {fatal:true}).decode(bytes));
    if (!validDefaults(value)) throw Error();
    return {provider_origin: value.provider_origin, relay_key: validRelayKey(value.relay_key) ? value.relay_key : null,
      fields: Object.fromEntries(defaultsFields.map(field => [field, value[field]]))};
  } catch {
    $('defaults-status').textContent = 'Deployment defaults are missing or invalid. Public fallback values remain in use. Creating a provider account requires valid deployment defaults; the existing-account form remains available.';
    return {provider_origin: null, relay_key: null};
  } finally { clearTimeout(timer); }
};
let defaultsPublished = false;
const publishDefaults = (material, accepted) => {
  if (defaultsPublished || !material.fields) return;
  defaultsPublished = true;
  if (!accepted) {
    $('defaults-status').textContent = 'Deployment defaults are missing or invalid. Public fallback values remain in use. Creating a provider account requires valid deployment defaults; the existing-account form remains available.';
    return;
  }
  for (const [id, field] of [['provider-origin', 'provider_origin'], ['provider-relay', 'relay_url'], ['poc-relay', 'relay_url'], ['poc-endpoint', 'chat_endpoint'], ['poc-model', 'model'], ['credit-amount', 'topup_sat']]) {
    if ($(id) && !defaultsEdited.has(id) && !providerReviewToken) $(id).value = material.fields[field];
  }
  updateInferenceFacts();
  updateCreditAmount(renderedReport?.credit);
  $('defaults-status').textContent = 'Deployment defaults loaded. Public fields remain editable; review and approval use the displayed values.';
};
const defaultsReady = loadDefaults();

const texts = {
  starting: 'Opening the local store…',
  working: 'Working…',
  'in-use': 'Farseed may be open in another tab or window of this browser. If it is, use that one or close it. Otherwise wait a moment: this page carries on by itself.',
  none: 'There is no local store yet.',
  locked: 'The local store is locked.',
  locking: 'Locking: waiting for the worker to finish any begun write and clear working secrets…',
  unlocked: 'The local store is unlocked.',
};
const clearWords = () => $('seed-backup-words-slot').replaceChildren();
let redisplay = false;
let ceremony = false;
let suspended = false;
const unlockNow = performance.now.bind(performance);
let unlockPageMarks = null;
const goalOutcomes = new Map();
const creditGoalDrafts = new Map();
const creditTemplateDrafts = new Map();
const goalTemplateDrafts = new Map();
const setupDrafts = new Map();
const startDrafts = new Map();
const taskLimitDrafts = new Map();
let pocKeyRefusal = '';
let pocKeySubmission = null;
const renderPocKeyStatus = store => {
  $('poc-key-status').textContent = pocKeySubmission === 'submitting' ? 'Setting key…'
    : pocKeySubmission === 'waiting' ? 'Key retained in worker memory. Waiting for task recovery before applying it automatically.'
    : pocKeySubmission === 'rejected' ? 'The key was not set: see the message above, then enter the key again.'
    : store.poc_configuration?.key_set === true ? 'Key set.'
    : store.poc_configuration?.key_set === false ? 'Key unset.' : 'Key status unavailable.';
};
const snapshotWorker = () => {
  const current = worker;
  const generation = current?.generation;
  return { postMessage: (data, transfer) => current?.sendAt ? current.sendAt(data, transfer, generation) : current?.postMessage(data, transfer) };
};
const readinessWait = store => ({starting:'The provider is starting the machine.',published_key:'The machine’s published host key has not appeared yet.',address:'Waiting for one allocated IPv4 address.',refused:`The machine check could not finish. ${store.page_error_step === 'machine' && store.error ? `Reason: ${shortLine(store.error, 160)}` : 'No reason is available. Refresh to check again.'}`,ready:'Saving the machine for setup.',checking:'Checking whether the machine is ready.'}[store.readiness?.kind ?? 'checking'] ?? 'The machine’s status is unavailable.');
const localTime = value => {
  const date = new Date(value);
  return date.toDateString() === new Date().toDateString()
    ? date.toLocaleTimeString(undefined, {hour: '2-digit', minute: '2-digit', hourCycle: 'h23'})
    : date.toLocaleString(undefined, {dateStyle: 'short', timeStyle: 'short'});
};
const stepNames = ['store', 'credit', 'machine', 'task'];
const foldChoices = new Map();
const rawFoldChoices = new Map();
let previousStep;
for (const name of stepNames) {
  const fold = $(`step-${name}-fold`);
  fold.querySelector('summary').addEventListener('click', () => foldChoices.set(name, !fold.open));
}
const startDisclosure = parent => {
  const disclosure = document.createElement('p');
  disclosure.dataset.startDisclosure = '';
  disclosure.textContent = $('lifecycle-disclosure').textContent;
  parent.append(disclosure);
};
const mainHomes = new Map();
const restoreMainActions = (retained) => {
  for (const [button, {parent, next, form}] of mainHomes) {
    if (retained.has(button)) continue;
    if (parent.isConnected) parent.insertBefore(button, next?.parentNode === parent ? next : null);
    else button.remove();
    if (form === null) button.removeAttribute('form'); else button.setAttribute('form', form);
    for (const control of [button, ...button.querySelectorAll('.main-action')]) {
      control.classList.remove('main-action');
      if (!control.className) control.removeAttribute('class');
    }
    mainHomes.delete(button);
  }
};
const renderSteps = store => {
  const unlocked = store.state === 'unlocked';
  const active = unlocked && !ceremony;
  const sessions = (store.sessions ?? []).filter(session => session.session_state !== 'ended');
  const current = !active ? 'store' : sessions.length || store.tasks?.length ? 'task'
    : !store.credit?.can_start && !store.poc_configuration?.key_set ? 'credit'
    : store.poc_targets?.length ? 'task' : 'machine';
  if (current !== previousStep) {
    if (foldChoices.get(current) === false) foldChoices.delete(current);
    previousStep = current;
  }
  const messages = {
    store: texts[store.state] ?? store.state,
    credit: store.credit_error || creditBalanceText(store.credit) || (!store.credit?.account ? 'No inference credit yet.' : 'Inference credit balance not read yet.'),
    machine: store.readiness?.expired ? 'Published host-key wait expired after three hours. First contact is stopped.'
      : store.readiness?.inactive ? 'Machine checks are paused. Open the machine step for details.'
      : payReadiness(store.procurement ?? {}) ? `${readinessWait(store)} ${store.readiness?.checked_at ? `Last check: ${localTime(store.readiness.checked_at)}.` : 'The machine has not been checked yet.'}`
      : store.procurement?.phase ? purchaseStatus(store.procurement) : store.poc_targets?.length ? 'Machine saved. Review it before Start session.' : 'Choose a new or existing machine.',
    task: store.tasks?.map(task => `${task.machine}: ${taskStatus(task.status, task)}${task.inference_retry ? ' — waiting to retry the AI connection' : ''}${task.pause_reason ? ' — ' + plainPause(task.pause_reason) : ''}`).join(' ') || (store.lifecycle_state === 'reconciling' ? 'Waiting to revalidate the saved session.' : sessions.length ? 'Session open. Set or continue its goal.' : 'No session started.'),
  };
  if (!active) for (const name of ['credit', 'machine', 'task'].filter(name => name !== 'credit' || !unlocked)) messages[name] = unlocked ? 'Record the seed backup to continue.' : name === 'machine' && store.state === 'locked' ? 'Unlock to continue checking the machine.' : 'Open the local store to view this step.';
  for (const name of stepNames) {
    const step = document.querySelector(`[data-step="${name}"]`);
    step.dataset.current = String(current === name);
    $(name === 'credit' ? 'credit-status' : `step-${name}-status`).textContent = messages[name];
    const errors = [name === (store.page_error_step ?? 'store') ? store.error : '', name === 'task' ? pocKeyRefusal : ''];
    $(`step-${name}-error`).textContent = [...new Set(errors.filter(Boolean))].join(' ');
    $(`step-${name}-fold`).open = foldChoices.get(name) ?? false;
    step.querySelectorAll('.main-action').forEach(button => { button.classList.remove('main-action'); if (!button.className) button.removeAttribute('class'); });
  }
  const retained = new Set();
  const emphasize = (name, controls) => {
    const offered = controls.filter(button => {
      if (!button || button.closest('[hidden]') || button.closest('[data-step]')?.dataset.step !== name) return false;
      const home = mainHomes.get(button.form ?? button)?.parent;
      return !home || (home.isConnected && !home.closest('[hidden]'));
    });
    const button = offered.find(button => !button.disabled) ?? offered[0];
    if (!button) return;
    button.classList.add('main-action');
    // Keep this decision beside the uncertainty the operator is accepting.
    if (button.hasAttribute('data-pending-retry')) return;
    // Move the existing form intact when its action is inside optional settings.
    // Controls already beside their required facts keep their original container.
    const node = button.form ?? button;
    if (mainHomes.has(node)) { retained.add(node); return; }
    if (button.closest('#tau-provider-existing') || !button.closest(`#tau-step-${name}-fold`)) return;
    mainHomes.set(node, {parent: node.parentNode, next: node.nextSibling, form: node.getAttribute('form')});
    retained.add(node);
    $(`step-${name}-action`).append(node);
  };
  emphasize('store', [$('create'), $('unlock'), $('seed-backup-answer'), $('seed-backup-check'), $('redisplay')]);
  emphasize('credit', [$('credit-invoice'), $('credit-check'), $('credit-configure'), $('poc-inference-form').querySelector('button')]);
  const purchase = store.procurement;
  const machineAction = purchase?.stop ? $('provider-stop')
    : !store.provider_configuration?.key_set ? $('provider-catalogue')
    : purchase?.phase === 'email_verification' ? (purchase.email_entered ? $('provider-email-check') : $('provider-email-form').querySelector('button'))
    : purchase?.phase === 'initial_invoice' ? $('provider-invoice')
    : purchase?.phase && !['terms_changed', 'handed_off'].includes(purchase.phase) ? $('provider-resume')
    : purchase?.selection ? $('provider-approval-form').querySelector('button')
    : providerCatalogue ? $('provider-selection-form').querySelector('button') : $('provider-catalogue');
  emphasize('machine', [machineAction, $('setup-approve')]);
  const taskControls = selector => [...document.querySelector('[data-step="task"]').querySelectorAll(selector)];
  const needsDeclaration = (store.setup ?? []).some(machine => !machine.declaration);
  const workingTasks = new Set((store.tasks ?? []).filter(task => !task.summary &&
    !['complete', 'abandoned', 'paused'].includes(task.status) && !awaitingAiKey(task) && !awaitingOperator(task) &&
    sessions.some(session => session.identity === task.start_session && session.bound_set.length === 1 &&
      session.bound_set[0] === task.machine)).map(task => task.id));
  emphasize('task', [
    ...taskControls('[data-verify-clock]'),
    ...taskControls('[data-requirements-decision="approve"]'),
    ...(needsDeclaration ? taskControls('[data-poc-propose]') : []),
    ...taskControls('[data-pending-retry]'),
    ...taskControls('[data-task] button').filter(button => button.textContent === 'Resume' &&
      !workingTasks.has(button.closest('[data-task]').dataset.task)),
    ...taskControls('[data-start-accepted-goal], [data-goal-enter], [data-bind]'),
    ...taskControls('#tau-poc-targets button').filter(button => button.textContent.startsWith('Start session ') &&
      !sessions.some(session => session.bound_set.some(machine => button.textContent === `Start session ${machine}`))),
    ...(!workingTasks.size ? taskControls('[data-poc-propose], [data-end-session], [data-delivery-check], [data-task] button, #tau-poc-targets button') : []),
  ]);
  restoreMainActions(retained);
};
let renderedReport;
let renderedReportJson;
const reportJson = ({payment_timer, ...content}) => JSON.stringify(content);
const taskDetails = new Map();
const deliveryDetails = {entry: new Map(), commands: new Map()};
const clearDetails = () => {
  taskDetails.clear();
  deliveryDetails.entry.clear();
  deliveryDetails.commands.clear();
};
let taskDetailsStore;
const updateCreatePassphrase = (state, error) => {
  const value = $('passphrase').value;
  $('confirm-field').hidden = state !== 'none' || value === '';
  if (value === '') $('confirm').value = '';
  const warning = $('passphrase-warning');
  warning.hidden = state !== 'none' || [...value].length >= 16 ||
    (value === '' && error === 'The two passphrases differ.');
  warning.textContent = value === ''
    ? "With no passphrase, anyone who can open this browser on this phone, or who has a copy of its data, can open Farseed: your machines' keys, your provider account (which can buy machines with your money) and your AI credit."
    : "A passphrase shorter than 16 characters can be guessed by anyone who has a copy of this browser's data.";
};
const render = (store, forceRender = false) => {
  let report;
  if (store.payment_timer === true) {
    report = reportJson(store);
    if (renderedReport !== undefined) renderedReportJson ??= reportJson(renderedReport);
    if (report === renderedReportJson && !store.error && !store.credit_error && !forceRender) return;
  }
  renderedReport = store;
  renderedReportJson = report;
  if (store.state !== 'unlocked' || ['suspended', 'reconciling', 'ended'].includes(store.lifecycle_state) ||
      store.lifecycle_generation !== taskDetailsStore?.lifecycle_generation) {
    machineFileLists.clear();
    for (const key of fileDownloads.keys()) if (JSON.parse(key)[0].startsWith('machine:')) fileDownloads.delete(key);
  }
  if (store.state !== 'unlocked' || ['suspended', 'reconciling'].includes(store.lifecycle_state) ||
      store.lifecycle_generation !== taskDetailsStore?.lifecycle_generation) clearDetails();
  else {
    const summaries = new Set((store.tasks ?? []).filter(task => task.summary).map(task => task.id));
    for (const id of taskDetails.keys()) if (!summaries.has(id)) taskDetails.delete(id);
    // Replies can be ahead of their requesting report; refresh only for a different report version.
    for (const task of store.tasks ?? []) {
      const opened = taskDetails.get(task.id);
      if (opened && (opened.task?.revision ?? opened.revision) !== task.revision &&
          opened.revision !== task.revision) {
        const request = crypto.randomUUID();
        taskDetails.set(task.id, {request, pending: true, revision: task.revision});
        snapshotWorker().postMessage({task_details: {id: task.id, request}});
      }
    }
    const machines = new Set((store.delivery ?? []).map(entry => entry.machine));
    const deliverySummaries = new Set((store.delivery ?? []).filter(entry => entry.summary).map(entry => entry.machine));
    for (const machine of deliveryDetails.entry.keys()) if (!deliverySummaries.has(machine)) deliveryDetails.entry.delete(machine);
    for (const machine of deliveryDetails.commands.keys()) if (!machines.has(machine)) deliveryDetails.commands.delete(machine);
    for (const entry of store.delivery ?? []) {
      const opened = deliveryDetails.commands.get(entry.machine);
      if (opened && (opened.fetchedRevision ?? opened.revision) !== entry.reports_revision &&
          opened.revision !== entry.reports_revision) {
        const request = crypto.randomUUID();
        deliveryDetails.commands.set(entry.machine, {request, pending: true, revision: entry.reports_revision});
        snapshotWorker().postMessage({delivery_details: {machine: entry.machine, request, kind: 'commands'}});
      }
    }
  }
  taskDetailsStore = store;
  const focused = document.activeElement;
  const selection = [focused?.selectionStart, focused?.selectionEnd, focused?.selectionDirection];
  for (const details of document.querySelectorAll('details[data-fold-key]')) {
    rawFoldChoices.set(details.dataset.foldKey, details.open);
  }
  const { state } = store;
  if (state !== 'unlocked') $('task-results')?.replaceChildren();
  $('store-state').dataset.lifecycle = store.lifecycle_state ?? '';
  if (store.seed_backup_stage !== undefined) ceremony = state === 'unlocked' && store.seed_backup_stage !== 'inactive';
  if (['locked', 'none', 'refused'].includes(state)) ceremony = false;
  // The storage note belongs to an open store, after the seed words: nothing on the create or locked screens.
  $('persist').hidden = state !== 'unlocked' || ceremony;
  $('session-controls').replaceChildren();
  renderSetup(store);
  renderPoc(store);
  if (unlockPageMarks?.rendering) {
    const started = unlockNow();
    renderTasks(store);
    unlockPageMarks.cards_ms += unlockNow() - started;
    const slot = $('tasks');
    unlockPageMarks.cards = slot?.querySelectorAll(':scope > [data-task]').length ?? 0;
    unlockPageMarks.card_nodes = slot?.querySelectorAll('*').length ?? 0;
  } else renderTasks(store);
  $('store').dataset.state = state;
  $('store-state').textContent = texts[state] ?? state;
  $('store-explanation').textContent = state === 'refused'
    ? `The local store is refused: ${store.reason}. Reload the page to try again.` : '';
  if (store.lifecycle_state) $('store-state').textContent += ` Session state: ${store.lifecycle_state}.`;
  $('create-help').hidden = $('create').hidden = state !== 'none';
  updateCreatePassphrase(state, store.error);
  $('passphrase-field').hidden = state !== 'none' && state !== 'locked';
  $('passphrase').autocomplete = state === 'none' ? 'new-password' : 'current-password';
  $('passphrase').enterKeyHint = state === 'none' ? 'next' : 'go';
  $('unlock').hidden = state !== 'locked';
  $('lock').hidden = state !== 'unlocked';
  if ($('lock').hidden) $('store-disclosure-slot').append($('lifecycle-disclosure'));
  else $('lifecycle-line').after($('lifecycle-disclosure'));
  const stage = store.seed_backup_stage;
  const active = state === 'unlocked' && typeof stage === 'string' && stage !== 'inactive';
  clearWords();
  $('seed-backup').hidden = !active;
  $('seed-backup-answer').hidden = stage !== 'showing_words';
  $('seed-backup-entry').hidden = stage !== 'answering';
  $('redisplay').hidden = state !== 'unlocked' || active;
  const completion = store.seed_backup_completion;
  $('seed-completion').textContent = '';
  if (state === 'unlocked' && completion) {
    $('seed-completion').textContent = completion === 'full_reentry'
      ? ' Seed-backup record: all twelve words re-entered.'
      : ' Seed-backup record: re-entry check skipped.';
  }
  $('seed-backup-state').textContent = active
    ? [stage === 'showing_words'
      ? 'Your seed backup: write these 12 words on paper, in order, and keep them private. They back up the keys this store uses for your machines. Your AI credit and provider account are not in them: those are kept only in this browser.'
      : stage === 'answering' ? 'Type all 12 words to check your copy, or skip the check.'
      : stage === 'append_failed' ? 'Your seed backup could not be saved. Reload this page to try again.' : 'Seed backup.',
    store.seed_backup_owed
      ? 'Until this is recorded, no new machine, relay pass or handover is allowed.'
      : stage !== 'append_failed' && 'You asked to see the words again: record a new full re-entry, or skip.',
    'No commands are sent while this is open.', store.error].filter(Boolean).join(' ')
    : '';
  if (state === 'locked' && redisplay) $('store-explanation').textContent += ' Enter the local passphrase again to show the seed backup.';
  renderSteps(store);
  for (const details of document.querySelectorAll('details[data-fold-key]')) {
    details.open = rawFoldChoices.get(details.dataset.foldKey) ?? false;
  }
  // Revalidation temporarily withholds cards without retiring their records.
  if (state === 'unlocked' && store.lifecycle_state !== 'reconciling' && Array.isArray(store.tasks)) {
    const offered = new Set([...document.querySelectorAll('details[data-fold-key]')].map(details => details.dataset.foldKey));
    for (const key of rawFoldChoices.keys()) if (!offered.has(key)) rawFoldChoices.delete(key);
  }
  if (focused?.isConnected && document.activeElement !== focused && focused.getClientRects().length) {
    focused.focus({preventScroll: true});
    if (Number.isInteger(selection[0])) focused.setSelectionRange(...selection);
  }
  renderProgress(store);
};

const progressView = {result: null, rows: new Map(), more: null};
const renderProgress = (store) => {
  const hidden = store.state === undefined || ['starting', 'working', 'locking'].includes(store.state);
  const rows = [
    ['store', 'Make your store'],
    ['credit', 'Buy AI credit'],
    ['approve', 'Choose and approve the machine'],
    ['pay', 'Pay for the machine'],
    ['start', 'Machine starting'],
    ['setup', 'Setting up'],
    ['checks', 'Final checks'],
  ];
  let done = rows.map(() => false);
  let skipped = rows.map(() => false);
  let current = 0;
  let line = '';
  let step;
  if (store.state !== 'unlocked') {
    line = ({
      locked: 'Unlock to see where you are.',
      none: 'Waiting for you: make your store below.',
      'in-use': 'Waiting for the store to be free. See below.',
      refused: 'Your store could not be opened. See below.',
    })[store.state] ?? '';
  } else {
    const purchase = store.procurement ?? {};
    const targets = store.poc_targets ?? [];
    const target = machine => targets.some(t => t.machine === machine);
    const liveSessions = (store.sessions ?? []).filter(session => session.session_state !== 'ended');
    const inLiveSession = task => liveSessions.some(session => session.identity === task.start_session);
    const setupFor = machine => {
      const tasks = (store.tasks ?? []).filter(task => machine !== undefined && task.machine === machine)
        .sort((a, b) => (b.creation_rank ?? -1) - (a.creation_rank ?? -1));
      const session = liveSessions.find(session => session.bound_set?.length === 1 && session.bound_set[0] === machine);
      // The live task, else the machine's newest task: an older success never stands in for newer unfinished work.
      // A live session on this machine with no task yet is where the user is: an older session's task never stands in.
      const task = tasks.find(task => !task.summary && inLiveSession(task)) ?? tasks.find(inLiveSession)
        ?? (session ? undefined : tasks[0]);
      return {session, task};
    };
    const draft = Boolean(purchase.selection) && (!purchase.phase || purchase.phase === 'handed_off');
    const setupSession = draft ? liveSessions.find(session => {
      if (session.bound_set?.length !== 1) return false;
      const {task} = setupFor(session.bound_set[0]);
      return task && !task.verdict && task.status !== 'abandoned';
    }) : undefined;
    const followDraft = draft && !setupSession;
    // A new draft takes over unless a live session still has a setup in progress.
    const machine = followDraft ? undefined : setupSession?.bound_set[0] ?? purchase.machine
      ?? liveSessions.find(session => session.bound_set?.length === 1)?.bound_set[0]
      ?? (targets.length === 1 ? targets[0].machine : undefined);
    const {session, task} = followDraft ? {} : setupFor(machine);
    const live = Boolean(task) && inLiveSession(task);
    const completed = (purchase.completed ?? []).find(entry => machine !== undefined && entry.machine === machine);
    const currentPurchase = machine !== undefined && machine === purchase.machine;
    const bought = !followDraft && (machine !== undefined ? currentPurchase || Boolean(completed)
      : targets.some(t => t.machine === purchase.machine || (purchase.completed ?? []).some(entry => entry.machine === t.machine)));
    const saved = !followDraft && (machine !== undefined ? target(machine) : targets.length > 0);
    skipped = [false, false, !bought && saved, !bought && saved, false, false, false];
    const checksPassed = [
      'Delivered (service and TCP checks only)',
      'Delivered (service, TCP and sign-in checks only)',
      'Delivered (service, TCP, sign-in and control-center checks only)',
    ].includes(task?.verdict);
    done = [
      !ceremony && store.seed_backup_stage === 'inactive',
      store.credit?.can_start === true || store.poc_configuration?.key_set === true,
      bought && (!currentPurchase || ['approved', 'registration_uncertain', 'registered', 'create_uncertain', 'email_verification',
        'initial_invoice', 'invoice_uncertain', 'payment_readiness', 'handed_off'].includes(purchase.phase) || saved),
      bought && (currentPurchase ? purchase.payment?.is_paid === true || purchase.phase === 'handed_off' || saved
        : completed?.is_paid === true || completed?.target_saved === true || saved),
      currentPurchase ? purchase.phase === 'handed_off' || saved : saved,
      task?.status === 'verifying' || Boolean(task?.verdict),
      checksPassed,
    ];
    // Once a session or task exists, setup is where the user is: credit doesn't take over as the current step.
    const settingUp = Boolean(session || task);
    current = done.findIndex((value, index) => !value && !skipped[index] && !(index === 1 && settingUp));
    if (!done[0]) {
      const stage = store.seed_backup_stage;
      line = stage === 'showing_words' ? 'Waiting for you: write down your 12 words below.'
        : stage === 'answering' ? 'Waiting for you: type your 12 words below, or skip the check.'
        : stage === 'append_failed' ? 'Your words could not be saved. See below.'
        : ceremony ? 'Waiting for you: finish the 12 words below.' : '';
    } else if (['suspended', 'reconciling'].includes(store.lifecycle_state)) {
      line = 'Checking the saved session after the interruption; nothing to press yet.';
    } else if (current === 1) {
      line = 'Waiting for you: get AI credit below.';
    } else if (current === 2) {
      line = purchase.selection ? 'Waiting for you: review the machine and approve it below.'
        : 'Waiting for you: choose a machine below.';
    } else if (current === 3) {
      line = purchase.stop ? 'Waiting for you: decide below whether to stop this purchase.'
        : purchase.candidates?.length ? 'Waiting for you: choose below which machine this purchase uses.'
        : purchase.payment?.is_paid === false && Date.parse(purchase.payment.expires) <= Date.now()
          ? "The machine's invoice has expired. See the machine step below."
        : ({
          approved: 'Waiting for you: order the machine below.',
          registered: 'Waiting for you: order the machine below.',
          registration_uncertain: 'Waiting for you: check the order again below.',
          create_uncertain: 'Waiting for you: check the order again below.',
          invoice_uncertain: 'Waiting for you: check the order again below.',
          email_verification: 'Waiting for you: confirm your email with the provider.',
          initial_invoice: "Waiting for you: get the machine's invoice below, then pay it in your wallet.",
          payment_readiness: "Waiting for you: pay the machine's invoice in your wallet.",
        })[purchase.phase] ?? 'See the machine step below.';
    } else if (current === 4) {
      line = store.readiness?.expired || store.readiness?.inactive || store.readiness?.kind === 'refused'
        ? 'The machine check stopped. See the machine step below.'
        : 'Your machine is starting and being checked; nothing to press.';
    } else if (current === 5) {
      // The session card then offers only Verify issuer clock (see the goal card), whether or not a task started.
      line = session?.inference_limits?.state === 'clock-withheld' && !session.credit_backed
        ? 'Waiting for you: verify the issuer clock below.'
        : !task ? (!session ? 'Waiting for you: start the session below.'
          : session.goal ? 'Waiting for you: start the setup with its saved goal below.'
          : 'Waiting for you: give the session its goal below.')
        : task.status === 'abandoned' ? 'The setup was stopped. See its task card below.'
        : !live ? "The setup's session ended before it finished. See its task card below."
        : awaitingAiKey(task) ? 'Waiting for you: create the AI key below.'
        : awaitingOperator(task) ? 'Waiting for you: the setup has a question for you below.'
        : task.status === 'paused' ? 'Waiting for you: the setup is paused. The reason, and how to continue, are below.'
        : task.inference_retry ? 'Waiting to try the AI connection again; nothing to press.'
        : task.status === 'waiting' ? 'Waiting for the machine to answer; nothing to press.'
        : 'The AI is working; nothing to press.';
    } else if (current === 6) {
      // End session keeps a verifying task's status, but its checks stop: the ended guard comes first.
      line = task?.verdict ? (!checksPassed ? 'The setup was handed over with findings. Its task card says what.' : '')
        : task && !live ? "The setup's session ended before it finished. See its task card below."
        : session?.inference_limits?.state === 'clock-withheld' && !session.credit_backed ? 'Waiting for you: verify the issuer clock below.'
        : task?.status === 'verifying' ? 'Farseed is running its own final checks; nothing to press.' : '';
    }
    if (current === 5 && task && live && !task.summary && task.status !== 'abandoned') {
      const latestCommand = (task.completed ?? []).filter(([, tool]) => tool?.name === 'exec').at(-1);
      const origin = controlCenterOrigin(task, task.proposal?.call_id) ?? controlCenterOrigin(task, latestCommand?.[0]);
      if (Number.isInteger(origin?.step) && origin.step >= 1 && origin.step <= 12 && controlCenterLabels.steps[origin.step]) {
        step = origin.step;
        rows[5][1] = `Setting up — step ${step} of 12`;
        line = `Step ${step}: ${controlCenterLabels.steps[step]}. ${line}`;
      } else if (origin?.step === 0 && origin.block === 'R2') {
        line = `Fixing a problem. ${line}`;
      }
    }
  }
  // While the store step itself needs the user (create, unlock, the seed words), show only that step, so its controls
  // stay on a phone's first screen.
  const compact = current === 0;
  const result = {
    hidden,
    rows: hidden ? [] : rows.slice(0, compact ? 1 : rows.length).map(([key, text], index) => ({
      key,
      state: done[index] ? 'done' : skipped[index] ? 'skip' : current === index ? 'current' : 'todo',
      mark: done[index] ? '✓ ' : skipped[index] ? '– ' : current === index ? '▸ ' : '○ ',
      label: skipped[index] ? `${text} — not needed for a machine you added yourself` : text,
      current: current === index ? 'step' : null,
      line: current === index ? line : index === 6 && done.every((value, row) => value || skipped[row])
        ? 'Setup finished and its own checks passed. Its task card has the result.' : null,
      step: index === 5 && current === index && step !== undefined ? step : null,
    })),
    more: !hidden && compact,
  };
  const signature = JSON.stringify(result);
  if (progressView.result === signature) return;

  const list = $('progress');
  if (list.hidden !== hidden) list.hidden = hidden;
  if (!hidden) {
    const shown = [];
    for (const data of result.rows) {
      let cached = progressView.rows.get(data.key);
      if (!cached) {
        const row = document.createElement('li');
        row.dataset.progressStep = data.key;
        const mark = document.createElement('span');
        mark.setAttribute('aria-hidden', 'true');
        const label = document.createElement('span');
        row.append(mark, label);
        cached = {row, mark, label, detail: null, strip: null, boxes: []};
        progressView.rows.set(data.key, cached);
      }
      const {row, mark, label} = cached;
      if (row.dataset.progressState !== data.state) row.dataset.progressState = data.state;
      if (mark.textContent !== data.mark) mark.textContent = data.mark;
      if (label.textContent !== data.label) label.textContent = data.label;
      if (row.getAttribute('aria-current') !== data.current) {
        if (data.current === null) row.removeAttribute('aria-current');
        else row.setAttribute('aria-current', data.current);
      }
      if (data.line !== null) {
        if (!cached.detail) {
          cached.detail = document.createElement('div');
          cached.detail.dataset.progressLine = '';
        }
        if (cached.detail.textContent !== data.line) cached.detail.textContent = data.line;
        if (![...row.children].includes(cached.detail)) {
          row.insertBefore(cached.detail, [...row.children].includes(cached.strip) ? cached.strip : null);
        }
      } else if ([...row.children].includes(cached.detail)) cached.detail.remove();
      if (data.step !== null) {
        if (!cached.strip) {
          cached.strip = document.createElement('div');
          cached.strip.dataset.progressStrip = '';
          cached.strip.setAttribute('role', 'img');
          for (let segment = 0; segment < 12; segment++) {
            const box = document.createElement('span');
            cached.boxes.push(box);
            cached.strip.append(box);
          }
        }
        const label = `Step ${data.step} of 12`;
        if (cached.strip.getAttribute('aria-label') !== label) cached.strip.setAttribute('aria-label', label);
        for (const [index, box] of cached.boxes.entries()) {
          if (index < data.step) {
            if (box.dataset.filled !== '') box.dataset.filled = '';
          } else if (box.dataset.filled !== undefined) delete box.dataset.filled;
        }
        if (![...row.children].includes(cached.strip)) row.append(cached.strip);
      } else if ([...row.children].includes(cached.strip)) cached.strip.remove();
      shown.push(row);
    }
    if (result.more) {
      if (!progressView.more) {
        progressView.more = document.createElement('li');
        progressView.more.dataset.progressMore = '';
        progressView.more.textContent = 'Six more steps after this.';
      }
      shown.push(progressView.more);
    }
    for (const child of [...list.children]) if (!shown.includes(child)) child.remove();
    for (const [index, row] of shown.entries()) {
      if (list.children[index] !== row) list.insertBefore(row, list.children[index] ?? null);
    }
  }
  progressView.result = signature;
};

// Fixture wording until the signed bundle supplies it. No message supplies question text.
const classQuestion = "Will this machine serve people you have never met, for example by renting out space on it or hosting other people's accounts?";
const classHelp = "If you are not sure, the machine is treated as serving people you have never met: it never holds spendable keys and is always bound alone.";
const answers = [['yes', 'Yes'], ['no', 'No, only me and people I know'], ['not_sure', 'Not sure']];
const paragraph = (parent, text) => {
  const p = document.createElement('p');
  p.textContent = text;
  parent.append(p);
  return p;
};
const rawDetails = (parent, value, identity) => {
  const details = document.createElement('details');
  details.hidden = true;
  const record = parent.closest('[data-machine], [data-task], [data-delivery-card], [id]');
  details.dataset.foldKey = JSON.stringify([identity ?? (record ? [...record.attributes]
    .filter(attribute => ['id', 'data-machine', 'data-task', 'data-delivery-card'].includes(attribute.name))
    .map(attribute => [attribute.name, attribute.value]) : []), value]);
  const summary = document.createElement('summary'); summary.textContent = 'Details';
  const text = document.createElement('pre'); text.dataset.rawJson = ''; text.textContent = JSON.stringify(value, null, 2);
  details.append(summary, text); parent.append(details);
  return details;
};
const detailFold = (parent, label, identity) => {
  const details = document.createElement('details');
  details.dataset.foldKey = JSON.stringify(identity);
  const summary = document.createElement('summary'); summary.textContent = label;
  details.append(summary); parent.append(details);
  return details;
};
// These summaries affect the page only; saved records retain their original text.
const shortLine = (value, limit = 80) => {
  const line = String(value ?? '').replace(/\s+/g, ' ').trim();
  if (line.length <= limit) return line;
  const cut = line.slice(0, limit - 1);
  const space = cut.lastIndexOf(' ');
  return `${space > 0 ? cut.slice(0, space) : cut}…`;
};
// Only known command words belong on the filmed card; arguments stay in Details.
const commandSummary = command => {
  const text = String(command ?? '').trim();
  const match = text.match(/^([A-Za-z0-9_./+-]+)(?=\s|$|[|;&<>])/);
  if (!match) return 'command …';
  const program = match[1].split('/').pop();
  if (!program) return 'command …';
  const rest = text.slice(match[1].length).trim();
  if (!rest) return shortLine(program);
  const first = rest.split(/\s/)[0];
  const words = {
    systemctl: ['enable', 'disable', 'start', 'stop', 'restart', 'reload', 'status', 'is-active', 'is-enabled', 'daemon-reload'],
    pacman: ['-S', '-Sy', '-Syu', '-Syyu', '-R', '-Rs', '-Rns', '-Q', '-Qi', '-Qs'],
    'nixos-rebuild': ['switch', 'boot', 'test', 'build', 'dry-build', 'dry-activate'],
    nix: ['build', 'shell', 'run', 'profile', 'search', 'flake', 'store', 'eval'],
    apt: ['update', 'upgrade', 'install', 'remove', 'purge', 'show', 'list'],
    'apt-get': ['update', 'upgrade', 'install', 'remove', 'purge'],
    dnf: ['update', 'upgrade', 'install', 'remove', 'info', 'list'],
    yum: ['update', 'upgrade', 'install', 'remove', 'info', 'list'],
  };
  const word = !/[|;&<>()`$\\\r\n]/.test(text) && Object.hasOwn(words, program) && words[program].includes(first) ? ` ${first}` : '';
  return shortLine(`${program}${word} …`);
};
const awaitingAiKey = task => task?.proposal?.tool?.name === 'request_ai_key' && !task.ai_key_approved && !task.pending && !['complete', 'abandoned'].includes(task.status);
const awaitingOperator = task => task?.proposal?.tool?.name === 'ask_operator' && !task.pending && !['complete', 'abandoned'].includes(task.status);
const operatorLink = link => {
  if (typeof link !== 'string' || !link.length || new TextEncoder().encode(link).length > 2048 || /[\p{White_Space}\p{Cc}\\]/u.test(link) || !/^https:\/\//i.test(link)) return;
  const authority = link.slice(link.indexOf('://') + 3).split(/[/?#]/)[0];
  if (!authority || authority.includes('@')) return;
  try {
    const url = new URL(link);
    if (url.protocol === 'https:' && url.hostname && !url.username && !url.password) return url;
  } catch { /* Refuse malformed links without displaying their text. */ }
};
const taskStatus = (status, task) => awaitingAiKey(task) || awaitingOperator(task) ? 'waiting for you' : ({running:'working', waiting:'waiting for the machine', verifying:'checking the result', paused:'paused', complete:'done', abandoned:'stopped'})[status] ?? status;
const purchaseStatus = purchase => ({
  approved: "Purchase approved; the machine hasn't been ordered yet. Press Create the server to order it.",
  registration_uncertain: 'Waiting to confirm that the provider saved the access key. The page will check before continuing.',
  registered: 'Access key saved; preparing the machine order.',
  create_uncertain: 'Waiting to confirm the machine order. The page will check before continuing.',
  email_verification: 'Waiting for your email to be verified by the machine provider.',
  initial_invoice: 'Machine ordered; review the invoice before paying.',
  invoice_uncertain: 'Waiting to confirm the invoice. The page will check before continuing.',
  payment_readiness: purchase.payment?.is_paid ? 'Payment received; the provider is starting the machine.' : 'Waiting for payment of the machine invoice.',
  handed_off: 'Machine ready.',
  terms_changed: 'The price or setup changed. Review the updated plan before approving it.'
})[purchase.phase] ?? 'Purchase status is unavailable. Open Details for the saved information.';
const pauseMessages = new Map();
const pauseGroup = (reasons, message) => reasons.forEach(reason => pauseMessages.set(reason, message));
pauseGroup(['unknown task', 'stale or ended task', 'task ended'], reason => `This task is no longer available to continue. Review this saved reason: ${shortLine(reason, 160)}`);
pauseGroup(['task encoding', 'task credential boundary', 'task result encoding', 'task result publication'], 'The page could not safely read or show this task. Unlock again; if it stays paused, keep the saved details for help.');
pauseGroup(['protected output unavailable', 'job output hex', 'output key collision after protection', 'redaction marker cannot exclude held credentials'], 'The page could not safely check the result for secrets, so it was withheld. Unlock again; if it stays paused, keep the saved details for help.');
pauseGroup(['session credential has no response scan representation', 'held credential derivation refused'], 'The page could not check results against its held credentials. Unlock again before Resume.');
pauseGroup(['locked', 'response requires an unlocked seed'], 'The page is locked. Unlock it to continue.');
pauseGroup(['missing pending job', 'missing pending identity', 'task has no pending job', 'no committed job evidence', 'job outcome is not trustworthy', 'pending task has no proposal', 'missing job exit', 'missing verification record', 'verification job mismatch'], reason => `The page cannot establish what happened to the earlier command. Review this saved reason before deciding how to continue: ${shortLine(reason, 160)}`);
pauseGroup(['resolved target differs from task machine', 'fresh authority must bind only the task machine'], 'The connection points to a different machine. Restore the original machine connection before Resume.');
pauseGroup(['resolved relay, host and user are required before Resume'], 'The machine connection is incomplete. Supply its relay, address and login name before Resume.');
pauseGroup(['trusted host pin missing; configure it before Resume'], 'The machine’s trusted host key is missing. Configure it before Resume.');
pauseGroup(['committed job record differs from its intent and cannot checkpoint; pending identity retained for inspection; to configure, Stop task; remote effects and command holds remain'], reason => `The saved result does not match the command that was sent. Saved reason: ${shortLine(reason, 160)}. Review this reason and use Stop task before changing the setup. Earlier commands may still run.`);
pauseGroup(['session authority belongs to another task; use the task’s original session'], 'This connection belongs to a different task. Restore this task’s original session before Resume.');
pauseGroup(['proposal approval pending; review the open requirements card and approve explicitly or reject before Resume'], 'The proposed requirements need your decision. Review the requirements card and approve or reject it before Resume.');
pauseGroup(['original session requires acceptance of Acting on a goal with no brief'], 'This session still needs your approval to act on a goal without a brief. Review and accept that choice before Resume.');
pauseGroup(['sessions ended', 'no live session', 'session ended', 'goal requires a live session'], 'The session has ended or is unavailable. This task needs its original active session to continue.');
pauseGroup(['reconciliation or verification required after suspension'], 'The page must check the saved session after the interruption. Unlock again before Resume.');
pauseGroup(['session cap exhausted'], 'The session’s spending limit has been reached. Review its budget before continuing.');
pauseGroup(['session expired'], 'The session has expired. Review the session controls before continuing.');
pauseGroup(['incompatible issuer usage', 'incompatible or missing issuer acceptance'], 'The saved spending approval cannot be used. Review the session’s spending approval before continuing.');
pauseGroup(['clock uncertain; verification required', 'clock evidence out of range'], 'The page cannot rely on its clock. Use the clock check before Resume.');
pauseGroup(['invalid spend', 'invalid spend exponent', 'invalid nonnegative spend', 'spend scale', 'unsupported spend precision'], reason => `The page could not read the spending amount safely. Review this saved reason before continuing: ${shortLine(reason, 160)}`);
pauseGroup(['recorded job is running; Resume inspects it again'], 'The earlier command is still running. Resume checks it again without running it twice.');
pauseGroup(['task paused: diagnostic protection failed; inspect authority and configuration before Resume'], 'The page could not safely show why it stopped. Check the session and connection settings before Resume.');
pauseGroup(['recorded job output requires protection before checkpoint', 'verification excerpt requires protection before checkpoint'], 'The page could not safely save the command result. Unlock again before Resume; the earlier command will be checked without running it twice.');
pauseGroup(['task revision exhausted'], 'This task has reached its saved-update limit and cannot continue. Keep its details for help.');
pauseGroup(['journal refused', 'AES-GCM refused the record', 'move: FileSystemHandle.move() is not available'], 'The browser could not safely save the result. Reopen and unlock this page before Resume; the earlier command will be checked without running it twice.');
const plainPause = reason => {
  if (!reason) return '';
  const verdict = 'Findings unknown until a complete re-check. ';
  if (reason.startsWith(verdict)) return verdict + plainPause(reason.slice(verdict.length));
  const checkpoint = 'recorded result could not be checkpointed: ';
  if (reason.startsWith(checkpoint)) {
    const cause = reason.slice(checkpoint.length);
    return pauseMessages.has(cause) ? plainPause(cause) : 'The browser could not safely save the result. Reopen and unlock this page before Resume; the earlier command will be checked without running it twice.';
  }
  if (pauseMessages.has(reason)) {
    const message = pauseMessages.get(reason);
    return typeof message === 'function' ? message(reason) : message;
  }
  const machineCheck = reason.match(/^Checked the machine at (\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z): it has no record of this command\. /);
  if (machineCheck) return `Checked the machine at ${new Date(machineCheck[1]).toLocaleString()}: it has no record of this command.`;
  if (/^collection returned no outcome for pending call \d+ job [0-9a-f]+; pending identity retained$/.test(reason)) return 'The earlier command’s result is not available yet. Resume checks it again without running it twice.';
  if (/^collection record identity mismatch for pending call \d+ job [0-9a-f]+; pending identity retained$/.test(reason)) return `The returned result does not match the earlier command. Saved reason: ${shortLine(reason, 160)}. Review this reason before Resume; the command will not be run twice.`;
  if (/^collection (?:recorded no record found|could not confirm whether the command reached the machine; Resume will check again without running it twice) for pending call \d+ job [0-9a-f]+; pending identity retained$/.test(reason)) return 'The page could not confirm whether the command reached the machine. Resume will check again without running it twice.';
  if (/^collection (?:failed for pending call|failed for pending call \d+ job|.* for pending call) /.test(reason)) return `The page could not establish the earlier command’s result. Saved reason: ${shortLine(reason, 160)}. Review this reason and check the connection before Resume; the command will not be run twice.`;
  return reason;
};
const sessionWait = reason => {
  if (reason === 'Inference key required for another request; existing job collection remains available.') return 'Resupply the AI connection key to continue. The page can still collect the earlier command’s result.';
  if (reason === 'Automatic inference waits for the admitted endpoint and model. Restore them, or explicitly Resume with the displayed configuration. Existing job collection remains available.') return 'Restore the earlier AI connection settings, or use Resume to approve the settings shown here. The page can still collect the earlier command’s result.';
  const plain = plainPause(reason);
  return plain !== reason ? plain : `This session needs a check before more work can run. Saved reason: ${shortLine(reason, 160)}. Review this reason and unlock again.`;
};
const commandResultWord = result => {
  const content = result?.content ?? result;
  if (content?.outcome === 'unknown') return 'result unknown';
  if (content?.outcome === 'still_running' || content?.record?.kind === 'background' || content?.job_record?.record?.kind === 'background') return 'still running in the background';
  if (Number.isInteger(content?.exit_status)) return content.exit_status === 0 ? 'finished' : `failed with code ${content.exit_status}`;
  return content?.running === true ? 'still running' : 'result unknown';
};
const checkSummary = (check, outcome) => {
  if (outcome?.content?.outcome === 'still_running') return `Check: ${commandSummary(check.command)} — still running in the background`;
  const service = check.command.match(/^systemctl is-(active|enabled) -- '([^']+)'\.service$/);
  if (service) {
    const [, kind, name] = service;
    const observation = check.observation;
    const value = observation?.kind === (kind === 'active' ? 'running' : 'enabled') && typeof observation.value === 'boolean' ? observation.value : null;
    return `Check: ${name} ${kind === 'active' ? 'is running' : 'starts at boot'} — ${value === null ? 'result unknown' : value ? 'yes' : 'no'}`;
  }
  if (check.command === 'ss -H -n -l -t -u') {
    const observation = check.observation;
    if (observation?.kind !== 'sockets' || !Array.isArray(observation.value)) return 'Check: listening ports — result unknown';
    const groups = [];
    for (const proto of ['tcp', 'udp']) {
      const ports = new Map();
      for (const socket of observation.value.filter(socket => socket.proto === proto)) {
        const local = /^127\./.test(socket.address) || socket.address === '::1';
        ports.set(socket.port, (ports.get(socket.port) ?? true) && local);
      }
      const external = [...ports].filter(([, local]) => !local).map(([port]) => port).sort((a, b) => a - b);
      const local = [...ports].filter(([, local]) => local).map(([port]) => port).sort((a, b) => a - b);
      if (external.length || local.length) groups.push(`${proto.toUpperCase()} ${external.join(', ')}${local.length ? `${external.length ? ' (plus ' : ''}local-only ${local.join(', ')}${external.length ? ')' : ''}` : ''}`);
    }
    return `Check: listening ports — ${groups.join('; ') || 'none'}`;
  }
  return `Check: machine setup — ${check.exit_status === 0 ? 'finished' : check.exit_status == null ? 'result unknown' : `failed with code ${check.exit_status}`}`;
};
const showCheckReport = (parent, report) => {
  const result = report.status === 'still running in the background' ? report.status : report.status === 'not run' ? 'not run' : report.exit_status == null
    ? (['queued', 'attempted', 'pending'].includes(report.status) ? 'waiting' : 'result unknown')
    : report.exit_status === 0 ? 'ran without an error (exit 0)' : `failed (exit ${report.exit_status})`;
  paragraph(parent, `${commandSummary(report.command)} — ${result}`);
  rawDetails(parent, report);
};
// Delivery reports carry the command as its exact bytes in lowercase hex; show it as text, or as unreadable.
const hexCommandText = hex => {
  if (typeof hex !== 'string' || !/^(?:[0-9a-f]{2})*$/.test(hex)) return '';
  try { return new TextDecoder('utf-8', {fatal: true}).decode(Uint8Array.from(hex.match(/../g) ?? [], byte => parseInt(byte, 16))); }
  catch { return ''; }
};
const showDeliveryReport = (parent, report) => {
  paragraph(parent, `Command: ${commandSummary(hexCommandText(report.command))}`);
  paragraph(parent, `Exit status: ${report.terminal?.exit_status ?? report.evidence?.at(-1)?.exit_status ?? 'not recorded'}.`);
  for (const evidence of report.evidence ?? []) {
    paragraph(parent, `Result: ${shortLine(evidence.state?.replaceAll('_', ' ') ?? 'unknown')}; exit status: ${evidence.exit_status ?? 'not recorded'}.`);
    paragraph(parent, `Command match: ${{advisory_match: 'matches the saved command', finding: 'differs from the saved command', no_record: 'no command record'}[evidence.agreement] ?? 'unknown'}.`);
    if (evidence.stdout) paragraph(parent, `Output: ${shortLine(evidence.stdout, 320)}`);
    if (evidence.stderr) paragraph(parent, `Error output: ${shortLine(evidence.stderr, 320)}`);
  }
};
const readableFacts = (parent, value) => {
  const list = document.createElement('dl');
  for (const [key, item] of Object.entries(value)) {
    const label = document.createElement('dt'); label.textContent = key.replaceAll('_', ' ');
    const fact = document.createElement('dd');
    if (item !== null && typeof item === 'object' && Object.keys(item).length) readableFacts(fact, item);
    else fact.textContent = item === null ? 'None' : typeof item === 'object'
      ? (Array.isArray(item) ? 'Empty list' : key === 'limits' ? 'No caps (empty limits)' : 'Empty set') : String(item);
    list.append(label, fact);
  }
  parent.append(list);
};
const updateInferenceFacts = () => {
  for (const node of document.querySelectorAll('[data-inference-approval]')) {
    node.textContent = `Inference endpoint: ${$('poc-endpoint').value}; model: ${$('poc-model').value}.`;
  }
};
for (const name of ['poc-endpoint', 'poc-model']) $(name).addEventListener('input', updateInferenceFacts);
const installationPreview = (parent, d) => {
  paragraph(parent, 'Installation preview. At handover, the page checks the promised services and TCP ports only.');
  const departures = document.createElement('strong');
  const extraPorts = Array.isArray(d.listeners.inbound) ? d.listeners.inbound.filter(e => !(e.proto === 'tcp' && e.port === 22 && e.from === 'any')) : [];
  const services = Array.isArray(d.services) ? d.services : [];
  const keyKind = kind => kind === 'public' ? 'a public key' : `${kind} key material`;
  const additions = [
    ...services.map(e => `runs the ${e.name} service${e.scope.kind === 'user' ? ` for user ${e.scope.account}` : ''}`),
    ...extraPorts.map(e => e.from === 'none' ? `${e.proto.toUpperCase()} port ${e.port} only from inside the machine` : `answers on ${e.proto.toUpperCase()} port ${e.port} ${e.from === 'any' ? 'for anyone' : 'for its peers (who can reach it is not checked)'}`),
    ...(Array.isArray(d.listeners.outbound) ? d.listeners.outbound.map(e => `may connect out ${e.host === 'any' ? '' : `to ${e.host} `}on ${e.proto.toUpperCase()} port ${e.port}`) : []),
    ...(d.key_material.spendable === true ? ['may hold keys that can spend money'] : []),
    ...(Array.isArray(d.key_material.permitted) ? d.key_material.permitted.map(e => `${keyKind(e.kind)} at ${e.where}`) : []),
    ...(Array.isArray(d.default_credentials) ? d.default_credentials.map(e => `changes the default password for ${e}`) : [])
  ];
  departures.textContent = `What this setup adds beyond the basic machine: ${additions.join('; ') || 'nothing extra'}.`;
  parent.append(departures);
  if (d.listeners.inbound === 'unspecified') paragraph(parent, 'Incoming ports are not stated yet; handover is blocked.');
  else if (!d.listeners.inbound.length) paragraph(parent, 'No port is permitted to answer.');
  else if (d.listeners.inbound.some(e => e.proto === 'tcp' && e.port === 22 && e.from === 'any')) paragraph(parent, 'The basic machine also allows SSH connections on TCP port 22 from anyone.');
  paragraph(parent, 'All open TCP ports count, including ports used only inside the machine and ports that came with it. An unexpected port is a finding. An allowed port need not be in use. UDP ports are listed but not judged.');
  if (d.services === 'unspecified') paragraph(parent, 'Services are not stated yet; handover is blocked.');
  else if (!services.length) paragraph(parent, 'No service is promised.');
  else for (const e of services) paragraph(parent, e.lifecycle === 'running-at-delivery'
    ? `${e.name} must be running at handover. A restart may stop it.`
    : `${e.name} must be running and set to start at boot.`);
  if (d.listeners.outbound === 'unspecified') paragraph(parent, 'Outgoing connections are not stated yet; handover is blocked.');
  else if (!d.listeners.outbound.length) paragraph(parent, 'No restriction on outgoing connections is promised.');
  if (d.key_material.spendable === 'unspecified') paragraph(parent, 'Whether money keys are allowed is not stated yet; handover is blocked.');
  else if (d.key_material.spendable === false) paragraph(parent, 'Keys that can spend money are not allowed.');
  if (d.key_material.permitted === 'unspecified') paragraph(parent, 'Other expected keys are not stated yet; handover is blocked.');
  else if (!d.key_material.permitted.length) paragraph(parent, 'No other keys are expected. SSH access keys and application keys are counted separately.');
  paragraph(parent, Array.isArray(d.drift_checks) && !d.drift_checks.length ? 'No extra checks on later visits.' : 'Checks on later visits are not stated.');
  paragraph(parent, Array.isArray(d.required) && !d.required.length ? 'No extra checks at handover.' : 'Extra handover checks are not stated.');
  if (d.default_credentials === 'none' || Array.isArray(d.default_credentials) && !d.default_credentials.length) paragraph(parent, 'No default passwords are listed to be changed.');
  else if (d.default_credentials === 'unspecified') paragraph(parent, 'Default passwords to change are not stated yet; handover is blocked.');
  paragraph(parent, 'This proof of concept does not check security hardening, SSH or local passwords, stored keys, later changes, outgoing restrictions or default password changes. It does not test a reboot.');
  paragraph(parent, 'Completion checks services and TCP listeners and visits each handed-over address once to see that it asks for sign-in. Differences leave the task paused as Handed over with findings. Incomplete reads leave Findings unknown until a complete re-check.');
  rawDetails(parent, d, ['installation-candidate', parent.dataset.requirementsCard]);
};
const renderDeclaration = (parent, d) => {
  paragraph(parent, `Delivery declaration version ${d.version}.`);
  const list = (label, value, empty, entry) => {
    if (value === 'unspecified') paragraph(parent, `${label}: unspecified (not stated).`);
    else if (!value.length) paragraph(parent, `${label}: explicit empty set; ${empty}.`);
    else for (const e of value) paragraph(parent, `${label}: ${entry(e)}.`);
  };
  list('Inbound listeners', d.listeners.inbound, 'no listener may be present', e => `${e.proto} port ${e.port} from ${e.from}`);
  list('Outbound restrictions', d.listeners.outbound, 'no restriction declared', e => `${e.proto} host ${e.host} port ${e.port}`);
  list('Services', d.services, 'no service obligation declared', e => `${e.name}, ${e.scope.kind}${e.scope.kind === 'user' ? ` account ${e.scope.account}` : ' (no account)'}, ${e.lifecycle === 'running-at-delivery' ? 'running at delivery' : 'enabled and survives reboot'}`);
  paragraph(parent, `Spendable tenant material: ${d.key_material.spendable === 'unspecified' ? 'unspecified (not stated)' : d.key_material.spendable ? 'permitted' : 'forbidden'}.`);
  list('Permitted tenant material', d.key_material.permitted, 'no tenant material may be present; application secrets are classified separately', e => `${e.kind} at ${e.where}`);
  for (const [label, value, empty] of [['Drift checks on re-entry', d.drift_checks, 'no re-entry checks declared'], ['Required checks', d.required, 'no delivery checks declared']]) {
    if (value === 'unspecified') paragraph(parent, `${label}: unspecified (not stated).`);
    else if (!value.length) paragraph(parent, `${label}: explicit empty set; ${empty}.`);
    else { paragraph(parent, label); for (const entry of value) readableFacts(parent, entry); rawDetails(parent, value, ['declaration', parent.dataset.machine, label]); }
  }
  if (d.default_credentials === 'none') paragraph(parent, 'Default credentials: none.');
  else list('Default credentials to change', d.default_credentials, 'none declared', e => e);
};
// Remember nested raw folds even while their lazy history disclosure has no children.
const endedSessionFolds = new Map();
const renderEndedSessions = (section, machine, store) => {
  const ended = (store.sessions ?? []).filter(session => session.session_state === 'ended' && session.bound_set.includes(machine));
  if (!ended.length) return;
  const details = document.createElement('details');
  details.dataset.endedSessions = machine;
  details.dataset.foldKey = JSON.stringify(['ended-sessions', machine]);
  const summary = document.createElement('summary');
  summary.textContent = `${ended.length} earlier sessions ended. Their approvals can no longer be used.`;
  details.append(summary);
  const populate = () => {
    if (details.childElementCount > 1) return;
    for (const session of ended) {
      paragraph(details, 'An earlier session ended. Its approvals can no longer be used.');
      const raw = rawDetails(details, session, ['ended-session', session.identity]);
      const key = raw.dataset.foldKey;
      const open = rawFoldChoices.get(key) ?? endedSessionFolds.get(key) ?? false;
      rawFoldChoices.set(key, open);
      endedSessionFolds.set(key, open);
      raw.open = open;
      raw.querySelector('summary').addEventListener('click', () => endedSessionFolds.set(key, !raw.open));
      raw.addEventListener('toggle', () => {
        if (raw.isConnected) endedSessionFolds.set(key, raw.open);
      });
    }
  };
  details.open = rawFoldChoices.get(details.dataset.foldKey) ?? false;
  if (details.open) populate();
  details.addEventListener('toggle', () => { if (details.open && details.isConnected) populate(); });
  section.append(details);
};
const renderSetup = (store) => {
  const worker = snapshotWorker();
  const slot = $('setup');
  const facts = $('setup-facts');
  if (store.state === 'unlocked') {
    for (const card of document.querySelectorAll('[data-goal-card]')) {
      const fields = [...card.querySelectorAll('textarea, input')].filter(field => !field.dataset.pocDeclaration);
      setupDrafts.set(card.dataset.goalCard, fields.map(field => field.value));
    }
    if (Array.isArray(store.sessions)) {
      const live = new Set(store.sessions.filter(session => session.session_state !== 'ended').map(session => session.identity));
      for (const identity of setupDrafts.keys()) if (!live.has(identity)) setupDrafts.delete(identity);
    }
  }
  slot.replaceChildren();
  $('task-setup').replaceChildren();
  slot.hidden = store.state !== 'unlocked' || store.seed_backup_stage !== 'inactive';
  facts.replaceChildren(); facts.hidden = slot.hidden;
  // Approval facts and their press stay together; accepted prices remain openable.
  if (!slot.hidden && store.setup?.length) $('step-machine-fold').append(facts);
  else slot.append(facts);
  if (slot.hidden) return;
  const addEnd = identity => {
    const end = document.createElement('button');
    end.type = 'button'; end.textContent = 'End session'; end.dataset.endSession = identity;
    end.addEventListener('click', () => { end.disabled = true; worker.postMessage({task: {action: 'end-session', session: identity}}); });
    const binding = [...(store.sessions ?? []), ...(store.endable_sessions ?? [])].find(session => session.identity === identity);
    paragraph($('session-controls'), `Session for ${(binding?.bound_set ?? []).join(', ')}.`);
    rawDetails($('session-controls'), {session: identity}, ['session-control', identity]);
    $('session-controls').append(end);
  };
  if (store.lifecycle_state === 'reconciling') {
    for (const session of store.endable_sessions ?? []) {
      paragraph($('session-controls'), `Checking the saved session for ${session.bound_set.join(', ')}.`);
      addEnd(session.identity);
    }
    return;
  }
  const approved = store.setup ?? [];
  const entries = approved.length ? approved.map(m => m.entry) : store.setup_offer ?? [];
  if (!entries.length) return;
  paragraph(facts, approved.length ? 'Approved setup' : 'Approve the setup');
  const purchase = Boolean(store.procurement?.phase || store.procurement?.completed?.length);
  if (!purchase) paragraph(facts, "Prices are fixture data, not a vendor's price.");
  for (const entry of entries) {
    const billing = entry.cost.period.billing;
    const period = billing ? `${billing.count} ${billing.interval}` : entry.cost.period;
    paragraph(facts, `${entry.machine}: ${entry.vendor}; ${entry.product}; ${entry.region}; ${entry.cost.amount} ${entry.cost.unit} per ${period}.`);
  }
  if (!purchase) {
    const monthly = entries.reduce((sum, entry) => sum + BigInt(entry.cost.amount), 0n);
    paragraph(facts, `Setup total: ${monthly} sat per month; ${monthly * 12n} sat per year.`);
  }
  paragraph(facts, 'Each machine will be bound alone in its own session.');
  paragraph(facts, purchase ? 'The purchase card records the approved billing interval and currency. App Lock and Stop task do not cancel the VM or its billing. Payment remains external, and this page does not change automatic renewal.' : "Recurring means each machine is billed by its vendor every month from the moment it is created until it is destroyed or abandoned, whether or not setup finishes. Farseed never pays for a machine and cannot stop a vendor's billing; only you can.");
  if (!approved.length) {
    if (store.lifecycle_state === 'ended') return;
    const button = document.createElement('button');
    button.type = 'button';
    button.id = 'tau-setup-approve';
    button.textContent = 'Approve setup';
    button.addEventListener('click', () => {
      button.disabled = true;
      worker.postMessage({ setup_approve: true });
    });
    slot.append(button);
    return;
  }
  for (const machine of approved) {
    const section = document.createElement('section');
    section.dataset.machine = machine.entry.machine;
    paragraph(section, `Machine: ${machine.entry.machine}.`);
    rawDetails(section, {family: machine.family, index: machine.index}, ['machine', machine.entry.machine, 'identity']);
    if (machine.class === null) {
      paragraph(section, `Machine class for ${machine.entry.machine}.`);
      paragraph(section, classQuestion);
      paragraph(section, classHelp);
      const controls = document.createElement('div');
      controls.dataset.classAnswers = '';
      for (const [answer, label] of answers) {
        const button = document.createElement('button');
        button.type = 'button';
        button.dataset.answer = answer;
        button.textContent = label;
        button.addEventListener('click', () => {
          for (const control of controls.children) control.disabled = true;
          worker.postMessage({ setup_answer: { machine: machine.entry.machine, answer } });
        });
        controls.append(button);
      }
      section.append(controls);
    } else {
      paragraph(section, machine.answer === 'no' ? 'This machine is for you and people you know.' : 'This machine may serve people you do not know.');
    }
    const access = machine.access;
    if (access) {
      paragraph(section, 'Machine access is approved.');
      rawDetails(section, access, ['machine', machine.entry.machine, 'access']);
    }
    if (machine.declaration) {
      paragraph(section, 'Approved setup requirements are saved.');
      rawDetails(section, machine.declaration, ['machine', machine.entry.machine, 'requirements']);
    }
    renderDelivery($('task-setup'), machine.entry.machine, store);
    for (const approval of (store.reinstall_approvals ?? []).filter(a => a.entry === machine.entry.machine)) {
      paragraph(section, `Dedicated reinstall reset ${approval.reset}: ${approval.state}; rendering session ${approval.session}.`);
      if (approval.state === 'no longer usable') paragraph(section, 'Approve again in this session to proceed; the new reset requires a newer rescue activation and a confirming read.');
      if (approval.withdrawal_offer) {
        paragraph(section, 'A standing destructive reinstall disposition still opens the installation through its own reset. Withdrawal of this approval does not withdraw that disposition. An eligible approved reset can run while hidden; there is no guaranteed withdrawal interval.');
        const withdraw = document.createElement('button');
        withdraw.type = 'button'; withdraw.dataset.withdrawReinstall = String(approval.approval);
        withdraw.textContent = `Withdraw approval for ${approval.reset}`;
        withdraw.addEventListener('click', () => { withdraw.disabled = true; worker.postMessage({ withdraw_reinstall: { approval: approval.approval, reset: approval.reset, entry: approval.entry } }); });
        section.append(withdraw);
      }
    }
    for (const approval of machine.requirements ?? []) {
      if (approval.proposal.kind === 'tighten_class') paragraph(section, 'Approved tightening: single-purpose to multi-tenant. The original class answer is retained.');
    }
    const installation = (store.installations ?? []).find(i => i.machine === machine.entry.machine);
    if (installation) paragraph(section, `Installation: ${installation.installation}.`);
    renderEndedSessions(section, machine.entry.machine, store);
    const session = (store.sessions ?? []).find(s => s.session_state !== 'ended' && s.bound_set.includes(machine.entry.machine));
    if (session) {
      paragraph(section, `Session open for ${session.bound_set.join(', ')}.`);
      rawDetails(section, {session: session.identity, state: session.inference_limits?.state ?? session.session_state}, ['session', session.identity]);
      if (session.readiness_reason) {
        paragraph(section, sessionWait(session.readiness_reason));
        rawDetails(section, {reason: session.readiness_reason}, ['session-wait', session.identity]);
      }
      paragraph(section, `AI connection selected for ${machine.entry.machine}.`);
      addEnd(session.identity);
      const limits = session.inference_limits;
      if (limits && !session.credit_backed) {
        paragraph(section, `Confirmed limit: ${(BigInt(limits.confirmed.cap_hundredths) / 100n)}.${String(BigInt(limits.confirmed.cap_hundredths) % 100n).padStart(2, '0')} ${limits.confirmed.unit}; lifetime ${limits.confirmed.lifetime_seconds / 60} minutes. No renewal; observed spend ${limits.observed_spend}. Unaccounted spend is not zero or refunded.`);
        paragraph(section, limits.original_expiry ? `Original requested expiry: ${new Date(limits.original_expiry * 1000).toISOString()} (UTC). All delays and hidden or frozen time consume this lifetime.` : 'Lifetime has not started.');
        if (limits.state === 'clock-withheld') paragraph(section, 'Clock validity unknown; verification required. The original expiry has not changed.');
      }
      if (limits?.state === 'clock-withheld' && !session.credit_backed) {
        if (session.goal) paragraph(section, session.goal.text);
        const verify = document.createElement('button');
        verify.type = 'button'; verify.dataset.verifyClock = session.identity;
        verify.textContent = 'Verify issuer clock';
        verify.addEventListener('click', () => { verify.disabled = true; worker.postMessage({ verify_clock: session.identity }); });
        section.append(verify); $('task-setup').append(section); continue;
      }
      const card = document.createElement('section');
      card.dataset.goalCard = session.identity;
      const started = (store.tasks ?? []).find(task => task.start_session === session.identity);
      if (!started) paragraph(card, 'Goal for this session');
      if (session.goal) {
        if (!started) {
          paragraph(card, session.goal.text);
          rawDetails(card, {source: session.goal.source, document_source: session.goal.document_source}, ['goal-source', session.identity]);
        }
        const accepted = (session.standing_modes ?? []).includes('Acting on a goal with no brief');
        if (started) {
          paragraph(card, 'See the task card for the goal and progress.');
        } else if (!accepted || !started) {
          paragraph(card, accepted ? 'Start was accepted. Continue with this same goal and machine.' : 'No brief is available.');
          paragraph(card, 'Acting on a goal with no brief');
          const start = document.createElement('button'); start.type = 'button'; start.textContent = 'Start session';
          start.dataset.startAcceptedGoal = session.identity;
          start.addEventListener('click', () => { start.disabled = true; worker.postMessage({goal_accept:{session:session.identity}}); });
          card.append(start);
        }
      } else {
        const words = document.createElement('textarea');
        words.dataset.goalText = '';
        words.setAttribute('aria-label', 'Your goal in your own words');
        const source = document.createElement('input');
        source.type = 'url';
        source.dataset.documentSource = '';
        source.setAttribute('aria-label', 'Optional document source (https URL)');
        [words.value, source.value] = setupDrafts.get(session.identity) ?? ['', ''];
        const enter = document.createElement('button');
        enter.type = 'button';
        enter.dataset.goalEnter = session.identity;
        enter.textContent = 'Set goal';
        enter.addEventListener('click', () => {
          const text = words.value;
          const document_source = source.value || null;
          words.value = source.value = '';
          enter.disabled = true;
          worker.postMessage({ goal: { session: session.identity, text, document_source } });
        });
        card.append(words, source, enter);
        for (const template of store.goal_templates ?? []) {
          const choice = document.createElement('section');
          paragraph(choice, 'Start from a template');
          paragraph(choice, template.text);
          const draft = goalTemplateDrafts.get(session.identity) ?? {options: {}, inputs: {}};
          goalTemplateDrafts.set(session.identity, draft);
          const values = templateControls(choice, template, draft);
          const choose = document.createElement('button');
          choose.type = 'button'; choose.textContent = template.name;
          choose.dataset.goalEnter = session.identity;
          choose.addEventListener('click', () => {
            choose.disabled = true; enter.disabled = true;
            worker.postMessage({goal: {session: session.identity, text: '', document_source: null, template: template.id, ...values()}});
          });
          choice.append(choose);
          card.append(choice);
        }
      }
      const pending = session.pending_requirements;
      if (pending) {
        const approval = document.createElement('section');
        approval.dataset.requirementsCard = session.identity;
        paragraph(approval, `Approve intended requirements for ${pending.proposal.machine}. These are proposed requirements, not measured results.`);
        if (pending.proposal.kind === 'declaration') installationPreview(approval, pending.proposal.declaration);
        else paragraph(approval, 'Tighten this machine from single-purpose to multi-tenant. It must remain bound alone and cannot hold spendable or private tenant material.');
        for (const [decision, text] of [['approve', 'Approve these requirements'], ['reject', 'Reject these requirements']]) {
          const button = document.createElement('button');
          button.type = 'button';
          button.dataset.requirementsDecision = decision;
          button.textContent = text;
          button.addEventListener('click', () => {
            for (const b of approval.querySelectorAll('button')) b.disabled = true;
            worker.postMessage({ requirements_answer: { session: session.identity, machine: pending.proposal.machine, candidate: pending.candidate, decision } });
          });
          approval.append(button);
        }
        card.append(approval);
      }
      const outcome = goalOutcomes.get(session.identity);
      if (outcome) {
        const status = document.createElement('p');
        status.dataset.goalOutcome = session.identity;
        status.textContent = outcome.done === true ? 'Goal loop ended: done.'
          : outcome.unresolved === true ? 'Goal loop ended: inference request unresolved.'
          : outcome.refused ? `Goal loop ended: ${outcome.refused}.`
          : outcome.finished === true ? `Goal loop ended: inference request finished with status ${outcome.status}.`
          : 'Goal loop ended.';
        card.append(status);
      }
      section.append(card);
      const spend = session.unaccounted_spend;
      if (spend?.count) paragraph(section, `${spend.count} unresolved inference requests: unaccounted spend against cap ${spend.cap}.`);
      for (const label of session.standing_modes ?? []) paragraph(section, `Standing mode: ${label}.`);
    }
    else if (machine.class !== null && access && store.fixture_admission) {
      const inputs = startInputs(section, machine.entry.machine);
      const button = document.createElement('button');
      button.type = 'button';
      button.dataset.bind = machine.entry.machine;
      button.textContent = `Start session ${machine.entry.machine}`;
      button.addEventListener('click', () => {
        button.disabled = true;
        worker.postMessage({ bind: { machine: machine.entry.machine, inference_approval: store.fixture_admission, ...inputs() } });
      });
      paragraph(section, `Inference endpoint: ${store.fixture_admission.configuration.endpoint}; model: ${store.fixture_admission.configuration.model}.`);
      startDisclosure(section);
      section.append(button);
    }
    (session || (store.sessions ?? []).some(history => history.bound_set.includes(machine.entry.machine)) || (store.fixture_admission && machine.class !== null && access) ? $('task-setup') : slot).append(section);
  }
  if (store.lifecycle_state === 'ended') {
    for (const control of [...slot.querySelectorAll('button, input, textarea'), ...$('task-setup').querySelectorAll('button, input, textarea')]) control.remove();
  }
};

// Terminal results arrive individually so a large history cannot suppress a new result.
const renderCommandResult = (result) => {
  if ($('store').dataset.state !== 'unlocked') return;
  let slot = $('task-results');
  if (!slot) {
    slot = document.createElement('section'); slot.id = 'tau-task-results';
    $('task-progress').append(slot);
  }
  const card = document.createElement('section');
  card.dataset.commandResult = String(result.call);
  if (result.optional_report) paragraph(card, 'Checks the AI wrote — not part of Delivered');
  paragraph(card, `Command ${commandResultWord(result)}.${result.historical ? ' This is a saved result; it does not allow any new action.' : ''}`);
  const details = rawDetails(card, {call: result.call, job: result.job, exit_status: result.exit_status}, ['command-result', result.call]);
  details.hidden = false;
  for (const field of ['stdout', 'stderr']) {
    paragraph(details, field === 'stdout' ? 'Output' : 'Error output');
    const output = document.createElement('pre'); output.dataset.commandOutput = ''; output.textContent = result[field] ?? ''; details.append(output);
  }
  const previous = slot.querySelector(`[data-command-result="${Number(result.call)}"]`);
  if (previous) previous.replaceWith(card); else slot.append(card);
};

const taskDispositionDrafts = new Map();
// Download state contains status only, never bytes, paths entered by the operator, or URLs.
const fileDownloads = new Map();
const machineFileLists = new Map();
const fileKey = (task, offer) => JSON.stringify([task, offer]);
const fileActionsEnabled = () => taskDetailsStore?.state === 'unlocked' && !ceremony &&
  !['suspended', 'reconciling', 'ended'].includes(taskDetailsStore.lifecycle_state);
const fileRow = (id, offer) => id.startsWith('machine:')
  ? document.querySelector(`[data-machine-files="${CSS.escape(id.slice(8))}"] [data-file-offer="${CSS.escape(offer)}"]`)
  : document.querySelector(`[data-task="${CSS.escape(id)}"] [data-file-offer="${CSS.escape(offer)}"]`);
const updateFileRow = (row, task, file) => {
  const state = fileDownloads.get(fileKey(task, file.id));
  const button = row.querySelector('[data-file-download]');
  button.disabled = !!state?.pending || !fileActionsEnabled();
  button.textContent = task.startsWith('machine:') ? (state?.pending ? 'Downloading…' : 'Download')
    : state?.pending ? `Downloading ${file.label}…` : state?.error ? `Retry download ${file.label}` : `Download ${file.label}`;
  row.querySelector('[data-file-error]')?.remove();
  if (state?.error) {
    const error = paragraph(row, state.error === 'too-large' ? `${file.label} is larger than 1 MiB; it wasn't downloaded.` : state.error);
    error.dataset.fileError = '';
  }
};
const interruptFileDownloads = () => {
  for (const state of machineFileLists.values()) {
    if (state.pending) { state.pending = false; state.error = 'The file list was interrupted. Try again.'; }
  }
  for (const [key, state] of fileDownloads) {
    if (!state.pending) continue;
    state.pending = false; state.error = 'The download was interrupted. Try again.';
    const [task, offer] = JSON.parse(key);
    const row = fileRow(task, offer);
    if (row) updateFileRow(row, task, state.file);
  }
};
const receiveFileDownload = (data, current) => {
  const key = fileKey(data.id, data.offer);
  const state = fileDownloads.get(key);
  try {
    if (worker !== current || data.generation !== current.generation || document.visibilityState === 'hidden' ||
        !fileActionsEnabled() || !state?.pending || state.request !== data.request) return;
    if (data.error) state.error = data.error;
    else if (data.bytes instanceof Uint8Array && typeof data.filename === 'string') {
      const blob = new Blob([data.bytes], {type: 'application/octet-stream'});
      const url = URL.createObjectURL(blob);
      try {
        const anchor = document.createElement('a');
        anchor.href = url; anchor.download = data.filename;
        document.body.append(anchor); anchor.click(); anchor.remove();
      } finally { setTimeout(() => URL.revokeObjectURL(url), 0); }
    } else state.error = 'The download outcome is unknown. Try again.';
    state.pending = false;
    const row = fileRow(data.id, data.offer);
    if (row) updateFileRow(row, data.id, state.file);
  } catch {
    state.error = 'The download could not be saved. Try again.';
    state.pending = false;
    const row = fileRow(data.id, data.offer);
    if (row) updateFileRow(row, data.id, state.file);
  } finally {
    if (data.bytes instanceof Uint8Array) data.bytes.fill(0);
    delete data.bytes;
  }
};

const receiveMachineFileList = (data, current) => {
  const state = machineFileLists.get(data.machine);
  if (worker !== current || data.generation !== current.generation || document.visibilityState === 'hidden' ||
      !fileActionsEnabled() || !state?.pending || state.request !== data.request) return;
  state.pending = false;
  if (data.error) state.error = data.error;
  else state.listing = data.listing;
  render(taskDetailsStore, true);
};

const renderMachineFiles = (row, machine, enabled, worker) => {
  const section = document.createElement('section'); section.dataset.machineFiles = machine;
  const state = machineFileLists.get(machine);
  const list = document.createElement('button'); list.type = 'button';
  list.textContent = 'Get a file from this machine'; list.disabled = !enabled || !!state?.pending;
  list.addEventListener('click', () => {
    if (!fileActionsEnabled() || machineFileLists.get(machine)?.pending) return;
    const request = crypto.randomUUID();
    machineFileLists.set(machine, {pending: true, request});
    render(taskDetailsStore, true);
    worker.postMessage({machine_file_list: {machine, request}});
  });
  section.append(list);
  if (state) {
    paragraph(section, 'Files from your machine can be secret. Keep them in a password manager and delete the downloaded copy.');
    if (state.pending) paragraph(section, 'Listing files…');
    if (state.error) paragraph(section, state.error);
    if (state.listing) {
      if (!state.listing.files.length) paragraph(section, state.listing.empty_message);
      for (const entry of state.listing.files) {
        const file = {id: entry.name, label: entry.name};
        const item = document.createElement('div'); item.dataset.fileOffer = entry.name;
        paragraph(item, `${entry.name} (${entry.size} bytes)`);
        if (entry.size > 1048576) paragraph(item, 'too large to download');
        else {
          const id = `machine:${machine}`;
          const button = document.createElement('button'); button.type = 'button'; button.dataset.fileDownload = entry.name;
          button.addEventListener('click', () => {
            const key = fileKey(id, entry.name);
            if (!fileActionsEnabled() || fileDownloads.get(key)?.pending) return;
            const request = crypto.randomUUID();
            fileDownloads.set(key, {pending: true, request, file});
            updateFileRow(item, id, file);
            worker.postMessage({machine_file_download: {machine, name: entry.name, request}});
          });
          item.append(button); updateFileRow(item, id, file);
          if (!enabled) button.disabled = true;
        }
        section.append(item);
      }
      if (state.listing.truncated) paragraph(section, 'Only the first 32 files are shown.');
    }
  }
  row.append(section);
};

const deliveredHostKind = (hostname) => {
  const host = hostname.toLowerCase().replace(/\.$/, '');
  if (host.endsWith('.onion')) return 'onion';
  const ipv4Kind = (parts) => {
    const [a, b, c] = parts;
    if (a === 10 || a === 172 && b >= 16 && b <= 31 || a === 192 && b === 168 || a === 100 && b >= 64 && b <= 127) return 'private';
    if (a === 0 || a === 127 || a >= 224 || a === 169 && b === 254 ||
        a === 192 && b === 0 && (c === 0 || c === 2) || a === 192 && b === 88 && c === 99 ||
        a === 198 && (b === 18 || b === 19 || b === 51 && c === 100) || a === 203 && b === 0 && c === 113) return 'other';
    return 'public';
  };
  if (host.startsWith('[') && host.endsWith(']')) {
    const ip = host.slice(1, -1);
    // URL.hostname has already normalized IPv6; expand it to classify the address bits.
    const [left, right] = ip.split('::');
    const before = left ? left.split(':') : [];
    const after = right ? right.split(':') : [];
    const words = [...before, ...Array(right === undefined ? 0 : 8 - before.length - after.length).fill('0'), ...after].map(word => parseInt(word, 16));
    if (words.length !== 8 || words.some(word => !Number.isInteger(word))) return 'other';
    if (words.slice(0, 5).every(word => word === 0) && words[5] === 0xffff) return ipv4Kind([words[6] >> 8, words[6] & 255, words[7] >> 8, words[7] & 255]);
    if ((words[0] & 0xfe00) === 0xfc00) return 'private';
    if ((words[0] & 0xe000) !== 0x2000 || words[0] === 0x2001 && (words[1] < 0x200 || words[1] === 0xdb8) ||
        words[0] === 0x2002 || words[0] === 0x3fff && words[1] < 0x1000) return 'other';
    return 'public';
  }
  if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) return ipv4Kind(host.split('.').map(Number));
  if (!host || !host.split('.').every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) return 'other';
  if (!host.includes('.') || ['.ts.net', '.local', '.internal', '.lan', '.home', '.home.arpa', '.localhost'].some(suffix => host.endsWith(suffix))) return 'private';
  if (['.invalid', '.test', '.example', '.arpa'].some(suffix => host.endsWith(suffix))) return 'other';
  return 'public';
};
const taskDeliveredUrls = (task) => {
  if (task.summary) return task.delivered_urls ?? [];
  const done = task.completed?.findLast(([, tool, outcome]) => tool.name === 'done' && outcome.content?.verification_required === true);
  return (done?.[1].arguments.urls ?? []).map(entry => ({...entry, notVisited: done[2].content.unvisited_urls?.find(skipped => skipped.url === entry.url)?.label}));
};
const renderDeliveredUrls = (parent, entries) => {
  if (!Array.isArray(entries) || entries.length > 8) return;
  const parsed = [];
  for (const entry of entries) {
    if (!entry || typeof entry.url !== 'string' || new TextEncoder().encode(entry.url).length > 2048 ||
        !/^https?:\/\//.test(entry.url) || /[\s\p{Cc}\\]/u.test(entry.url) ||
        entry.url.slice(entry.url.indexOf('://') + 3).split(/[/?#]/, 1)[0].includes('@') ||
        entry.label !== undefined && (typeof entry.label !== 'string' || !entry.label.trim() || !/^[\x20-\x7e]{1,48}$/.test(entry.label))) return;
    try {
      const url = new URL(entry.url);
      if (!url.hostname || url.username || url.password) return;
      parsed.push({url, text: entry.url, hostname: url.hostname, label: entry.label, notVisited: entry.notVisited});
    } catch { return; }
  }
  if (!parsed.length) return;
  const section = document.createElement('section');
  paragraph(section, 'Addresses to open the service:');
  for (const {url, text, hostname, label, notVisited} of parsed) {
    const row = document.createElement('p');
    if (label || notVisited) {
      const caption = document.createElement('span'); caption.textContent = notVisited ? `${notVisited}; not visited from the machine` : label;
      row.append(caption, document.createElement('br'));
    }
    const host = document.createElement('strong'); host.textContent = hostname;
    const anchor = document.createElement('a');
    anchor.dataset.deliveredUrl = ''; anchor.dataset.kind = deliveredHostKind(url.hostname);
    anchor.href = url.href; anchor.target = '_blank'; anchor.rel = 'noopener noreferrer';
    anchor.textContent = text;
    row.append(host, document.createElement('br'), anchor); section.append(row);
  }
  parent.append(section);
};

const receiveTaskDetails = (data, current) => {
  if (worker !== current || document.visibilityState === 'hidden' ||
      data.generation !== undefined && data.generation !== current.generation) return;
  const entry = [...taskDetails].find(([, state]) => state.pending && state.request === data.request);
  if (!entry) return;
  const [id, state] = entry;
  state.pending = false;
  if (!data.error && data.id === id && data.task?.id === id && !data.task.summary) state.task = data.task;
  else state.error = true;
  render(taskDetailsStore, true);
};

const receiveDeliveryDetails = (data, current) => {
  if (worker !== current || document.visibilityState === 'hidden' ||
      data.generation !== undefined && data.generation !== current.generation) return;
  for (const [kind, states] of Object.entries(deliveryDetails)) {
    const entry = [...states].find(([, state]) => state.pending && state.request === data.request);
    if (!entry) continue;
    const [machine, state] = entry;
    state.pending = false;
    if (!data.error && data.machine === machine && data.kind === kind &&
        (kind === 'commands' ? Array.isArray(data.value) && Number.isSafeInteger(data.reports_revision) : data.value?.machine === machine && !data.value.summary)) {
      state.value = data.value;
      state.fetchedRevision = data.reports_revision;
    } else state.error = true;
    render(taskDetailsStore, true);
    return;
  }
};

const deliveryDetailsButton = (card, machine, kind, label, store) => {
  const worker = snapshotWorker();
  const states = deliveryDetails[kind];
  const state = states.get(machine);
  const button = document.createElement('button');
  button.type = 'button'; button.dataset.deliveryDetails = kind;
  button.textContent = state ? `Close ${label}` : `Show ${label}`;
  button.disabled = ['suspended', 'reconciling'].includes(store.lifecycle_state);
  button.addEventListener('click', () => {
    if (states.has(machine)) states.delete(machine);
    else {
      const request = crypto.randomUUID();
      const revision = (store.delivery ?? []).find(entry => entry.machine === machine)?.reports_revision;
      states.set(machine, {request, pending: true, revision});
      worker.postMessage({delivery_details: {machine, request, kind}});
    }
    render(store, true);
  });
  card.append(button);
  if (state?.pending) paragraph(card, `Opening ${label}…`);
  if (state?.error) paragraph(card, `These ${label} could not be shown.`);
  return state?.value;
};

const recentTaskSummaries = 3;
const taskHistoryPageSize = 20;
let taskHistoryPage = null;
let taskHistoryGeneration;
function* visibleTasks(store, slot) {
  const tasks = store.tasks ?? [];
  // Newest first by creation (`creation_rank`, the store's task creation order); task IDs are random,
  // and a session can be opened long before its task starts. A task without a rank sorts oldest.
  const summaries = tasks.filter(task => task.summary)
    .sort((a, b) => (b.creation_rank ?? -1) - (a.creation_rank ?? -1) || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  const recent = new Set(summaries.slice(0, recentTaskSummaries).map(task => task.id));
  // Keep the existing relative order of every full card and the recent summaries.
  yield* tasks.filter(task => !task.summary || recent.has(task.id));
  const earlier = summaries.slice(recentTaskSummaries);
  if (!earlier.length) { taskHistoryPage = null; return; }
  const pages = Math.ceil(earlier.length / taskHistoryPageSize);
  if (taskHistoryPage !== null) taskHistoryPage = Math.min(taskHistoryPage, pages - 1);
  const line = paragraph(slot, `${earlier.length} earlier tasks${taskHistoryPage === null ? '' : ` — page ${taskHistoryPage + 1} of ${pages}`}. `);
  line.dataset.taskHistoryCount = String(earlier.length);
  const control = (action, label, page, disabled = false) => {
    const button = document.createElement('button');
    button.type = 'button'; button.dataset.taskHistory = action;
    button.textContent = label; button.disabled = disabled;
    button.addEventListener('click', () => {
      taskHistoryPage = page;
      render(store, true);
      const next = $('tasks').querySelector(`[data-task-history="${action}"]`);
      (next && !next.disabled ? next : $('tasks').querySelector('[data-task-history]'))?.focus({preventScroll: true});
    });
    line.append(button);
  };
  control('toggle', taskHistoryPage === null ? 'Show earlier tasks' : 'Hide earlier tasks', taskHistoryPage === null ? 0 : null);
  if (taskHistoryPage !== null) {
    control('newer', 'Newer tasks', taskHistoryPage - 1, taskHistoryPage === 0);
    control('older', 'Older tasks', taskHistoryPage + 1, taskHistoryPage === pages - 1);
  }
  const start = (taskHistoryPage ?? 0) * taskHistoryPageSize;
  // An opened card stays rendered when paging away or folding the history.
  for (let index = 0; index < earlier.length; index++) {
    const task = earlier[index];
    if (taskDetails.has(task.id) || taskHistoryPage !== null && index >= start && index < start + taskHistoryPageSize) yield task;
  }
}
// These names follow the playbook's 12 steps of version 1.
const controlCenterLabels = {
  steps: {
    1: 'look at the machine',
    2: 'prepare the settings folder',
    3: 'apply the base system',
    4: 'create the keys',
    5: 'install the AI agent and its dashboard',
    6: 'let the agent install more later',
    7: 'install T3 Code',
    8: 'link T3 Code to your T3 account',
    9: 'set up private access (WireGuard)',
    10: 'set up Tor',
    11: 'write your two files',
    12: 'save everything and run the final check',
  },
  blocks: {Do: '', Wait: 'wait for the build', Check: 'check', Later: 'link later', R2: 'fix a problem (recovery)'},
};
const controlCenterOrigin = (task, id) => task.template === 'control-center@1' ? task.block_origins?.[id] : undefined;
const playbookCommand = origin => {
  if (!origin) return;
  if (origin.step === 0 && origin.block === 'R2') return controlCenterLabels.blocks.R2;
  const name = controlCenterLabels.steps[origin.step];
  const suffix = controlCenterLabels.blocks[origin.block];
  if (name && suffix !== undefined) return `step ${origin.step}, ${suffix || name}`;
};
const renderTasks = (store) => {
  if (store.state !== 'unlocked' || store.lifecycle_generation !== taskHistoryGeneration) {
    taskHistoryPage = null;
    taskHistoryGeneration = store.lifecycle_generation;
  }
  if (store.state !== 'unlocked' || ['suspended', 'reconciling', 'ended'].includes(store.lifecycle_state)) fileDownloads.clear();
  const worker = snapshotWorker();
  let slot = $('tasks');
  if (!slot) {
    slot = document.createElement('section');
    slot.id = 'tau-tasks';
    $('task-progress').append(slot);
  }
  if (store.state === 'unlocked') {
    for (const card of slot.querySelectorAll('[data-task]')) {
      const requests = card.querySelector('[aria-label="Task request limit"]');
      const steps = card.querySelector('[aria-label="Task step limit"]');
      if (requests && steps) taskLimitDrafts.set(card.dataset.task, [requests.value, steps.value]);
    }
    if (Array.isArray(store.tasks)) {
      const active = new Set(store.tasks.filter(task => !['complete', 'abandoned'].includes(task.status)).map(task => task.id));
      for (const identity of taskLimitDrafts.keys()) if (!active.has(identity)) taskLimitDrafts.delete(identity);
    }
  }
  slot.replaceChildren();
  slot.hidden = store.state !== 'unlocked' || store.seed_backup_stage !== 'inactive';
  if (slot.hidden) return;
  for (const entry of visibleTasks(store, slot)) {
    const opened = entry.summary ? taskDetails.get(entry.id) : undefined;
    const task = opened?.task ?? entry;
    const missingRecord = task.status === 'paused' && task.disposition_offer?.read === 'missing' &&
      task.proposal?.tool.name === 'exec' && task.proposal.check == null && task.proposal.report == null &&
      !task.proposal.call_id.startsWith('$');
    const card = document.createElement('section');
    card.dataset.task = task.id;
    card.dataset.cycleTimings = JSON.stringify(task.cycle_timings ?? []);
    card.dataset.replyTools = JSON.stringify(task.reply_tools ?? []);
    const session = (store.sessions ?? []).find(s => s.identity === task.start_session && s.session_state !== 'ended' && s.bound_set.length === 1 && s.bound_set[0] === task.machine);
    paragraph(card, `Setting up ${task.machine}: ${taskStatus(task.status, task)}.`);
    if (entry.summary) {
      const open = document.createElement('button');
      open.type = 'button'; open.dataset.openTask = entry.id;
      open.textContent = opened ? 'Close task' : 'Open task';
      open.disabled = ['suspended', 'reconciling'].includes(store.lifecycle_state);
      open.addEventListener('click', () => {
        if (taskDetails.has(entry.id)) {
          taskDetails.delete(entry.id);
          render(store, true);
        } else {
          const request = crypto.randomUUID();
          taskDetails.set(entry.id, {request, pending: true, revision: entry.revision});
          render(store, true);
          worker.postMessage({task_details: {id: entry.id, request}});
        }
      });
      card.append(open);
    }
    if (task.summary) {
      card.dataset.taskSummary = 'true';
      paragraph(card, shortLine(task.goal, 120));
      if (task.verdict) paragraph(card, task.verdict);
      if (!session && !['complete', 'abandoned'].includes(task.status)) paragraph(card, 'This task’s session has ended. Its history stays here, but it cannot continue.');
      if (opened?.pending) paragraph(card, 'Opening task…');
      if (opened?.error) paragraph(card, 'This task could not be shown.');
      slot.append(card);
      continue;
    }
    if (task.goal.length <= 120) paragraph(card, task.goal);
    else {
      const firstSentence = task.goal.match(/^.*?[.!?](?=\s|$)/s)?.[0] ?? task.goal;
      paragraph(card, shortLine(firstSentence, 120));
      rawDetails(card, {goal: task.goal}, ['task', task.id, 'goal']);
    }
    if (!['complete', 'abandoned'].includes(task.status)) {
      const latestCommand = task.completed.filter(([, tool]) => tool.name === 'exec').at(-1);
      const origin = controlCenterOrigin(task, task.proposal?.call_id) ?? controlCenterOrigin(task, latestCommand?.[0]);
      if (origin?.step === 0 && origin.block === 'R2') paragraph(card, 'Now: fixing a problem (recovery)');
      else if (origin && controlCenterLabels.steps[origin.step]) paragraph(card, `Now: step ${origin.step} of 12, ${controlCenterLabels.steps[origin.step]}`);
    }
    if (task.inference_retry) {
      paragraph(card, 'Waiting before trying the AI connection again.');
      rawDetails(card, {retry: task.inference_retry}, ['task', task.id, 'retry']);
    }
    paragraph(card, `${task.requests} of ${task.limits.requests} AI replies used; ${task.steps} of ${task.limits.steps} steps used.`);
    for (const [id, tool, outcome] of task.completed.filter(([id]) => !id.startsWith('$report:'))) {
      if (id.startsWith('$verify-batch') && typeof outcome?.content?.refused === 'string') {
        paragraph(card, `The machine setup check could not start: ${outcome.content.refused}`);
        rawDetails(card, {outcome}, ['task', task.id, 'completed', id]);
        continue;
      }
      if (id.startsWith('$verify:') || id.startsWith('$verify-batch') || tool.name === 'offer_file' && outcome.content?.status === 'offered') continue;
      if (tool.name === 'ask_operator') {
        const answered = typeof outcome.answer === 'string';
        paragraph(card, answered ? `Answered: ${outcome.answer}.` : outcome.content?.refused ?? 'The question could not be asked.');
        rawDetails(card, {tool: answered ? tool : {name: tool.name}, outcome}, ['task', task.id, 'completed', id]);
        continue;
      }
      if (tool.name === 'request_ai_key') {
        const created = outcome?.content?.status === 'created';
        const declined = outcome?.content?.status === 'declined';
        const application = shortLine(tool.arguments.application, 64);
        const line = paragraph(card, created ? `Created an AI key for ${application} on this machine (limit ${outcome.content.limit_usd} USD, expires in 30 days)` : declined ? `Didn't create an AI key for ${application}.` : `Couldn't create an AI key: ${shortLine(outcome?.content?.reason ?? 'the outcome is unavailable', 160)}.`);
        line.dataset[created ? 'aiKeyCreated' : declined ? 'aiKeyDeclined' : 'aiKeyFailed'] = '';
      } else paragraph(card, id.startsWith('$before:') ? 'Read the listening ports before setup.' : tool.name === 'exec' ? `Ran: ${(!id.startsWith('$rerun:') && playbookCommand(controlCenterOrigin(task, id))) || commandSummary(tool.arguments.command)} (${commandResultWord(outcome)})` : tool.name === 'propose_declaration' ? 'The AI proposed requirements.' : tool.name === 'done' ? 'The AI handed the work over for checks.' : 'Completed a step.');
      const machineKey = tool.name === 'request_ai_key' ? (store.poc_targets ?? []).find(target => target.machine === task.machine)?.application_inference_keys?.find(key => key.path === outcome?.content?.path) : undefined;
      rawDetails(card, {tool: tool.name === 'done' ? {name: tool.name, arguments: {machine: tool.arguments.machine}} : tool, outcome, ...(machineKey ? {application_inference_key: machineKey} : {})}, ['task', task.id, 'completed', id]);
    }
    for (const file of task.file_offers ?? []) {
      const row = document.createElement('div'); row.dataset.fileOffer = file.id;
      const button = document.createElement('button'); button.type = 'button'; button.dataset.fileDownload = file.id;
      button.addEventListener('click', () => {
        const key = fileKey(task.id, file.id);
        if (!fileActionsEnabled() || fileDownloads.get(key)?.pending) return;
        const request = crypto.randomUUID();
        fileDownloads.set(key, {pending: true, request, file});
        updateFileRow(row, task.id, file);
        worker.postMessage({file_download: {id: task.id, offer: file.id, request}});
      });
      row.append(button); paragraph(row, file.why);
      rawDetails(row, {path: file.path, machine: file.machine}, ['task', task.id, 'file', file.id]);
      updateFileRow(row, task.id, file);
      if (['suspended', 'reconciling', 'ended'].includes(store.lifecycle_state)) button.disabled = true;
      card.append(row);
    }
    if (task.proposal && task.proposal.report == null) {
      if (awaitingOperator(task)) {
        const question = task.operator_question;
        const url = question?.link == null ? undefined : operatorLink(question.link);
        if (question && (question.link == null || url && url.href === question.href && url.hostname.toLowerCase() === question.domain)) {
          const row = document.createElement('section'); row.dataset.operatorQuestion = '';
          paragraph(row, question.purpose);
          if (url) {
            const anchor = document.createElement('a'); anchor.dataset.operatorLink = '';
            anchor.href = url.href; anchor.target = '_blank'; anchor.rel = 'noopener noreferrer';
            const domain = document.createElement('strong'); domain.textContent = url.hostname.toLowerCase();
            anchor.append(domain); row.append(anchor);
            const fullLink = document.createElement('code'); fullLink.textContent = url.href;
            row.append(document.createElement('br'), fullLink);
            const userCode = url.searchParams.get('user_code');
            if (userCode && /^[A-Za-z0-9-]{1,32}$/.test(userCode)) {
              const codeLine = paragraph(row, 'Code to check there: ');
              const code = document.createElement('code'); code.textContent = userCode; codeLine.append(code);
              const steps = document.createElement('ol');
              for (const text of [
                'Tap the link. Sign in there, or create an account.',
                'Check that the page shows this code, then approve.',
                question.choices?.length ? `Come back here and press ${question.choices[0]}.` : 'Come back here and choose your answer.',
              ]) {
                const step = document.createElement('li'); step.textContent = text; steps.append(step);
              }
              row.append(steps);
            }
          }
          const unavailable = !session || ['suspended', 'reconciling', 'ended'].includes(store.lifecycle_state);
          let answered = false;
          for (const choice of question.choices ?? ['Done', "Can't"]) {
            const button = document.createElement('button');
            button.type = 'button'; button.textContent = choice;
            button.dataset.operatorChoice = ''; button.dataset.choice = choice; button.disabled = unavailable;
            button.addEventListener('click', () => {
              if (answered || button.disabled) return;
              answered = true;
              for (const control of row.querySelectorAll('button')) control.disabled = true;
              worker.postMessage({task: {action: 'operator-answer', id: task.id, session: session.identity, call_id: task.proposal.call_id, revision: task.revision, answer: choice}});
            });
            row.append(button);
          }
          card.append(row);
        }
      } else if (awaitingAiKey(task)) {
        const requestCard = document.createElement('section');
        requestCard.dataset.aiKeyRequest = '';
        paragraph(requestCard, `Create an AI key for ${shortLine(task.proposal.tool.arguments.application, 64)} on this machine (limit ${task.ai_key_limit_usd} USD, expires in 30 days)?`);
        paragraph(requestCard, "Paid from your inference balance. It can read the account's usage history. It ends when the machine is destroyed, it expires, or it is revoked.");
        paragraph(requestCard, "This key is for the operator's application and outlives this session. Lock, Stop task and End session do not revoke it.");
        const needsClass = (store.poc_targets ?? []).find(target => target.machine === task.machine)?.ai_key_needs_class_answer !== false;
        const unavailable = !session || ['suspended', 'reconciling', 'ended'].includes(store.lifecycle_state);
        let classAnswer;
        const sendDecision = (decision, answer) => {
          for (const control of requestCard.querySelectorAll('button')) control.disabled = true;
          worker.postMessage({task: {action: `ai-key-${decision}`, id: task.id, session: session.identity, call_id: task.proposal.call_id, revision: task.revision, ...(answer ? {machine_class_answer: answer} : {})}});
        };
        if (needsClass) {
          const question = paragraph(requestCard, 'Does this machine serve only you?');
          question.dataset.machineClass = '';
          for (const [answer, text] of [['only-me', 'Only me'], ['others-too', 'Others too'], ['not-sure', 'Not sure']]) {
            const button = document.createElement('button');
            button.type = 'button'; button.textContent = text; button.dataset.machineClassAnswer = answer;
            button.setAttribute('aria-pressed', 'false');
            button.disabled = unavailable;
            button.addEventListener('click', () => {
              if (answer !== 'only-me') { sendDecision('class', answer); return; }
              classAnswer = answer;
              button.setAttribute('aria-pressed', 'true');
              requestCard.querySelector('[data-ai-key-decision="create"]').disabled = unavailable;
            });
            requestCard.append(button);
          }
        }
        for (const [decision, text] of [['create', 'Create key'], ['decline', "Don't"]]) {
          const button = document.createElement('button');
          button.type = 'button'; button.textContent = text; button.dataset.aiKeyDecision = decision;
          button.disabled = unavailable || (decision === 'create' && needsClass);
          button.addEventListener('click', () => sendDecision(decision, decision === 'create' ? classAnswer : undefined));
          requestCard.append(button);
        }
        card.append(requestCard);
      } else if (task.proposal.call_id.startsWith('$rerun:')) {
        const label = task.pending ? task.status === 'paused' ? 'Re-issued command' : 'Running again' : 'Ready to send once more';
        paragraph(card, `${label}: ${commandSummary(task.proposal.tool.arguments.command)}`);
      } else if (!missingRecord) paragraph(card, task.proposal.call_id.startsWith('$before:') ? 'Next: read the listening ports before setup.' : task.proposal.call_id.startsWith('$verify:') || task.proposal.call_id.startsWith('$verify-batch') ? 'Next: check the machine setup.' : task.proposal.tool.name === 'exec' ? `Next: ${playbookCommand(controlCenterOrigin(task, task.proposal.call_id)) || commandSummary(task.proposal.tool.arguments.command)}` : task.proposal.tool.name === 'propose_declaration' ? 'Next: a requirements proposal from the AI.' : task.proposal.tool.name === 'done' ? 'Next: the handover from the AI.' : task.proposal.tool.name === 'request_ai_key' ? `Creating an AI key for ${shortLine(task.proposal.tool.arguments.application, 64)} and saving it on the machine.` : 'Next: a step.');
      rawDetails(card, task.proposal.tool, ['task', task.id, 'proposal', task.proposal.call_id]);
    }
    if (task.pending && task.proposal?.report == null) {
      if (!missingRecord && !(task.proposal?.call_id.startsWith('$rerun:') && task.disposition_offer)) paragraph(card, task.proposal?.call_id.startsWith('$rerun:') ? 'Waiting for the re-issued command. Resume checks its result without running it twice.' : 'Waiting for the earlier command. Resume checks its result without running it twice.');
      rawDetails(card, task.pending, ['task', task.id, 'pending']);
    }
    if (task.pause_reason) {
      paragraph(card, plainPause(task.pause_reason));
      rawDetails(card, {reason: task.pause_reason}, ['task', task.id, 'pause']);
    }
    for (const check of task.verification) {
      const line = paragraph(card, checkSummary(check, task.completed.find(([, , outcome]) => outcome?.content?.job === check.job)?.[2]));
      line.dataset.harnessRead = check.command;
      rawDetails(card, check, ['task', task.id, 'check', check.command, check.job]);
    }
    if (task.verdict) {
      paragraph(card, task.verdict);
      renderDeliveredUrls(card, taskDeliveredUrls(task));
    }
    for (const finding of task.findings ?? []) {
      const service = finding.service?.name;
      paragraph(card, ['sign_in', 'control_center', 'control_center_files', 'unmet_command'].includes(finding.field) ? finding.detail : service ? `${service} does not match the approved setup.` : finding.field === 'inbound' ? 'The listening ports do not match the approved setup.' : `A setup check found a difference or could not finish. ${shortLine(finding.detail, 160) || 'No further reason is available.'}`);
      rawDetails(card, finding);
    }
    for (const note of task.notes ?? []) paragraph(card, note.text === 'enabled, restart not demonstrated'
      ? `${note.service.name} is set to start at boot (a reboot was not tested).`
      : note.text === 'stopped since a restart, as approved' ? `${note.service.name} stopped after a restart, as approved.` : `${note.service.name}: ${note.text}`);
    let reports;
    if (task.reports?.length) {
      reports = document.createElement('section');
      paragraph(reports, 'Checks the AI wrote — not part of Delivered');
      if (task.pending && task.proposal?.report != null) {
        paragraph(reports, 'Waiting for the earlier check. Resume checks its result without running it twice.');
        rawDetails(reports, task.pending, ['task', task.id, 'pending-report']);
      }
      for (const report of task.reports) showCheckReport(reports, report);
      card.append(reports);
    }
    for (const [id, , result] of task.completed) {
      if (result.content?.outcome === 'unknown' && result.content?.disposition) {
        const outcome = result.content;
        const parent = id.startsWith('$report:') && reports ? reports : card;
        paragraph(parent, `The earlier command’s result is unknown. You chose to carry on as if it ${outcome.continuation === 'as_if_done' ? 'ran' : 'did not run'}.`);
        if (outcome.machine_held) paragraph(parent, 'Other commands still have unknown results. The machine stays paused for them.');
        paragraph(parent, 'The earlier command may arrive or run late and overlap later commands. The page will never show that late result.');
        rawDetails(parent, outcome, ['task', task.id, 'unknown', id]);
      }
    }
    if (task.status === 'complete' && task.verdict && session && store.lifecycle_state !== 'ended') {
      paragraph(card, "Finished? End session stops Farseed's AI and cancels its session key. Your machine keeps running, and billing, until you delete it.");
      for (const [, tool, outcome] of task.completed) {
        if (tool.name === 'request_ai_key' && outcome?.content?.status === 'created') paragraph(card, `The AI key made for ${shortLine(tool.arguments.application, 64)} keeps working, up to its limit, until it expires or is revoked.`);
      }
      const identity = session.identity;
      const end = document.createElement('button');
      end.type = 'button'; end.textContent = 'End session'; end.dataset.endSession = identity;
      end.addEventListener('click', () => { end.disabled = true; worker.postMessage({task: {action: 'end-session', session: identity}}); });
      card.append(end);
    }
    if (['complete', 'abandoned'].includes(task.status)) { slot.append(card); continue; }
    paragraph(card, 'If you close this page, work that can continue picks up after you unlock and resupply any requested key. The task keeps the same session, machine, approvals and limits. Use Resume if it stays paused.');
    const action = (text, request) => {
      const button = document.createElement('button');
      button.type = 'button'; button.textContent = text;
      button.addEventListener('click', () => { button.disabled = true; worker.postMessage({ task: { id: task.id, ...request } }); });
      card.append(button);
    };
    if (session && store.lifecycle_state !== 'ended' && !awaitingAiKey(task) && !awaitingOperator(task)) {
      action('Resume', { action: 'resume', session: session.identity });
    } else if (entry.summary || (store.sessions ?? []).some(s => s.identity === task.start_session && s.session_state === 'ended')) paragraph(card, 'This task’s session has ended. Its history stays here, but it cannot continue.');
    else if (!session) paragraph(card, 'Unlock to restore this task’s session.');
    if (session && task.verifying && task.status === 'paused' && !task.pending) {
      action('Prepare complete re-check', { action: 'retry-checks', session: session.identity });
    }
    if (session && store.lifecycle_state !== 'ended') {
      for (const command of task.unmet_commands ?? []) {
        if (!(task.acknowledgeable_commands ?? []).includes(command.created)) continue;
        const decision = document.createElement('section');
        paragraph(decision, `Command awaiting confirmation on ${command.machine}: ${commandSummary(command.command)}`);
        paragraph(decision, 'If you know this command already ran, record that here. Nothing is sent by this choice. Its result stays unknown; verification still decides Delivered.');
        const choose = document.createElement('button'); choose.type = 'button'; choose.textContent = 'It already ran';
        choose.dataset.commandObligation = String(command.created);
        choose.addEventListener('click', () => {
          choose.disabled = true;
          worker.postMessage({task: {action: 'command-already-ran', id: task.id, session: session.identity, revision: task.revision, obligation: command.created}});
        });
        decision.append(choose);
        card.append(decision);
      }
    }
    if (session && store.lifecycle_state !== 'ended' && task.disposition_offer) {
      const offer = task.disposition_offer;
      if (missingRecord) {
        taskDispositionDrafts.delete(task.id);
        const decision = document.createElement('section');
        decision.dataset.missingRecord = '';
        paragraph(decision, 'The machine has no record of this command, so it may never have arrived.');
        if (task.rerun_refusal) paragraph(decision, task.rerun_refusal);
        else {
          paragraph(decision, 'Running it again is the usual choice. If it did arrive, running it again repeats its changes. This is your decision.');
          paragraph(decision, 'Run it again: Farseed will send this command to the machine once more.');
        }
        paragraph(decision, 'It already ran: nothing is sent, and the AI carries on.');
        paragraph(decision, 'The earlier result stays unknown. The earlier command may arrive or run late, overlap later commands, and its late result will not appear here.');
        if (offer.remaining.length) paragraph(decision, 'Other commands still have unknown results. This choice does not clear them; the machine stays paused for them.');
        if (offer.standing) paragraph(decision, 'This replaces your earlier choice for this command. Other commands covered by that choice keep their unknown results.');
        let chosen = false;
        for (const [continuation, label] of [['as_if_not_done', 'Run it again'], ['as_if_done', 'It already ran']]) {
          if (continuation === 'as_if_not_done' && task.rerun_refusal) continue;
          const choose = document.createElement('button'); choose.type = 'button'; choose.textContent = label;
          choose.dataset.pendingAssumption = continuation;
          if (continuation === 'as_if_not_done') choose.dataset.pendingRetry = '';
          choose.addEventListener('click', () => {
            if (chosen || choose.disabled) return;
            chosen = true;
            for (const control of decision.querySelectorAll('button')) control.disabled = true;
            worker.postMessage({task: {action: 'dispose-pending', id: task.id, session: task.start_session, confirmation: structuredClone(offer), continuation}});
          });
          decision.append(choose);
        }
        card.append(decision);
      } else {
        const reissued = task.proposal?.call_id.startsWith('$rerun:');
        const unsent = reissued && task.rerun_unsent === true;
        if (unsent) {
          paragraph(card, 'Farseed has not sent this command yet. Resume sends it to the machine once.');
          paragraph(card, "If Farseed can't send it, choose Let the AI decide: this command still needs to run, and the AI will be told so.");
        } else if (reissued) {
          paragraph(card, 'Farseed sent this command once more and the machine has no record of it either. Farseed will not send it again by itself.');
          paragraph(card, 'It already ran clears the obligation and sends nothing. Let the AI decide keeps the obligation: this command still needs to run.');
        }
        const labels = unsent
          ? {as_if_not_done: 'Let the AI decide'}
          : reissued
          ? {as_if_done: 'It already ran', as_if_not_done: 'Let the AI decide'}
          : {as_if_not_done: "Carry on as if it didn't run", as_if_done: 'Carry on as if it ran'};
        const confirmation = document.createElement('section');
        confirmation.dataset.pendingConfirmation = task.id;
        const showConfirmation = () => {
          confirmation.replaceChildren();
          const draft = taskDispositionDrafts.get(task.id);
          if (!draft) return;
          const snapshot = draft.confirmation;
          paragraph(confirmation, `The earlier command on ${snapshot.machine} still has no confirmed result.`);
          rawDetails(confirmation, snapshot, ['task', task.id, 'confirmation']);
          paragraph(confirmation, `The result stays unknown. Your choice: ${labels[draft.continuation]}.`);
          paragraph(confirmation, reissued
            ? draft.continuation === 'as_if_done'
              ? 'The AI will be told you recorded this command as already run and must not run it again to meet this obligation.'
              : 'This command still needs to run. The AI will be told that; Farseed will not send it again by itself.'
            : 'The AI may then run the same command again.');
          paragraph(confirmation, 'If the earlier command arrives or runs late, it can overlap later commands and the page will never show it.');
          if (snapshot.read === 'incomplete') paragraph(confirmation, 'The incomplete command may still be running.');
          if (snapshot.remaining.length) paragraph(confirmation, 'Other commands still have unknown results. This choice does not clear them; the machine stays paused for them.');
          if (snapshot.standing) {
            paragraph(confirmation, 'This replaces your earlier choice for this command. Other commands covered by that choice keep their unknown results.');
          }
          const confirm = document.createElement('button'); confirm.type = 'button'; confirm.textContent = 'Confirm unknown outcome';
          confirm.addEventListener('click', () => {
            confirm.disabled = true;
            taskDispositionDrafts.delete(task.id);
            worker.postMessage({task: {action: 'dispose-pending', id: task.id, session: task.start_session, ...draft}});
          });
          const cancel = document.createElement('button'); cancel.type = 'button'; cancel.textContent = 'Cancel assumption';
          cancel.addEventListener('click', () => { taskDispositionDrafts.delete(task.id); showConfirmation(); });
          confirmation.append(confirm, cancel);
        };
        for (const [continuation, label] of Object.entries(labels)) {
          const choose = document.createElement('button'); choose.type = 'button'; choose.textContent = label;
          choose.dataset.pendingAssumption = continuation;
          choose.addEventListener('click', () => {
            taskDispositionDrafts.set(task.id, {confirmation: structuredClone(offer), continuation});
            showConfirmation();
          });
          card.append(choose);
        }
        card.append(confirmation); showConfirmation();
      }
    } else if (task.disposition_refusal) {
      paragraph(card, `Saved reason: ${shortLine(task.disposition_refusal, 160)}`);
      paragraph(card, 'The page cannot accept a choice about the unknown result yet. Review the saved reason above before continuing.');
      rawDetails(card, {reason: task.disposition_refusal}, ['task', task.id, 'choice-refused']);
    }
    paragraph(card, 'Stop task ends this task here. What was already done on the machine stays, and the machine keeps running and billing until you delete it.');
    action('Stop task', { action: 'abandon' });
    const requests = document.createElement('input'); requests.type = 'number'; requests.min = task.limits.requests; requests.max = 1000; requests.value = taskLimitDrafts.get(task.id)?.[0] ?? task.limits.requests; requests.setAttribute('aria-label', 'Task request limit');
    const steps = document.createElement('input'); steps.type = 'number'; steps.min = task.limits.steps; steps.max = 2000; steps.value = taskLimitDrafts.get(task.id)?.[1] ?? task.limits.steps; steps.setAttribute('aria-label', 'Task step limit');
    const raise = document.createElement('button'); raise.type = 'button'; raise.textContent = 'Raise limits';
    raise.addEventListener('click', () => { raise.disabled = true; worker.postMessage({ task: { action: 'raise', id: task.id, limits: { requests: Number(requests.value), steps: Number(steps.value) } } }); });
    const requestLabel = document.createElement('label'); requestLabel.textContent = 'AI reply limit'; requestLabel.append(requests);
    const stepLabel = document.createElement('label'); stepLabel.textContent = 'Step limit'; stepLabel.append(steps);
    const details = document.createElement('details'); details.dataset.taskDetails = task.id; details.dataset.foldKey = JSON.stringify(['task',task.id,'limits']);
    const summary = document.createElement('summary'); summary.textContent = 'Task details'; details.append(summary, requestLabel, stepLabel, raise); card.append(details);
    slot.append(card);
  }
};

const deliveryTaskChecksPassed = task => {
  if (!task || ![
    'Delivered (service and TCP checks only)',
    'Delivered (service, TCP and sign-in checks only)',
    'Delivered (service, TCP, sign-in and control-center checks only)',
    'Handed over with findings',
  ].includes(task.verdict) || !Array.isArray(task.findings ?? []) ||
      !(task.findings ?? []).every(finding => ['control_center_files', 'unmet_command'].includes(finding?.field)) ||
      !Array.isArray(task.read_plan) || !Array.isArray(task.verification) ||
      task.read_plan.length === 0 || task.read_plan.length !== task.verification.length) return false;
  return task.read_plan.every((read, index) => {
    const observation = task.verification[index]?.observation;
    if (!read || !observation) return false;
    switch (read.kind) {
      case 'running':
      case 'enabled':
        return typeof read.service?.name === 'string' && read.service.name.length > 0 &&
          observation.kind === read.kind && observation.value === true;
      case 'listeners':
        return observation.kind === 'sockets' && Array.isArray(observation.value);
      case 'sign_in':
        return typeof read.url === 'string' && read.url.length > 0 && observation.kind === 'sign_in';
      case 'control_center':
        return observation.kind === 'control_center' && observation.value?.passed === true;
      default:
        return false;
    }
  });
};
const deliveryCheckExcerptLines = verification => typeof verification?.excerpt === 'string' ? verification.excerpt.split(/\r?\n/) : [];

const renderDelivery = (section, machine, store) => {
  const worker = snapshotWorker();
  const entry = (store.delivery ?? []).find(d => d.machine === machine);
  if (!entry) return;
  const delivery = deliveryDetails.entry.get(machine)?.value ?? entry;
  // A machine whose purchase is still open has nothing to report about delivery yet: its target is saved only once it
  // is paid for and running.
  if (store.procurement?.machine === machine && !(store.poc_targets ?? []).some(target => target.machine === machine) &&
      delivery.verdict === 'delivery evidence not yet supplied' && (delivery.findings_count ?? (delivery.findings ?? []).length) === 0) return;
  const isLive = !delivery.summary && (store.poc_targets ?? []).some(target => target.machine === machine);
  const fixtureBreak = isLive ? (delivery.fixture_limit ?? '').indexOf('. ') : -1;
  const card = document.createElement('section');
  card.dataset.deliveryCard = machine;
  const heading = document.createElement('h3');
  heading.textContent = `Delivery for ${machine}`;
  card.append(heading);
  const plain = isLive && delivery.last_check == null && delivery.last_completed_check == null &&
    (delivery.findings ?? []).length === 0 && delivery.findings_unknown !== true &&
    (delivery.applications ?? []).length === 0 && (delivery.subsequent_placement_sessions ?? []).length === 0;
  if (plain) {
    const verdict = document.createElement('p');
    verdict.dataset.deliveryVerdict = machine;
    verdict.textContent = "This card lists what Farseed checked on this machine itself, and what it didn't. The fuller check against Farseed's lockdown checklist isn't in this version. Each setup task's own result is on its task card.";
    card.append(verdict);
    if (entry.summary) deliveryDetailsButton(card, machine, 'entry', 'delivery details', store);
    const verdictTasks = (store.tasks ?? []).filter(task => task.machine === machine && task.verdict);
    const recordTasks = (store.tasks ?? []).filter(task => task.machine === machine && task.summary !== true &&
      Array.isArray(task.read_plan) && task.read_plan.length > 0);
    const summaryTasks = (store.tasks ?? []).filter(task => task.machine === machine && task.summary === true);
    const task = recordTasks.length === 1 ? recordTasks[0] : null;
    const checked = document.createElement('section');
    checked.dataset.deliveryChecked = machine;
    if (deliveryTaskChecksPassed(task)) {
      const count = task.read_plan.length;
      paragraph(checked, count === 1
        ? 'When the AI handed the setup over, Farseed ran 1 check on this machine itself. It passed:'
        : `When the AI handed the setup over, Farseed ran ${count} checks on this machine itself. All ${count} passed:`);
      const list = document.createElement('ul');
      for (const [index, read] of task.read_plan.entries()) {
        const item = document.createElement('li');
        switch (read.kind) {
          case 'running': item.textContent = `${read.service.name} is running`; break;
          case 'enabled': item.textContent = `${read.service.name} is set to start at boot`; break;
          case 'listeners': item.textContent = 'Only the TCP ports the setup declared are listening'; break;
          case 'sign_in': item.textContent = `${read.url} asks for a sign-in`; break;
          case 'control_center': {
            const lastLine = deliveryCheckExcerptLines(task.verification[index]).filter(line => line.trim()).at(-1) ?? '';
            const counts = /^CHECKS done PASS (\d+)\/(\d+)$/.exec(lastLine);
            item.textContent = counts && BigInt(counts[1]) > 0n && BigInt(counts[1]) === BigInt(counts[2])
              ? `The control center's own final check: all ${BigInt(counts[1])} of its checks passed`
              : "The control center's own final check passed";
            break;
          }
        }
        list.append(item);
      }
      checked.append(list);
      if (task.read_plan.some(read => read.kind === 'control_center')) {
        paragraph(checked, "The control center's check records names only for checks that fail, so the ones that passed aren't listed here.");
      }
      if ((task.findings ?? []).length > 0) {
        paragraph(checked, 'The setup still has something left to do outside these checks. Its task card says what.');
      }
    } else if (task) {
      const count = task.read_plan.length;
      const results = Array.isArray(task.verification) ? task.verification.filter(entry => entry?.observation != null).length : 0;
      paragraph(checked, results === 0
        ? `Farseed's own final checks on this machine have no result yet: 0 of ${count}. The task card shows what happens next.`
        : `Farseed's own final checks on this machine haven't all passed: ${results} of ${count} have a result so far. The task card shows which, and what to do next.`);
    } else if (recordTasks.length > 1) {
      paragraph(checked, `Farseed has final-check records from ${recordTasks.length} setup tasks on this machine. Each task card shows its own results.`);
    } else if (summaryTasks.length > 0) {
      paragraph(checked, "This page shows this machine's earlier tasks in short form, so their final checks aren't listed here. Each task card shows its result.");
    } else paragraph(checked, "Farseed has no record of its own final checks on this machine yet.");
    card.append(checked);
    const unchecked = document.createElement('section');
    unchecked.dataset.deliveryUnchecked = machine;
    paragraph(unchecked, "What Farseed didn't check:");
    const list = document.createElement('ul');
    const addUnchecked = text => {
      const item = document.createElement('li');
      item.textContent = text;
      list.append(item);
    };
    addUnchecked("The whole machine against Farseed's lockdown checklist: this version can't run that check yet");
    addUnchecked('Where the machine connects out to');
    if (task) {
      if (task.read_plan.some(read => read?.kind === 'enabled')) addUnchecked('That the services come back after a restart: no reboot was tried');
      if (task.read_plan.some(read => read?.kind === 'sign_in')) addUnchecked('That the apps work the way you want: the sign-in checks only show that each address asks for a sign-in');
      if (task.read_plan.some((read, index) => read?.kind === 'control_center' &&
          deliveryCheckExcerptLines(task.verification?.[index]).includes('T3 Code: not linked yet (the user chose Later)'))) {
        addUnchecked("Your T3 Code link: you chose Later, so it isn't linked yet");
      }
    }
    addUnchecked("Anything that changes later: Farseed doesn't keep watching the machine, so these results are from when the checks ran");
    unchecked.append(list);
    card.append(unchecked);
    if (verdictTasks.length === 1) renderDeliveredUrls(card, taskDeliveredUrls(verdictTasks[0]));
    if (Number.isInteger(delivery.reports_count)) {
      const reports = document.createElement('section');
      paragraph(reports, delivery.report_label);
      if (delivery.report_note) paragraph(reports, delivery.report_note);
      const count = deliveryDetails.commands.get(machine)?.value?.length ?? delivery.reports_count;
      const records = deliveryDetailsButton(reports, machine, 'commands', `commands (${count})`, store);
      for (const [index, report] of (records ?? []).entries()) {
        showDeliveryReport(reports, report);
        rawDetails(reports, report, ['delivery', machine, 'report', index]);
      }
      card.append(reports);
    }
    section.append(card);
    return;
  }
  if (delivery.summary === true && (store.poc_targets ?? []).some(target => target.machine === machine) &&
      delivery.verdict === 'delivery evidence not yet supplied' && delivery.findings_count === 0) {
    const verdict = document.createElement('p');
    verdict.dataset.deliveryVerdict = machine;
    verdict.textContent = "Open delivery details for what Farseed checked on this machine and what it didn't. Each setup task's own result is on its task card.";
    card.append(verdict);
    if (entry.summary) deliveryDetailsButton(card, machine, 'entry', 'delivery details', store);
    section.append(card);
    return;
  }
  if (delivery.fixture_limit) paragraph(card, fixtureBreak === -1 ? delivery.fixture_limit : delivery.fixture_limit.slice(0, fixtureBreak + 1));
  const verdict = document.createElement('p');
  verdict.dataset.deliveryVerdict = machine;
  verdict.textContent = delivery.verdict;
  if (delivery.verdict_is_historical && delivery.last_completed_check) paragraph(card, 'The last completed result is historical; a final demonstration is still needed.');
  card.append(verdict);
  if (isLive) paragraph(card, 'Not checked here: this version has no machine-wide delivery check (the lockdown checklist). The checks the setup runs, and their result, are on its task card.');
  if (entry.summary) deliveryDetailsButton(card, machine, 'entry', 'delivery details', store);
  if (delivery.summary) {
    paragraph(card, `${delivery.findings_count} findings recorded.`);
    section.append(card);
    return;
  }
  // Tasks arrive keyed by random id, not in time order: show addresses here only when exactly one task on this machine
  // has a verdict; otherwise each task's own card shows its addresses.
  const verdictTasks = (store.tasks ?? []).filter(task => task.machine === machine && task.verdict);
  if (verdictTasks.length === 1) renderDeliveredUrls(card, taskDeliveredUrls(verdictTasks[0]));
  if (isLive) {
    const about = document.createElement('details');
    about.dataset.foldKey = JSON.stringify(['delivery-about', machine]);
    const summary = document.createElement('summary'); summary.textContent = 'About this card';
    about.append(summary);
    if (fixtureBreak !== -1) paragraph(about, delivery.fixture_limit.slice(fixtureBreak + 2));
    paragraph(about, 'Delivered covers the declared machine state and the fixed lockdown checks.');
    card.append(about);
  } else paragraph(card, 'Delivered covers the declared machine state and the fixed lockdown checks.');
  if (delivery.last_completed_check) {
    paragraph(card, 'Last recorded check against its journaled declaration:');
    paragraph(card, delivery.verdict_is_historical ? 'Last completed check (historical result):' : 'Last completed check:');
    paragraph(card, delivery.last_completed_check.result.delivered ? 'Delivered' : 'handed over with findings');
    for (const note of delivery.last_completed_check.result.notes) paragraph(card, note.service.name + ': ' + note.text);
    if (!delivery.completed_declaration_current) paragraph(card, 'The current declaration needs a re-check; the completed check used earlier values.');
  }
  if (delivery.last_check) {
    if (!delivery.last_check.result.complete) paragraph(card, 'Latest attempt incomplete; no final demonstration recorded.');
    for (const note of delivery.last_check.result.notes) {
      if (!delivery.last_check.result.complete) paragraph(card, note.service.name + ': ' + note.text);
    }
    for (const result of delivery.last_check.result.fields) paragraph(card, result.field + ': ' + result.status);
    if (!delivery.last_check.result.complete) { paragraph(card, 'Latest attempt measurements:'); rawDetails(card, delivery.last_check.measurements).dataset.deliveryMeasurements = machine; }
  }
  if (delivery.findings_unknown) paragraph(card, 'Findings unknown until a complete re-check.');
  for (const finding of delivery.findings ?? []) paragraph(card, finding.class + ': ' + finding.detail);
  for (const name of delivery.applications ?? []) {
    const application = document.createElement('section');
    application.dataset.deliveryApplication = '';
    paragraph(application, `${name} is an AI that acts on this server by itself. Farseed's promises cover what Farseed's AI does, not what ${name} does.`);
    paragraph(application, `It does not mean ${name} works`);
    card.append(application);
  }
  for (const session of delivery.subsequent_placement_sessions ?? []) paragraph(card, 'Placement since the last check in session ' + session + '; final lifecycle demonstration not supplied.');
  if (Number.isInteger(delivery.reports_count)) {
    const reports = document.createElement('section');
    paragraph(reports, delivery.report_label);
    if (delivery.report_note) paragraph(reports, delivery.report_note);
    const count = deliveryDetails.commands.get(machine)?.value?.length ?? delivery.reports_count;
    const records = deliveryDetailsButton(reports, machine, 'commands', `commands (${count})`, store);
    for (const [index, report] of (records ?? []).entries()) {
      showDeliveryReport(reports, report);
      rawDetails(reports, report, ['delivery', machine, 'report', index]);
    }
    card.append(reports);
  }
  const session = (store.sessions ?? []).find(s => s.session_state !== 'ended' && s.bound_set.includes(machine));
  if (!isLive && session && session.inference_limits?.state !== 'clock-withheld') {
    const button = document.createElement('button');
    button.type = 'button';
    button.dataset.deliveryCheck = machine;
    button.textContent = 'Check delivery (fixture evidence only)';
    button.addEventListener('click', () => {
      button.disabled = true;
      worker.postMessage({ delivery: { action: 'check', session: session.identity, machine } });
    });
    card.append(button);
  }
  section.append(card);
};
const bolt11AmountTenths = invoice => {
  if (typeof invoice !== 'string' || (invoice !== invoice.toLowerCase() && invoice !== invoice.toUpperCase())) return null;
  const normalized = invoice.toLowerCase();
  const separator = normalized.lastIndexOf('1');
  if (separator < 0 || separator === normalized.length - 1) return null;
  const amount = /^lnbc([0-9]+)([munp]?)$/.exec(normalized.slice(0, separator));
  if (!amount) return null;
  // Tenths of a millisat keep the p multiplier exact, including fractional millisats.
  const multiplier = {'': 1000000000000n, m: 1000000000n, u: 1000000n, n: 1000n, p: 1n};
  return BigInt(amount[1]) * multiplier[amount[2]];
};
const roundedInvoiceSats = tenths => ((tenths + 9999n) / 10000n).toLocaleString('en-US');
// The invoice's own amount, exactly: whole sats grouped, any fraction of a sat kept (tenths of a millisat).
const exactInvoiceSats = tenths => {
  const whole = (tenths / 10000n).toLocaleString('en-US');
  const fraction = (tenths % 10000n).toString().padStart(4, '0').replace(/0+$/, '');
  return fraction ? `${whole}.${fraction}` : whole;
};
const lightningMillisats = invoice => {
  if (invoice.currency !== 'BTC' || ![invoice.amount, invoice.tax].every(part => Number.isSafeInteger(part) && part >= 0)) return null;
  return {millisats: BigInt(invoice.amount) + BigInt(invoice.tax), currency: invoice.currency};
};
const invoiceControls = (parent, savedInvoice, expires, total) => {
  const wallet = document.createElement('a'); wallet.textContent = 'Open in wallet'; wallet.href = `lightning:${savedInvoice}`;
  const bound = total?.currency === 'BTC' && typeof total.millisats === 'bigint' && total.millisats >= 0n ? total.millisats : null;
  const requested = bolt11AmountTenths(savedInvoice);
  let guidance = null;
  if (bound === null) {
    if (requested === null) guidance = 'The provider converted this charge at its own rate. Check the amount in your wallet.';
    else {
      const actual = exactInvoiceSats(requested);
      wallet.textContent = `Pay ${actual} sat in your wallet`;
      guidance = `The provider converted this charge into ${actual} sat at its own rate.`;
    }
  } else {
    const expectedTenths = ((bound + 999n) / 1000n) * 10000n;
    const expected = roundedInvoiceSats(expectedTenths);
    if (requested === expectedTenths) wallet.textContent = `Pay ${expected} sat in your wallet`;
    else if (requested === null) guidance = `Check that your wallet asks for ${expected} sat.`;
    else if (requested < expectedTenths) {
      const actual = exactInvoiceSats(requested);
      wallet.textContent = `Pay ${actual} sat in your wallet`;
      guidance = `This invoice asks for ${actual} sat, less than the ${expected} sat price shown above.`;
    } else guidance = `This invoice asks for ${exactInvoiceSats(requested)} sat, more than the ${expected} sat shown here. Don't pay it.`;
  }
  const copy = document.createElement('button'); copy.type = 'button'; copy.textContent = 'Copy';
  copy.addEventListener('click', async () => {
    try { await navigator.clipboard.writeText(savedInvoice); copy.textContent = 'Copied'; }
    catch { copy.textContent = 'Copy unavailable'; }
  });
  const remaining = document.createElement('span'); remaining.dataset.invoiceExpires = String(expires);
  remaining.textContent = `${Math.max(0, Math.ceil((expires - Date.now() / 1000) / 60))} minutes left`;
  parent.append(wallet, ' ', copy, ' ', remaining);
  if (guidance) paragraph(parent, guidance);
};
let providerCloseState = {purchase: {}, enabled: false};
const updateProviderClose = () => {
  const {purchase, enabled} = providerCloseState;
  const closeEligible = Boolean(purchase.vm_id) && !purchase.target && (!purchase.payment || (purchase.payment.is_paid === false && Math.floor(Date.parse(purchase.payment.expires) / 1000) <= Math.floor(Date.now() / 1000)));
  $('provider-close').hidden = !closeEligible;
  $('provider-close').disabled = !enabled || !closeEligible;
  $('provider-stop').hidden = !purchase.stop;
  $('provider-stop').disabled = !enabled || !purchase.stop;
};
setInterval(() => {
  for (const node of document.querySelectorAll('[data-invoice-expires]')) node.textContent = `${Math.max(0, Math.ceil((Number(node.dataset.invoiceExpires) - Date.now() / 1000) / 60))} minutes left`;
  updateProviderClose();
  // Unchanged payment-timer reports skip render, so time-based progress lines (an invoice expiring) refresh here.
  if (renderedReport !== undefined) renderProgress(renderedReport);
}, 1000);
// Measured by the test side on 2026-11-18 with the default model: 0.14-0.17 USD per setup
// on older builds, 0.07 USD on the build that runs every block by name. Update when that changes.
const setupCreditUsd = {low: '0.10', high: '0.20', suggested: '0.50'};
const creditUsdPerSat = credit => {
  const topup = credit?.last_topup;
  const rate = topup?.usd / topup?.sat;
  return Number.isFinite(rate) && rate > 0 ? rate : null;
};
const wholeSats = amount => Math.round(amount).toLocaleString('en-US');
const creditBalanceText = credit => {
  const rate = creditUsdPerSat(credit);
  return credit?.balance_text && rate !== null && Number.isFinite(credit.balance)
    ? `${credit.balance_text} (≈ ${wholeSats(credit.balance / rate)} sat)` : credit?.balance_text;
};
const updateCreditAmount = credit => {
  const input = $('credit-amount');
  const output = $('credit-amount-value');
  const rate = creditUsdPerSat(credit);
  const sat = input.valueAsNumber;
  output.hidden = rate === null || !input.validity.valid || !Number.isFinite(sat);
  output.textContent = output.hidden ? '' : `${wholeSats(sat)} sat ≈ ${(sat * rate).toFixed(2)} USD`;
};
const renderCredit = (store, enabled) => {
  const credit = store.credit;
  const rate = creditUsdPerSat(credit);
  const setupSats = rate === null ? '' : ` (≈ ${wholeSats(Number(setupCreditUsd.low) / rate)}-${wholeSats(Number(setupCreditUsd.high) / rate)} sat)`;
  const suggestedSats = rate === null ? '' : ` (≈ ${wholeSats(Number(setupCreditUsd.suggested) / rate)} sat)`;
  $('credit-guidance').textContent = `Setting up one machine usually uses about ${setupCreditUsd.low}-${setupCreditUsd.high} USD${setupSats} of AI credit. Buying ${setupCreditUsd.suggested} USD${suggestedSats} leaves room to spare; unused credit stays in your account.`;
  $('credit-rate').textContent = rate === null ? 'The sat equivalent shows here after your first top-up.' : 'Estimates use the rate from your last top-up.';
  updateCreditAmount(credit);
  const invoices = credit?.invoices ?? [];
  const latest = invoices.at(-1);
  const unresolved = latest && !['paid', 'expired_unpaid', 'abandoned'].includes(latest.outcome);
  $('credit-invoice').disabled = !enabled || Boolean(unresolved);
  $('credit-invoice').textContent = ['expired_unpaid','abandoned'].includes(latest?.outcome) ? 'New invoice' : credit?.account ? 'Add credit' : 'Get an invoice';
  $('credit-check').hidden = !credit?.account;
  $('credit-check').disabled = !enabled;
  $('credit-configure').disabled = !enabled || !credit?.can_start;
  $('credit-details').textContent = latest ? `Last saved status: ${latest.last_status}` : '';
  const slot = $('credit-invoices'); slot.replaceChildren();
  for (const invoice of invoices) {
    const row = document.createElement('section'); row.dataset.creditInvoice = invoice.id;
    paragraph(row, `${invoice.amount_sat} sat. ${({abandoned:'Invoice marked abandoned.',pending:'Waiting for external payment.',paid:'Payment seen; inference credit read.',expired_unpaid:'This invoice expired unpaid, according to the credit service.',unknown:'Payment status unknown.',seen:'Payment seen; balance not read yet.'})[invoice.outcome]}`);
    if (!['paid', 'seen'].includes(invoice.outcome)) invoiceControls(row, invoice.bolt11, invoice.expires_at, {millisats: BigInt(invoice.amount_sat) * 1000n, currency: 'BTC'});
    slot.append(row);
  }
};
$('credit-amount').addEventListener('input', () => updateCreditAmount(renderedReport?.credit));
$('credit-invoice').addEventListener('click', () => {
  $('credit-invoice').disabled = true;
  worker.postMessage({credit_request:{action:'invoice',amount:Number($('credit-amount').value)}});
});
$('credit-check').addEventListener('click', () => worker.postMessage({credit_request:{action:'check'}}));
$('credit-configure').addEventListener('click', () => worker.postMessage({credit_request:{action:'configure',endpoint:$('poc-endpoint').value,model:$('poc-model').value}}));

let providerCatalogue = null;
let providerCompletedMachine = null;
let providerMachineTyped = false;
$('provider-machine').addEventListener('input', () => { providerMachineTyped = true; });
let providerSelectionDirty = true;
let providerReviewToken = null;
let providerDisplayedBilling = null;
let providerDisplayedSelection = null;
let providerDisplayedOrigin = null;
const providerRequest = action => worker.postMessage({provider_request: action});
const updateProviderResources = () => {
  $('provider-resources-field').hidden = !$('provider-offer').value.startsWith('custom:');
};
const readableMoney = (amount, currency) => {
  const unit = currency === 'BTC' ? 'millisats' : `${currency} cents`;
  const raw = `${amount} ${unit}`;
  if (!Number.isSafeInteger(amount) && typeof amount !== 'bigint') return raw;
  const value = BigInt(amount);
  if (currency === 'BTC') {
    const sat = value / 1000n + (value % 1000n > 0n ? 1n : 0n);
    return `${sat.toLocaleString('en-US')} sat (${raw})`;
  }
  const absolute = value < 0n ? -value : value;
  const decimal = `${value < 0n ? '-' : ''}${absolute / 100n}.${String(absolute % 100n).padStart(2, '0')}`;
  return `${decimal} ${currency} (${raw})`;
};
const boundInvoiceTotal = invoice => {
  const parts = [invoice.amount, invoice.tax];
  if (!parts.every(Number.isSafeInteger)) return parts.join(' + ');
  return parts.reduce((sum, part) => sum + BigInt(part), 0n);
};
const readableInterval = (amount, type) => {
  if (['month', 'day', 'hour'].includes(type) && Number.isSafeInteger(amount) && amount >= 1) {
    return amount === 1 ? `per ${type}` : `per ${amount} ${type}s`;
  }
  return `${amount} ${type}`;
};
const readableSize = bytes => {
  if (!Number.isSafeInteger(bytes) || bytes < 0) return `${bytes} bytes`;
  const unit = bytes >= 1024 ** 3 ? 'GB' : 'MB';
  const size = bytes / 1024 ** (unit === 'GB' ? 3 : 2);
  return `${Number.isInteger(size) ? size : size.toFixed(1)} ${unit}`;
};
const readableCpus = count => `${count} ${count === 1 ? 'CPU' : 'CPUs'}`;
const readableDuration = seconds => {
  if (Number.isSafeInteger(seconds) && seconds > 0) {
    if (seconds % 86400 === 0) return `${seconds / 86400} days`;
    if (seconds % 3600 === 0) return `${seconds / 3600} hours`;
  }
  return `${seconds} seconds`;
};
const renderProvider = (store, enabled) => {
  const worker = snapshotWorker();
  const recorded = store.provider_configuration?.recorded === true;
  const account = store.provider_configuration?.account;
  $('provider-key-status').textContent = recorded
    ? (/^[0-9a-f]{64}$/.test(account ?? '') ? `Provider account public identity: ${account}` : 'Provider account recorded; public identity unavailable.')
    : 'The first provider action creates and keeps one provider account.';
  const fixed = recorded || Boolean(store.procurement?.phase || store.procurement?.closed);
  $('provider-existing').hidden = true;
  $('provider-existing').inert = true;
  $('provider-existing').open = false;
  $('provider-key').value = '';
  for (const control of $('provider-key-form').elements) control.disabled = true;
  $('provider-key-form').hidden = fixed;
  const entered = store.provider_configuration?.entered === true;
  $('provider-entered-note').hidden = !entered;
  $('provider-account-fixed').hidden = !fixed;
  const deployed = store.provider_configuration?.relay_deployed === true;
  const relayFold = $('provider-relay-fold');
  relayFold.hidden = !deployed;
  if (deployed) relayFold.append($('provider-relay-guidance'));
  else relayFold.after($('provider-relay-guidance'));
  $('provider-relay-guidance').textContent = deployed
    ? 'Registering the machine SSH public key with the provider does not enroll the relay. The deployment relay key is in use. You still need published pins and approvals for the goal, class, access and installation declaration.'
    : 'Registering the machine SSH public key with the provider does not enroll the relay. Before configuration, copy the separate relay public key and ask your relay operator to enroll it. You still need published pins and approvals for the goal, class, access and installation declaration.';
  $('relay-task-guidance').textContent = deployed
    ? 'After enrollment, configure inference, then press Start session for the displayed model and machine. Copy its public keys. Install the SSH line. The deployment relay key is in use.'
    : 'After enrollment, configure inference, then press Start session for the displayed model and machine. Copy its public keys. Install the SSH line and enroll the separate relay public key with the relay operator.';
  $('relay-deployment-status').textContent = deployed ? 'The deployment relay key is in use.' : 'No valid deployment relay key is loaded. The seed-derived relay key requires manual enrollment.';
  const purchase = store.procurement ?? {};
  if (store.readiness?.checked_at) $('step-machine-status').title = `${new Date(store.readiness.checked_at).toISOString()} UTC`;
  else $('step-machine-status').removeAttribute('title');
  const emailRequired = purchase.phase === 'email_verification';
  $('provider-email').hidden = !emailRequired;
  $('provider-email-wait').hidden = !purchase.email_entered;
  for (const control of $('provider-email-form').elements) control.disabled = !enabled || !emailRequired;
  $('provider-email-check').disabled = !enabled || !emailRequired;
  $('provider-email-reissue').disabled = !enabled || !emailRequired || !purchase.email_entered;
  if (!emailRequired) $('provider-email-address').value = '';
  const completedMachine = purchase.phase === 'handed_off' ? purchase.machine : purchase.completed?.at(-1)?.machine ?? null;
  if (providerCompletedMachine !== completedMachine) {
    providerCompletedMachine = completedMachine;
    providerCatalogue = null;
    providerSelectionDirty = true;
    $('provider-catalogue-view').replaceChildren();
    $('provider-offer').replaceChildren(new Option('Choose a fetched offer', ''));
    $('provider-image').replaceChildren(new Option('Choose a fetched image', ''));
    $('provider-machine').value = '';
    providerMachineTyped = false;
    $('provider-class').value = '';
  }
  if ((!purchase.phase || purchase.phase === 'handed_off') && store.state === 'unlocked' &&
      !$('provider-machine').value && !providerMachineTyped) {
    const names = new Set([
      ...(store.setup ?? []).map(setup => setup.entry?.machine),
      ...(store.poc_targets ?? []).map(target => target.machine),
      purchase.machine,
      ...(purchase.completed ?? []).map(completed => completed.machine),
      ...(store.sessions ?? []).flatMap(session => session.bound_set ?? []),
      ...(store.tasks ?? []).map(task => task.machine),
      ...(store.delivery ?? []).map(delivery => delivery.machine),
    ]);
    let number = 1;
    while (names.has(`server-${number}`)) number += 1;
    $('provider-machine').value = `server-${number}`;
  }
  if (!$('purchase-review-home')) {
    const home = document.createElement('span'); home.id = 'tau-purchase-review-home';
    $('purchase-review').before(home);
  }
  if (purchase.selection) {
    if ($('purchase-review').parentNode !== $('purchase-review-slot')) $('purchase-review-slot').append($('purchase-review'));
  } else if ($('purchase-review-home').nextSibling !== $('purchase-review')) $('purchase-review-home').after($('purchase-review'));
  $('purchase-review-slot').hidden = store.state !== 'unlocked';
  if (!$('provider-origin').value && (store.provider_configuration?.origin ?? purchase.origin)) $('provider-origin').value = store.provider_configuration?.origin ?? purchase.origin;
  providerDisplayedOrigin = purchase.origin ?? null;
  providerDisplayedBilling = purchase.billing ? structuredClone(purchase.billing) : null;
  providerDisplayedSelection = purchase.selection ? structuredClone(purchase.selection) : null;
  const renewal = purchase.phase === 'terms_changed';
  const reviewToken = purchase.selection ? JSON.stringify([purchase.origin, purchase.selection]) : null;
  if (providerReviewToken !== reviewToken) {
    $('provider-approve-charge').checked = false;
    $('provider-approve-access').checked = false;
    providerReviewToken = reviewToken;
  }
  if (renewal) {
    $('provider-machine').value = purchase.machine;
    $('provider-relay').value = purchase.relay;
    $('provider-class').value = purchase.class_answer;
  }
  if (store.provider_catalogue) {
    providerCatalogue = store.provider_catalogue;
    const catalogue = $('provider-catalogue-view'); catalogue.replaceChildren();
    const offerSelect = $('provider-offer'); offerSelect.replaceChildren(new Option('Choose a fetched offer', ''));
    for (const [kind, offers] of [['fixed', providerCatalogue.offers.templates], ['custom', providerCatalogue.offers.custom_template ?? []]]) {
      for (const offer of offers) {
        const terms = offer.cost_plan ?? offer;
        const hourly = terms.interval_type === 'hour';
        const label = `${kind === 'fixed' ? `${offer.name}, ${offer.region?.name}: ${readableCpus(offer.cpu)}, ${readableSize(offer.memory)} memory, ${readableSize(offer.disk_size)} disk, ${readableMoney(terms.amount, terms.currency)}` : `Custom size, ${offer.region?.name}: choose resources and request a price,`} ${readableInterval(terms.interval_amount, terms.interval_type)}${hourly ? ' — unsupported credit-only hourly plan' : ''}`;
        paragraph(catalogue, label);
        const option = new Option(label, `${kind}:${offer.id}`); option.disabled = hourly; offerSelect.add(option);
        if (kind === 'custom') { readableFacts(catalogue, offer); rawDetails(catalogue, offer); }
      }
    }
    const images = $('provider-image'); images.replaceChildren(new Option('Choose a fetched image', ''));
    for (const image of providerCatalogue.images) {
      const user = !Object.hasOwn(image, 'default_username') && image.distribution === 'archlinux' ? 'arch' : image.default_username;
      const unsupported = image.encrypted !== false || !['archlinux', 'nixos'].includes(image.distribution) || typeof user !== 'string' || !/^[a-z_][a-z0-9_-]{0,31}$/.test(user) || user !== user.trim();
      const label = `${image.distribution} ${image.flavour} ${image.version}${unsupported ? ' — unsupported (requires a supported unencrypted image without console unlock)' : ''}`;
      const option = new Option(label, String(image.id)); option.disabled = unsupported; images.add(option);
    }
    providerSelectionDirty = true; $('provider-approve-charge').checked = false;
  }
  updateProviderResources();
  if (store.provider_selection_reviewed || renewal) providerSelectionDirty = false;
  const selection = $('provider-selection-view'); selection.replaceChildren();
  if (purchase.selection) {
    paragraph(selection, `Provider origin: ${purchase.origin}`);
    const c = purchase.selection.charge;
    paragraph(selection, `Recurring charge: ${readableMoney(c.amount, c.currency)} ${readableInterval(c.interval_amount, c.interval_type)}. Tax and processing fee are shown on the initial invoice.`);
    const selected = purchase.selection;
    const resources = selected.resources ?? selected.offer;
    paragraph(selection, `${selected.offer.name}; ${selected.offer.region?.name ?? 'region not stated'}; ${selected.image.distribution} ${selected.image.flavour} ${selected.image.version}.`);
    paragraph(selection, `${readableCpus(resources.cpu)}, ${readableSize(resources.memory)} memory (${resources.memory} bytes), ${readableSize(resources.disk_size ?? resources.disk)} disk (${resources.disk_size ?? resources.disk} bytes).`);
    rawDetails(selection, purchase.selection, ['purchase', purchase.origin, purchase.account ?? null]);
  }
  const progress = $('provider-progress'); progress.replaceChildren();
  if (purchase.closed) {
    paragraph(progress, purchase.closed.startsWith('Stopped:') ? purchase.closed : 'The provider no longer has the earlier machine or its payment records, and this purchase recorded no payment. You can approve a new purchase. If you paid, keep your proof of payment; these checks cannot establish whether you paid.');
    rawDetails(progress, {closed: purchase.closed}, ['purchase-closed']);
  }
  const stopNotice = $('provider-stop-notice'); stopNotice.replaceChildren();
  stopNotice.hidden = !purchase.stop;
  if (purchase.stop) paragraph(stopNotice, purchase.stop.message);
  $('provider-stop').onclick = () => providerRequest({action: 'stop', stage: purchase.stop.stage});
  if (purchase.phase) {
    if (purchase.duplicate_orders?.length) paragraph(progress, `The provider received this order twice. The extra machine (${purchase.duplicate_orders.join(', ')}) is unpaid; the provider deletes it within about an hour. Nothing is charged for it.`);
    if (purchase.payment_notice) paragraph(progress, purchase.payment_notice);
    if (purchase.stop_after && !purchase.stop) paragraph(progress, `If no machine appears by ${new Date(purchase.stop_after * 1000).toLocaleTimeString([], {hour: '2-digit', minute: '2-digit'})}, you can stop this purchase.`);
    if (purchase.candidates?.length) {
      paragraph(progress, purchase.candidates.length > 1 ? 'The provider holds more than one machine that matches this order. Choose the one this purchase uses; the others are left as they are and never invoiced here.' : 'Confirm the machine this purchase uses.');
      for (const candidate of purchase.candidates) {
        paragraph(progress, `Machine ${candidate.id}; created ${candidate.created}; address ${(candidate.addresses ?? []).map(address => address.ip).join(', ') || 'not allocated'}.`);
        const choose = document.createElement('button'); choose.type = 'button'; choose.textContent = `Use machine ${candidate.id}`; choose.disabled = !enabled;
        choose.addEventListener('click', () => providerRequest({action: 'choose', vm_id: candidate.id})); progress.append(choose);
      }
    }
    paragraph(progress, `${purchase.machine}: ${purchaseStatus(purchase)}`);
    rawDetails(progress, purchase, ['purchase-progress', purchase.machine]);
    paragraph(progress, `Machine provider: ${purchase.origin}`);
    paragraph(progress, `Automatic renewal: ${purchase.auto_renewal_enabled === true ? 'on' : purchase.auto_renewal_enabled === false ? 'off' : 'unknown'}. This page does not change it.`);
    if (purchase.billing) {
      const quote = purchase.billing.terms;
      paragraph(progress, `Price for the first period, before any account credit: ${readableMoney(boundInvoiceTotal(quote), quote.currency)} for ${readableDuration(quote.time)} (${readableMoney(quote.amount, quote.currency)}, tax ${readableMoney(quote.tax, quote.currency)}).`);
      if (quote.processing_fee !== 0) paragraph(progress, `Its processing fee of ${readableMoney(quote.processing_fee, quote.currency)} is not part of the Lightning invoice.`);
      if (purchase.selection && purchase.selection.charge.currency !== quote.currency) paragraph(progress, `This machine is priced in ${purchase.selection.charge.currency}: the provider converted the price into the sat amounts above at its own rate.`);
      paragraph(progress, `Initial Lightning quote: ${quote.amount}, plus tax ${quote.tax} and processing fee ${quote.processing_fee} (${quote.currency === 'BTC' ? 'millisats' : quote.currency + ' cents'}), covering ${quote.time} seconds. Review these terms before requesting the invoice. Refresh may update the quote.`);
    }
    if (purchase.payment) {
      const pay = purchase.payment;
      paragraph(progress, `Price, before any account credit: ${readableMoney(boundInvoiceTotal(pay), pay.currency)} (amount ${readableMoney(pay.amount, pay.currency)}, tax ${readableMoney(pay.tax, pay.currency)}).`);
      if (pay.processing_fee !== 0) paragraph(progress, `Its processing fee of ${readableMoney(pay.processing_fee, pay.currency)} is not part of the Lightning invoice.`);
      paragraph(progress, `Invoice ${pay.is_paid ? 'paid' : 'awaiting payment'}; expires ${pay.expires}. Amount ${pay.amount}, tax ${pay.tax}, processing fee ${pay.processing_fee} (${pay.currency === 'BTC' ? 'millisats' : pay.currency + ' cents'}).`);
      if (!pay.is_paid) {
        invoiceControls(progress, pay.data.lightning, Math.floor(Date.parse(pay.expires) / 1000), lightningMillisats(pay));
        const check = document.createElement('button'); check.type = 'button'; check.textContent = 'Check now'; check.disabled = !enabled;
        check.addEventListener('click', () => providerRequest({action:'payment_check'})); progress.append(check);
      }
    }
    if (payReadiness(purchase)) {
      const readiness = store.readiness;
      if (readiness?.expired) paragraph(progress, 'Published host-key wait expired after three hours from recorded payment. First contact is stopped; this page cannot reinstall or abandon a paid purchase.');
      else if (readiness?.inactive) {
        paragraph(progress, readiness.inactive === 'the page is hidden' ? 'Return to this page to continue checking the machine.' : readiness.inactive === 'the provider key is missing' ? 'Resupply the provider key to continue checking the machine.' : readiness.inactive === 'a command response is pending' ? 'Waiting for the earlier command before checking the machine.' : 'Machine checks are paused. Unlock again before continuing.');
        rawDetails(progress, readiness, ['readiness', purchase.machine]);
      }
      else {
        paragraph(progress, readinessWait(store));
        if (readiness?.checked_at) {
          const checked = paragraph(progress, 'Last machine check: ');
          const time = document.createElement('time');
          time.dateTime = new Date(readiness.checked_at).toISOString();
          time.title = `${time.dateTime} UTC`;
          time.textContent = localTime(readiness.checked_at);
          checked.append(time, '.');
        } else paragraph(progress, 'The machine has not been checked yet.');
      }
    }
    if (purchase.public_keys) {
      const relay = deployed ? detailFold(progress, 'Relay details', ['purchase-relay', purchase.machine]) : progress;
      paragraph(relay, deployed ? 'Registering the machine SSH public key with the provider does not enroll the relay. The deployment relay key is in use.' : 'Registering the machine SSH public key with the provider does not enroll the relay. Copy the separate relay public key and ask your relay operator to enroll it before configuration.');
      paragraph(relay, deployed ? 'Deployment relay public key:' : 'Relay public key — enroll this separately with the relay operator:');
      const publicKey = document.createElement('pre'); publicKey.textContent = purchase.public_keys.relay_pubkey; relay.append(publicKey);
    }
    if (purchase.target) paragraph(progress, `The machine’s published host key is saved. Press Start session ${purchase.machine} below to continue setup.`);
  }
  if (purchase.completed?.length) {
    const earlier = detailFold(progress, `Earlier purchases (${purchase.completed.length})`, ['purchase-completed']);
    for (const completed of purchase.completed) {
      paragraph(earlier, `${completed.machine}: Purchase completed. Provider: ${completed.origin}. VM: ${completed.vm_id ?? 'unknown'}. Payment: ${completed.payment_id ?? 'none'} (${completed.is_paid ? 'paid' : 'not recorded as paid'}). Target saved: ${completed.target_saved ? 'yes' : 'no'}.`);
    }
  }
  const canReview = !purchase.phase || ['approved', 'registered', 'terms_changed', 'handed_off'].includes(purchase.phase);
  $('provider-approval-form').querySelector('button[type="submit"]').textContent = purchase.phase === 'terms_changed' ? 'Approve the new terms' : 'Approve and order this machine';
  const chargeNote = entered ? 'With an account this page made for you, nothing is charged until you pay its first invoice yourself, in your wallet.' : 'Nothing is charged until you pay its first invoice yourself, in your wallet.';
  $('provider-approval-note').textContent = purchase.phase === 'terms_changed' ? `This records the new terms only. Then press Create the server to order the machine. ${chargeNote}` : `Approving orders this machine from the provider now. ${chargeNote}`;
  for (const control of $('provider-selection-form').elements) control.disabled = !enabled || !canReview;
  for (const control of $('provider-approval-form').elements) control.disabled = !enabled || (Boolean(purchase.phase) && !renewal && purchase.phase !== 'handed_off') || providerSelectionDirty || !purchase.selection;
  if (renewal) {
    for (const name of ['provider-machine', 'provider-relay', 'provider-class']) $(name).disabled = true;
  }
  providerCloseState = {purchase, enabled};
  updateProviderClose();
  $('provider-resume').textContent = ['approved', 'registered'].includes(purchase.phase) ? 'Create the server' : 'Check the order again';
  $('provider-resume').hidden = !purchase.phase || purchase.phase === 'handed_off';
  $('provider-resume').disabled = !enabled || !purchase.phase;
  $('provider-invoice').hidden = purchase.phase !== 'initial_invoice';
  $('provider-invoice').disabled = !enabled || purchase.phase !== 'initial_invoice' || !purchase.billing;
};
$('provider-key-form').addEventListener('submit', event => {
  event.preventDefault();
  $('provider-key').value = '';
});
$('provider-catalogue').addEventListener('click', () => providerRequest({action: 'catalogue'}));
$('provider-selection-form').addEventListener('input', () => {
  updateProviderResources();
  providerSelectionDirty = true; $('provider-approve-charge').checked = false;
  for (const control of $('provider-approval-form').elements) control.disabled = true;
});
$('provider-selection-form').addEventListener('submit', event => {
  event.preventDefault();
  try {
    const [kind, id] = $('provider-offer').value.split(':');
    providerRequest({action: 'select', choice: {offer_id: Number(id), image_id: Number($('provider-image').value), resources: kind === 'custom' ? JSON.parse($('provider-resources').value) : null}});
  } catch { $('step-machine-error').textContent = 'Enter valid custom resource JSON.'; }
});
$('provider-approval-form').addEventListener('submit', event => {
  event.preventDefault(); if (providerSelectionDirty) return;
  providerRequest({action: 'approve', selection: providerDisplayedSelection, approval: {origin: providerDisplayedOrigin, machine: $('provider-machine').value, relay: $('provider-relay').value, class_answer: $('provider-class').value, approve_charge: $('provider-approve-charge').checked, approve_maintained_access: $('provider-approve-access').checked}});
});
$('provider-close').addEventListener('click', () => providerRequest({action: 'close'}));
$('provider-email-form').addEventListener('submit', event => {
  event.preventDefault();
  const field = $('provider-email-address');
  const email = field.value;
  field.value = '';
  providerRequest({action:'email_send', email});
});
$('provider-email-check').addEventListener('click', () => providerRequest({action:'email_check'}));
$('provider-email-reissue').addEventListener('click', () => providerRequest({action:'email_reissue'}));
$('provider-resume').addEventListener('click', () => providerRequest({action: 'resume'}));
$('provider-invoice').addEventListener('click', () => providerRequest({action: 'initial_invoice', billing: providerDisplayedBilling}));
const clearPocInputs = () => {
  pocKeySubmission = null;
  providerMachineTyped = false;
  rawFoldChoices.clear();
  // Fold choices of ended sessions hidden inside their closed list live here; reset with the rest.
  endedSessionFolds.clear();
  providerCatalogue = null;
  providerCompletedMachine = null;
  providerSelectionDirty = true;
  providerReviewToken = null;
  providerDisplayedBilling = null;
  providerDisplayedSelection = null;
  $('provider-catalogue-view').replaceChildren();
  $('provider-selection-view').replaceChildren();
  $('provider-progress').replaceChildren();
  $('provider-key').value = '';
  $('provider-email-address').value = '';
  creditGoalDrafts.clear();
  creditTemplateDrafts.clear();
  goalTemplateDrafts.clear();
  setupDrafts.clear();
  startDrafts.clear();
  taskLimitDrafts.clear();
  pocKeyRefusal = '';
  for (const field of $('poc').querySelectorAll('input')) {
    if (field.closest('#tau-setup, #tau-task-setup, #tau-task-progress, #tau-session-controls')) continue;
    if (field.type === 'checkbox') field.checked = false;
    else if (!defaultsInputs.includes(field.id.replace('tau-', ''))) field.value = '';
  }
  $('poc-elevation').value = $('poc-class').value = '';
  $('poc-public-keys').replaceChildren();
};
const payReadiness = purchase => purchase.payment?.is_paid && !purchase.target;

const templateControls = (parent, template, draft) => {
  const options = new Map();
  for (const value of template.options) {
    const label = document.createElement('label');
    const option = document.createElement('input');
    option.type = 'checkbox'; option.dataset.templateOption = value.name;
    option.checked = draft.options[value.name] ?? value.default;
    option.addEventListener('change', () => { draft.options[value.name] = option.checked; });
    label.append(option, document.createTextNode(value.label));
    parent.append(label); options.set(value.name, option);
  }
  const inputs = new Map();
  for (const value of template.inputs ?? []) {
    const label = document.createElement('label');
    const input = document.createElement('input');
    input.type = 'text'; input.dataset.templateInput = value.name;
    input.value = draft.inputs[value.name] ?? '';
    input.addEventListener('input', () => { draft.inputs[value.name] = input.value; });
    label.append(document.createTextNode(value.label), input);
    parent.append(label); inputs.set(value.name, input);
  }
  return () => ({
    options: Object.fromEntries([...options].map(([name, option]) => [name, option.checked])),
    inputs: Object.fromEntries([...inputs].map(([name, input]) => [name, input.value])),
  });
};

const startInputs = (row, machine, initialGoal = '', documentSource = true, creditMode = false, templates = [], defaultTemplateSelected = false) => {
  const goal = document.createElement('textarea'); if (creditMode) goal.dataset.creditGoal = machine; goal.dataset.startGoal = machine;
  goal.setAttribute('aria-label', 'Goal before Start session'); goal.value = creditGoalDrafts.get(machine) ?? initialGoal;
  goal.addEventListener('input', () => creditGoalDrafts.set(machine, goal.value));
  const source = document.createElement('input'); source.type = 'url'; source.dataset.documentSource = '';
  source.setAttribute('aria-label', 'Optional document source (https URL)');
  source.value = startDrafts.get(machine)?.[1] ?? '';
  source.addEventListener('input', () => startDrafts.set(machine, ['', source.value]));
  paragraph(row, 'Acting on a goal with no brief');
  const template = templates.find(value => value.id === 'control-center@1');
  let selected;
  let values;
  if (template) {
    const draft = creditTemplateDrafts.get(machine) ?? {selected: defaultTemplateSelected, options: {}, inputs: {}};
    creditTemplateDrafts.set(machine, draft);
    const label = document.createElement('label');
    selected = document.createElement('input');
    selected.type = 'checkbox'; selected.dataset.creditTemplate = template.id; selected.checked = draft.selected;
    selected.addEventListener('change', () => { draft.selected = selected.checked; });
    goal.addEventListener('input', () => {
      if (goal.value.length && selected.checked) selected.checked = draft.selected = false;
    });
    label.append(selected, document.createTextNode('Use the Control center template'));
    row.append(label); paragraph(row, template.text);
    values = templateControls(row, template, draft);
    const goalLabel = document.createElement('label');
    goalLabel.append(document.createTextNode('Or write your own goal instead:'), goal);
    row.append(goalLabel);
  } else row.append(goal);
  if (documentSource) row.append(source);
  return () => ({goal:goal.value, document_source:selected?.checked ? null : source.value || null,
    ...(selected?.checked ? {template: template.id, ...values()} : {})});
};

const renderPoc = (store) => {
  if (typeof store.credit_started_machine === 'string') {
    creditGoalDrafts.delete(store.credit_started_machine);
    creditTemplateDrafts.delete(store.credit_started_machine);
  }
  const worker = snapshotWorker();
  const enabled = store.state === 'unlocked' && !ceremony &&
    !['suspended', 'reconciling', 'ended'].includes(store.lifecycle_state);
  for (const content of document.querySelectorAll('.requires-store')) content.hidden = store.state !== 'unlocked';
  for (const control of $('poc').querySelectorAll('input, select, button')) {
    if (!control.closest('#tau-setup, #tau-task-setup, #tau-task-progress, #tau-session-controls')) control.disabled = !enabled;
  }
  renderProvider(store, enabled);
  renderCredit(store, enabled);
  const restored = (store.sessions ?? []).find(s => s.session_state !== 'ended')?.inference_configuration;
  if (restored && store.poc_configuration?.key_set !== true) { $('poc-endpoint').value = restored.endpoint; $('poc-model').value = restored.model; }
  if (['locked', 'none', 'refused', 'lost', 'starting'].includes(store.state) || store.lifecycle_state === 'ended') clearPocInputs();
  renderPocKeyStatus(store);
  const targets = $('poc-targets');
  targets.replaceChildren();
  for (const target of store.poc_targets ?? []) {
    const row = document.createElement('section');
    paragraph(row, `${target.machine} is ready for setup.`);
    paragraph(row, `Connect to ${target.host} on port ${target.port} as ${target.user}. ${target.elevation === 'sudo -n' ? 'Commands can use administrator access without a password.' : target.elevation === 'none' ? 'Commands use this login’s normal access.' : 'Open Details for command access settings.'}`);
    paragraph(row, `Trusted machine host key: ${target.pin}`);
    rawDetails(row, target, ['target', target.machine]);
    if (target.file_access_available) renderMachineFiles(row, target.machine, enabled, worker);
    else if (target.file_access_unavailable_message) paragraph(row, target.file_access_unavailable_message);
    const liveSession = (store.sessions ?? []).find(session => session.session_state !== 'ended' && (session.bound_set ?? []).includes(target.machine));
    const creditSession = (store.sessions ?? []).some(session => session.credit_backed && session.session_state !== 'ended' && (session.bound_set ?? []).includes(target.machine));
    const creditChoice = store.credit?.selected || !store.poc_configuration?.key_set;
    const readingCredit = store.credit?.account && store.credit.balance === null && !store.credit_error;
    const useCredit = creditSession || (creditChoice && Boolean(store.credit?.account));
    const configuration = document.createElement('p');
    if (useCredit) configuration.dataset.inferenceApproval = '';
    else configuration.textContent = `Inference endpoint: ${store.poc_configuration?.configuration?.endpoint ?? 'unavailable'}; model: ${store.poc_configuration?.configuration?.model ?? 'unavailable'}.`;
    row.append(configuration);
    if (liveSession) paragraph(row, `A session is running for ${target.machine}. Its progress is on the task card above.`);
    else paragraph(row, `Start session approves the selected AI connection for ${target.machine}.`);
    const defaultTemplateSelected = store.procurement?.machine === target.machine &&
      store.procurement?.approved_selection?.image?.distribution === 'nixos';
    const inputs = liveSession ? null : startInputs(row, target.machine, '', !useCredit, useCredit, store.goal_templates, defaultTemplateSelected);
    if (liveSession && creditSession) {
      paragraph(row, store.credit.disclosure);
      if (store.credit_error) paragraph(row, store.credit_error);
      paragraph(row, 'New key: only if the task says its AI key ran out.');
    } else if (!liveSession && useCredit) {
      paragraph(row, store.credit.disclosure);
      if (readingCredit) paragraph(row, 'Reading AI credit balance…');
      else if (store.credit_error) paragraph(row, store.credit_error);
      else if (!store.credit.can_start) paragraph(row, creditBalanceText(store.credit));
    }
    for (const [kind, label] of [['poc_bind', 'Start session'], ['poc_public_keys', 'Show public keys']]) {
      if (liveSession && kind === 'poc_bind') continue;
      const button = document.createElement('button');
      button.type = 'button';
      button.disabled = !enabled || (kind === 'poc_bind' && (useCredit ? !store.credit?.can_start : !store.poc_configuration?.configuration));
      button.textContent = `${label} ${target.machine}`;
      button.addEventListener('click', () => {
        button.disabled = true;
        if (kind === 'poc_bind' && useCredit) worker.postMessage({credit_request:{action:'start',machine:target.machine,...inputs(),endpoint:$('poc-endpoint').value,model:$('poc-model').value}});
        else worker.postMessage({ [kind]: { machine: target.machine, ...(kind === 'poc_bind' ? inputs() : {}) } });
      });
      if (kind === 'poc_bind') startDisclosure(row);
      const actions = kind === 'poc_public_keys' ? detailFold(row, `More for ${target.machine}`, ['target-more', target.machine]) : row;
      actions.append(button);
    }
    for (const session of store.sessions ?? []) {
      if (!session.credit_backed || session.session_state === 'ended' || !(session.bound_set ?? []).includes(target.machine)) continue;
      const button = document.createElement('button'); button.type = 'button'; button.textContent = 'New key'; button.dataset.creditNewKey = session.identity; button.disabled = !enabled;
      button.addEventListener('click', () => { button.disabled = true; worker.postMessage({credit_request: {action:'new_key', session:session.identity}}); });
      row.append(button);
    }
    targets.append(row);
  }
  updateInferenceFacts();
  if (store.poc_keys && enabled) {
    const slot = $('poc-public-keys');
    slot.replaceChildren();
    pocKeyRefusal = store.poc_keys.refused ?? '';
    if (!store.poc_keys.refused) {
      paragraph(slot, `Public keys for ${store.poc_keys.machine}`);
      paragraph(slot, store.provider_configuration?.relay_deployed ? 'Registering the machine SSH public key with the provider does not enroll the relay. The deployment relay key is in use.' : 'Registering the machine SSH public key with the provider does not enroll the relay. Copy the separate relay public key and ask your relay operator to enroll it before configuration.');
      for (const [field, label] of [['authorized_keys', 'SSH authorized_keys line'], ['relay_pubkey', 'Relay AUTH public key']]) {
        const value = String(store.poc_keys[field] ?? '');
        paragraph(slot, label);
        const text = document.createElement('pre');
        text.textContent = value;
        const copy = document.createElement('button');
        copy.type = 'button';
        copy.textContent = `Copy ${label}`;
        copy.addEventListener('click', async () => {
          try { await navigator.clipboard.writeText(value); copy.textContent = 'Copied'; }
          catch { copy.textContent = 'Select and copy the text above'; }
        });
        slot.append(text, copy);
      }
    }
  } else if (!enabled) {
    $('poc-public-keys').replaceChildren();
    pocKeyRefusal = '';
  }
};
$('poc-inference-form').addEventListener('submit', event => {
  event.preventDefault();
  const field = $('poc-key');
  if (!worker || $('store').dataset.state !== 'unlocked') {
    $('poc-key-status').textContent = 'Unlock the store before setting the key. Your entry has been kept.';
    return;
  }
  const bytes = new TextEncoder().encode(field.value);
  try {
    worker.postMessage({ poc_configure: {
      endpoint: $('poc-endpoint').value,
      model: $('poc-model').value,
      key: bytes,
      sessions: (taskDetailsStore.sessions ?? []).filter(session => session.session_state !== 'ended').map(session => session.identity).sort(),
    } }, [bytes.buffer]);
    field.value = '';
    pocKeySubmission = 'submitting';
    renderPocKeyStatus(taskDetailsStore);
  } catch {
    $('poc-key-status').textContent = 'The worker could not receive the key. Your entry has been kept; unlock again before retrying.';
  } finally {
    if (bytes.byteLength) bytes.fill(0);
  }
});
$('poc-target-form').addEventListener('submit', event => {
  event.preventDefault();
  worker.postMessage({ poc_enroll: {
    target: {
      machine: $('poc-machine').value, relay: $('poc-relay').value,
      profile: $('poc-profile').value, host: $('poc-host').value,
      port: Number($('poc-port').value), user: $('poc-user').value,
      elevation: $('poc-elevation').value, pin: $('poc-pin').value,
    },
    approve_existing: $('poc-approve-existing').checked,
    class_answer: $('poc-class').value,
    approve_maintained_access: $('poc-approve-access').checked,
  } });
});
let worker;
let firstStart = true;
const setLoadingText = text => {
  const line = $('loading-text');
  if (line.textContent !== text) line.textContent = text;
};

const start = () => {
  unlockPageMarks = null;
  worker = firstStart ? firstWorker : new Worker(new URL('./worker.js', import.meta.url), { type: 'module' });
  firstStart = false;
  $('loading').hidden = false;
  setLoadingText('Loading the app…');
  $('store').inert = $('poc').inert = true;
  goalOutcomes.clear();
  show('starting', 'Starting the harness…');
  render({ state: 'starting' });
  suspended = false;
  ceremony = false;
  const current = worker;
  const incarnation = crypto.randomUUID();
  current.generation = '0';
  const nativePost = current.postMessage.bind(current);
  current.sendAt = (request, transfer, generation) => nativePost({incarnation, generation, request}, transfer);
  current.postMessage = (request, transfer) => current.sendAt(request, transfer, current.generation);
  let deploymentMaterial;
  void defaultsReady.then(material => {
    if (worker !== current) return;
    deploymentMaterial = material;
    const key = new TextEncoder().encode(material.relay_key ?? '');
    try { nativePost({initialize: incarnation, presence: {visible: document.visibilityState === 'visible', online: navigator.onLine}, deployment: {origin: material.provider_origin, key, public_fields: JSON.stringify(material.fields ?? {})}}, [key.buffer]); }
    finally { if (key.byteLength) key.fill(0); }
  });
  worker.onmessage = ({ data }) => {
    if (data.machine_file_list) { receiveMachineFileList(data.machine_file_list, current); return; }
    if (data.machine_file_download) {
      receiveFileDownload({...data.machine_file_download, id: `machine:${data.machine_file_download.machine}`, offer: data.machine_file_download.name}, current);
      return;
    }
    if (data.file_download) { receiveFileDownload(data.file_download, current); return; }
    if (data.task_details) { receiveTaskDetails(data.task_details, current); return; }
    if (typeof data.task_details_unavailable === 'string') { receiveTaskDetails({request: data.task_details_unavailable, error: true}, current); return; }
    if (data.delivery_details) { receiveDeliveryDetails(data.delivery_details, current); return; }
    if (typeof data.delivery_details_unavailable === 'string') { receiveDeliveryDetails({request: data.delivery_details_unavailable, error: true}, current); return; }
    if (worker !== current) return;
    if (['waiting', 'rejected', 'applied', 'cancelled'].includes(data.poc_configure_status)) {
      pocKeySubmission = ['applied', 'cancelled'].includes(data.poc_configure_status) ? null : data.poc_configure_status;
      renderPocKeyStatus(data.poc_configure_status === 'applied' ? {poc_configuration: {key_set: true}} : taskDetailsStore);
      return;
    }
    if (data.unlock_timings) {
      $('store').dataset.unlockTimings = JSON.stringify(data.unlock_timings);
      return;
    }
    if (data.unlock_worker_timings) {
      $('store').dataset.unlockWorkerTimings = JSON.stringify(data.unlock_worker_timings);
      return;
    }
    if (data.app_load_failed === true) {
      current.onerror({message: 'the app did not load'});
      return;
    }
    if (data.app_loading) {
      const {loaded, total, complete} = data.app_loading;
      setLoadingText(total
        ? `Loading the app: ${(loaded / 1000000).toFixed(1)} of ${(total / 1000000).toFixed(1)} MB${complete ? ' — preparing the app…' : ''}`
        : 'Loading the app…');
      return;
    }
    if (typeof data.deployment_ready === 'boolean') {
      publishDefaults(deploymentMaterial, data.deployment_ready);
      return;
    }
    if (data.requirements_store) {
      const { state, error, reason, ...rest } = JSON.parse(data.requirements_store);
      data = { store: { store_state: state, ...(error ? { store_error: error } : {}), ...(reason ? { store_reason: reason } : {}), ...rest } };
    }
    if (worker !== current) return;
    if (typeof data.store?.lifecycle_generation === 'string') current.generation = data.store.lifecycle_generation;
    if (data.harness_ready) {
      $('loading').hidden = true;
      $('store').inert = $('poc').inert = false;
      show('ready', `Harness ready (spec ${data.harness_ready}).`);
    }
    else if (data.store) {
      const marks = unlockPageMarks;
      const received = marks ? unlockNow() : null;
      const { store_state: state, store_error: error, store_reason: reason, ...rest } = data.store;
      if (rest.goal_outcome) goalOutcomes.set(rest.goal_outcome.session, rest.goal_outcome.outcome);
      if (marks) marks.rendering = true;
      const renderStarted = marks ? unlockNow() : null;
      render({ state, error, reason, ...rest });
      if (marks) {
        const renderEnded = unlockNow();
        unlockPageMarks = null;
        $('store').dataset.unlockPageTimings = JSON.stringify({
          press_to_store_ms: Math.round(received - marks.pressed),
          render_ms: Math.round(renderEnded - renderStarted),
          cards_ms: Math.round(marks.cards_ms), cards: marks.cards, card_nodes: marks.card_nodes,
        });
      }
    }
    else if (data.command_result) renderCommandResult(data.command_result);
    else if (Object.keys(data).length === 1 && typeof data.seed_backup_display === 'string') {
      if (document.visibilityState === 'hidden') { lock(); return; }
      clearWords();
      const list = document.createElement('ol');
      list.id = 'tau-seed-backup-words';
      for (const word of data.seed_backup_display.split(' ')) {
        const item = document.createElement('li');
        item.textContent = word;
        list.append(item);
      }
      $('seed-backup-words-slot').append(list);
    }
    else show('failed', `Harness failed: ${data.harness_error}`);
  };
  worker.onerror = (event) => {
    if (worker !== current) return;
    unlockPageMarks = null;
    current.terminate();
    clearWords();
    $('seed-backup-input').value = '';
    $('passphrase').value = $('confirm').value = '';
    render({ state: 'lost' });
    $('loading').hidden = false;
    setLoadingText('The app could not load. Reload this page to retry.');
    show('failed', `Harness lost: ${event.message ?? 'the worker did not load'}. Reload to reopen locked.`);
  };
};

// Retirement acknowledges only after a begun append and secret disposal finish.
const RETIRE_EXPLANATION_MS = 5000;
const lock = () => {
  const previous = worker;
  if (!previous) return;
  worker = undefined;
  clearWords();
  clearPocInputs();
  $('seed-backup-input').value = '';
  redisplay = false;
  $('passphrase').value = '';
  $('confirm').value = '';
  render({state: 'locking'});
  const timer = setTimeout(() => {
    if (!worker) $('store-explanation').textContent = 'Still locking while the worker finishes a write. You can reload or close the page to stop it and recover at the next unlock.';
  }, RETIRE_EXPLANATION_MS);
  previous.addEventListener('message', ({data}) => {
    if (data?.runtime_retired === true) {
      clearTimeout(timer);
      previous.terminate();
      start();
    }
  });
  previous.postMessage({retire_runtime: true});
};
const updateTaskPresence = () => worker?.postMessage({task_presence: {
  visible: document.visibilityState === 'visible', online: navigator.onLine,
}});
document.addEventListener('visibilitychange', () => {
  updateTaskPresence();
  const hidden = document.visibilityState === 'hidden';
  if (hidden) interruptFileDownloads();
  if (hidden && (taskDetails.size || deliveryDetails.entry.size || deliveryDetails.commands.size)) { clearDetails(); render(taskDetailsStore, true); }
  if (hidden && ceremony) { lock(); return; }
  worker?.postMessage({ lifecycle: hidden ? 'hidden' : 'visible' });
});
document.addEventListener('freeze', () => {
  worker?.postMessage({task_presence: {visible: false, online: navigator.onLine}});
  interruptFileDownloads();
  if (taskDetails.size || deliveryDetails.entry.size || deliveryDetails.commands.size) { clearDetails(); render(taskDetailsStore, true); }
  if (ceremony) { lock(); return; }
  suspended = true;
  worker?.postMessage({ lifecycle: 'freeze' });
});
document.addEventListener('resume', () => {
  updateTaskPresence();
  if (suspended) { suspended = false; worker?.postMessage({ lifecycle: 'resume' }); }
});
addEventListener('pagehide', lock);
addEventListener('online', updateTaskPresence);
addEventListener('offline', updateTaskPresence);
addEventListener('pageshow', (event) => {
  if (event.persisted) lock();
  updateTaskPresence();
});
$('lock').addEventListener('click', lock);

const send = (kind) => {
  if (kind === 'unlock') {
    unlockPageMarks = { pressed: unlockNow(), rendering: false, cards_ms: 0, cards: 0, card_nodes: 0 };
    delete $('store').dataset.unlockTimings;
    delete $('store').dataset.unlockWorkerTimings;
    delete $('store').dataset.unlockPageTimings;
  }
  const passphrase = $('passphrase');
  const confirm = $('confirm');
  const differ = kind === 'create' && passphrase.value !== '' && passphrase.value !== confirm.value;
  const bytes = differ ? null : new TextEncoder().encode(passphrase.value);
  passphrase.value = '';
  confirm.value = '';
  if (differ) {
    render({ state: 'none', error: 'The two passphrases differ.' });
    return;
  }
  // Ask within the Create/Unlock gesture, before posting the store operation.
  requestPersistence();
  render({ state: 'working' });
  const operation = kind === 'unlock' && redisplay ? 'seed_backup_redisplay' : kind;
  redisplay = false;
  worker.postMessage({ [operation]: bytes }, [bytes.buffer]);
};
$('create').addEventListener('click', () => send('create'));
$('unlock').addEventListener('click', () => send('unlock'));
$('passphrase').addEventListener('input', () => updateCreatePassphrase($('store').dataset.state));
$('passphrase').addEventListener('keydown', event => {
  if (event.key !== 'Enter' || event.isComposing) return;
  if (!$('unlock').hidden && !$('unlock').disabled) {
    event.preventDefault();
    $('unlock').click();
  } else if (!$('create').hidden) {
    event.preventDefault();
    if ($('passphrase').value !== '') $('confirm').focus();
  }
});
$('confirm').addEventListener('keydown', event => {
  if (event.key !== 'Enter' || event.isComposing || $('create').hidden || $('create').disabled) return;
  event.preventDefault();
  $('create').click();
});

$('redisplay').addEventListener('click', () => {
  lock();
  redisplay = true;
});
$('seed-backup-answer').addEventListener('click', () => {
  clearWords();
  worker.postMessage({ seed_backup_answer: true });
});
$('seed-backup-check').addEventListener('click', () => {
  const field = $('seed-backup-input');
  const bytes = new TextEncoder().encode(field.value);
  field.value = '';
  worker.postMessage({ seed_backup_reentry: bytes }, [bytes.buffer]);
});
$('seed-backup-skip').addEventListener('click', () => {
  $('seed-backup-input').value = '';
  worker.postMessage({ seed_backup_skip: true });
});

// STA-23: request on every load unless already granted, and again in Create/Unlock.
const persist = $('persist');
// Only the most recently started request may draw the line; an older answer arriving late is dropped.
let persistGeneration = 0;
// A refusal carries its own re-check: the press asks Chrome again inside the gesture, as Create and Unlock do.
const persistCheck = document.createElement('button');
persistCheck.type = 'button';
persistCheck.dataset.persistCheck = '';
persistCheck.textContent = 'Check again';
persistCheck.addEventListener('click', () => requestPersistence());
const renderPersistence = (generation, granted) => {
  if (generation !== persistGeneration) return;
  persist.dataset.state = granted ? 'granted' : 'refused';
  persist.textContent = granted
    ? "Chrome has agreed to keep Farseed's data on this phone. It can still be lost if the phone is lost or reset, or its browser data is cleared."
    : "Chrome hasn't promised to keep Farseed's data on this phone. If the phone runs short of space, Chrome may delete it, and with it your AI credit and your provider account. Your machines would keep running, but this page could no longer reach them. Bookmark this page in Chrome, then press Check again: when we tested Chrome on Android, a bookmark was enough for it to agree to keep the data. ";
  if (!granted) persist.append(persistCheck);
  // A refusal stays visible in the store step (STA-23: visibly report a refusal); the granted line sits in Store options.
  const fold = $('step-store-fold');
  if (granted) fold.append(persist);
  else fold.after(persist);
};
const request = async () => {
  try {
    return (await navigator.storage.persisted()) || (await navigator.storage.persist());
  } catch {
    return false;
  }
};
const loadGeneration = ++persistGeneration;
request().then(granted => renderPersistence(loadGeneration, granted));
// Coming back to the page after a refusal (another app or tab, for example after bookmarking) asks again.
document.addEventListener('visibilitychange', () => {
  if (document.visibilityState !== 'visible' || persist.dataset.state !== 'refused') return;
  const generation = ++persistGeneration;
  request().then(granted => renderPersistence(generation, granted));
});
const requestPersistence = async () => {
  const generation = ++persistGeneration;
  let granted = false;
  try {
    // Do not await persisted() first: persist() must start in the gesture.
    granted = await navigator.storage.persist();
  } catch { /* An unavailable persistence API is also a refusal. */ }
  renderPersistence(generation, granted);
};

start();
