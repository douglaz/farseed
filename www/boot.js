// The page sends passphrase and re-entry bytes once and clears fields immediately. The only
// mnemonic display is the dedicated seed-backup ceremony; lock removes its words and inputs.
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
  $('defaults-status').textContent = 'Deployment defaults loaded. Public fields remain editable; review and approval use the displayed values.';
};
const defaultsReady = loadDefaults();

const texts = {
  starting: 'Opening the local store…',
  working: 'Working…',
  'in-use': 'Waiting for the local store: another tab, or this page\'s previous harness worker, still holds it.',
  none: 'There is no local store yet.',
  locked: 'The local store is locked.',
  locking: 'Locking: waiting for the worker to finish any begun write and clear working secrets…',
  unlocked: 'The local store is unlocked.',
};
const clearWords = () => $('seed-backup-words-slot').replaceChildren();
let redisplay = false;
let ceremony = false;
let suspended = false;
const goalOutcomes = new Map();
const creditGoalDrafts = new Map();
const setupDrafts = new Map();
const startDrafts = new Map();
const taskLimitDrafts = new Map();
let pocKeyRefusal = '';
const snapshotWorker = () => {
  const current = worker;
  const generation = current?.generation;
  return { postMessage: (data, transfer) => current?.sendAt ? current.sendAt(data, transfer, generation) : current?.postMessage(data, transfer) };
};
const readinessWait = store => ({starting:'The provider is starting the machine.',published_key:'The machine’s published host key has not appeared yet.',address:'Waiting for one allocated IPv4 address.',refused:'The machine check could not finish. Open Details to review what happened.',ready:'Saving the machine for setup.',checking:'Checking whether the machine is ready.'}[store.readiness?.kind ?? 'checking'] ?? 'The machine’s status is unavailable.');
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
    credit: store.credit_error || store.credit?.balance_text || (!store.credit?.account ? 'No inference credit yet.' : 'Inference credit balance not read yet.'),
    machine: store.readiness?.expired ? 'Published host-key wait expired after three hours. First contact is stopped.'
      : store.readiness?.inactive ? 'Machine checks are paused. Open the machine step for details.'
      : payReadiness(store.procurement ?? {}) ? `${readinessWait(store)} ${store.readiness?.checked_at ? `Last check: ${new Date(store.readiness.checked_at).toISOString()}.` : 'The machine has not been checked yet.'}`
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
    $(`step-${name}-fold`).open = foldChoices.get(name) ?? current === name;
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
  const machineAction = !store.provider_configuration?.key_set ? $('provider-catalogue')
    : purchase?.phase === 'initial_invoice' ? $('provider-invoice')
    : purchase?.phase && !['terms_changed', 'handed_off'].includes(purchase.phase) ? $('provider-resume')
    : purchase?.selection ? $('provider-approval-form').querySelector('button')
    : providerCatalogue ? $('provider-selection-form').querySelector('button') : $('provider-catalogue');
  emphasize('machine', [machineAction, $('setup-approve')]);
  const taskControls = selector => [...document.querySelector('[data-step="task"]').querySelectorAll(selector)];
  const needsDeclaration = (store.setup ?? []).some(machine => !machine.declaration);
  emphasize('task', [
    ...taskControls('[data-verify-clock]'),
    ...taskControls('[data-requirements-decision="approve"]'),
    ...(needsDeclaration ? taskControls('[data-poc-propose]') : []),
    ...taskControls('[data-task] button').filter(button => button.textContent === 'Resume'),
    ...taskControls('[data-start-accepted-goal], [data-goal-enter], [data-bind]'),
    ...taskControls('#tau-poc-targets button').filter(button => button.textContent.startsWith('Start session ') &&
      !sessions.some(session => session.bound_set.some(machine => button.textContent === `Start session ${machine}`))),
    ...taskControls('[data-poc-propose], [data-end-session], [data-delivery-check], [data-task] button, #tau-poc-targets button'),
  ]);
  restoreMainActions(retained);
};
let renderedReport;
const render = (store) => {
  const { payment_timer, ...content } = store;
  const report = JSON.stringify(content);
  if (payment_timer === true && report === renderedReport && !store.error && !store.credit_error) return;
  renderedReport = report;
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
  $('session-controls').replaceChildren();
  renderSetup(store);
  renderPoc(store);
  renderTasks(store);
  $('store').dataset.state = state;
  $('store-state').textContent = texts[state] ?? state;
  $('store-explanation').textContent = state === 'refused'
    ? `The local store is refused: ${store.reason}. Reload the page to try again.` : '';
  if (store.lifecycle_state) $('store-state').textContent += ` Session state: ${store.lifecycle_state}.`;
  $('create-help').hidden = $('confirm-field').hidden = $('create').hidden = state !== 'none';
  $('passphrase-field').hidden = state !== 'none' && state !== 'locked';
  $('passphrase').autocomplete = state === 'none' ? 'new-password' : 'current-password';
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
    ? ['Seed-backup ceremony.', store.seed_backup_owed
      ? 'New machines, relay passes and handoffs are refused until the seed backup is recorded.'
      : stage !== 'append_failed' && 'Re-display: record a new full re-entry or skip.',
    'Dispatch is stopped.', store.error].filter(Boolean).join(' ')
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
  const record = parent.closest('[data-machine], [data-task], [data-delivery-card], [id]');
  details.dataset.foldKey = JSON.stringify([identity ?? (record ? [...record.attributes]
    .filter(attribute => ['id', 'data-machine', 'data-task', 'data-delivery-card'].includes(attribute.name))
    .map(attribute => [attribute.name, attribute.value]) : []), value]);
  const summary = document.createElement('summary'); summary.textContent = 'Details';
  const text = document.createElement('pre'); text.dataset.rawJson = ''; text.textContent = JSON.stringify(value, null, 2);
  details.append(summary, text); parent.append(details);
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
    apt: ['update', 'upgrade', 'install', 'remove', 'purge', 'show', 'list'],
    'apt-get': ['update', 'upgrade', 'install', 'remove', 'purge'],
    dnf: ['update', 'upgrade', 'install', 'remove', 'info', 'list'],
    yum: ['update', 'upgrade', 'install', 'remove', 'info', 'list'],
  };
  const word = !/[|;&<>()`$\\\r\n]/.test(text) && Object.hasOwn(words, program) && words[program].includes(first) ? ` ${first}` : '';
  return shortLine(`${program}${word} …`);
};
const awaitingAiKey = task => task?.proposal?.tool?.name === 'request_ai_key' && !task.ai_key_approved && !task.pending && !['complete', 'abandoned'].includes(task.status);
const taskStatus = (status, task) => awaitingAiKey(task) ? 'waiting for you' : ({running:'working', waiting:'waiting for the machine', verifying:'checking the result', paused:'paused', complete:'done', abandoned:'stopped'})[status] ?? status;
const purchaseStatus = purchase => ({
  approved: 'Purchase approved; preparing access to the machine.',
  registration_uncertain: 'Waiting to confirm that the provider saved the access key. The page will check before continuing.',
  registered: 'Access key saved; preparing the machine order.',
  create_uncertain: 'Waiting to confirm the machine order. The page will check before continuing.',
  initial_invoice: 'Machine ordered; review the invoice before paying.',
  invoice_uncertain: 'Waiting to confirm the invoice. The page will check before continuing.',
  payment_readiness: purchase.payment?.is_paid ? 'Payment received; the provider is starting the machine.' : 'Waiting for payment of the machine invoice.',
  handed_off: 'Machine ready.',
  terms_changed: 'The price or setup changed. Review the updated plan before approving it.'
})[purchase.phase] ?? 'Purchase status is unavailable. Open Details for the saved information.';
const workBoundReason = 'protected output withheld: protection work bound exceeded';
const pauseMessages = new Map();
const pauseGroup = (reasons, message) => reasons.forEach(reason => pauseMessages.set(reason, message));
pauseGroup([workBoundReason], 'The page stopped because checking the task’s history for secrets got too large. Resume may need several tries. If it keeps stopping here, Stop task ends it.');
pauseGroup(['unknown task', 'stale or ended task', 'task ended'], 'This task is no longer available to continue. Review its saved details.');
pauseGroup(['task encoding', 'task credential boundary', 'task result encoding', 'task result publication'], 'The page could not safely read or show this task. Unlock again; if it stays paused, keep the saved details for help.');
pauseGroup(['protected output withheld: value depth exceeded', 'protected output withheld: encoding depth exceeded', 'protected output unavailable', 'inference protected field name invalid', 'inference output withheld after protected field collision', 'inference output escaped fragment count exceeds the local bound', 'scan length', 'scan marker contains protected material; output withheld', 'output hex', 'job output hex', 'output key collision after protection', 'redaction marker cannot exclude held credentials'], 'The page could not safely check the result for secrets, so it was withheld. Unlock again; if it stays paused, keep the saved details for help.');
pauseGroup(['required scan material unavailable; output withheld', 'session credential has no response scan representation', 'held credential derivation refused', 'required scan material unavailable', 'invalid scan envelope', 'scan envelope encoding', 'noncanonical scan envelope', 'invalid scan ciphertext', 'noncanonical scan ciphertext', 'scan authentication failed', 'invalid scan material', 'scan material encoding', 'noncanonical or unsupported scan material', 'scan identity is not awaiting material'], 'Information needed to check results for secrets is unavailable or unreadable. Unlock again and resupply any requested keys before Resume.');
pauseGroup(['locked', 'response requires an unlocked seed'], 'The page is locked. Unlock it to continue.');
pauseGroup(['missing pending job', 'missing pending identity', 'task has no pending job', 'no committed job evidence', 'job outcome is not trustworthy', 'pending task has no proposal', 'missing job exit', 'missing verification record', 'verification job mismatch'], 'The page cannot establish what happened to the earlier command. Review the saved details before deciding how to continue.');
pauseGroup(['resolved target differs from task machine', 'fresh authority must bind only the task machine'], 'The connection points to a different machine. Restore the original machine connection before Resume.');
pauseGroup(['resolved relay, host and user are required before Resume'], 'The machine connection is incomplete. Supply its relay, address and login name before Resume.');
pauseGroup(['trusted host pin missing; configure it before Resume'], 'The machine’s trusted host key is missing. Configure it before Resume.');
pauseGroup(['committed job record differs from its intent and cannot checkpoint; pending identity retained for inspection; to configure, Stop task; remote effects and command holds remain'], 'The saved result does not match the command that was sent. Review Details and use Stop task before changing the setup. Earlier commands may still run.');
pauseGroup(['session authority belongs to another task; use the task’s original session'], 'This connection belongs to a different task. Restore this task’s original session before Resume.');
pauseGroup(['proposal approval pending; review the open requirements card and approve explicitly or reject before Resume'], 'The proposed requirements need your decision. Review the requirements card and approve or reject it before Resume.');
pauseGroup(['original session requires acceptance of Acting on a goal with no brief'], 'This session still needs your approval to act on a goal without a brief. Review and accept that choice before Resume.');
pauseGroup(['sessions ended', 'no live session', 'session ended', 'goal requires a live session'], 'The session has ended or is unavailable. This task needs its original active session to continue.');
pauseGroup(['reconciliation or verification required after suspension'], 'The page must check the saved session after the interruption. Unlock again before Resume.');
pauseGroup(['session cap exhausted'], 'The session’s spending limit has been reached. Review its budget before continuing.');
pauseGroup(['session expired'], 'The session has expired. Review the session controls before continuing.');
pauseGroup(['incompatible issuer usage', 'incompatible or missing issuer acceptance'], 'The saved spending approval cannot be used. Review the session’s spending approval before continuing.');
pauseGroup(['clock uncertain; verification required', 'clock evidence out of range'], 'The page cannot rely on its clock. Use the clock check before Resume.');
pauseGroup(['invalid spend', 'invalid spend exponent', 'invalid nonnegative spend', 'spend scale', 'unsupported spend precision'], 'The page could not read the spending amount safely. Review the saved details before continuing.');
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
    return pauseMessages.get(cause) ?? 'The browser could not safely save the result. Reopen and unlock this page before Resume; the earlier command will be checked without running it twice.';
  }
  if (pauseMessages.has(reason)) return pauseMessages.get(reason);
  if (/^collection returned no outcome for pending call \d+ job [0-9a-f]+; pending identity retained$/.test(reason)) return 'The earlier command’s result is not available yet. Resume checks it again without running it twice.';
  if (/^collection record identity mismatch for pending call \d+ job [0-9a-f]+; pending identity retained$/.test(reason)) return 'The returned result does not match the earlier command. Review Details before Resume; the command will not be run twice.';
  if (/^collection (?:failed for pending call|failed for pending call \d+ job|.* for pending call) /.test(reason)) return 'The page could not establish the earlier command’s result. Review Details and check the connection before Resume; the command will not be run twice.';
  if (reason.startsWith('scan nonce: ')) return 'The saved information needed to check for secrets is unreadable. Unlock again and resupply any requested keys before Resume.';
  return reason;
};
const sessionWait = reason => {
  if (reason === 'Inference key required for another request; existing job collection remains available.') return 'Resupply the AI connection key to continue. The page can still collect the earlier command’s result.';
  if (reason === 'Automatic inference waits for the admitted endpoint and model. Restore them, or explicitly Resume with the displayed configuration. Existing job collection remains available.') return 'Restore the earlier AI connection settings, or use Resume to approve the settings shown here. The page can still collect the earlier command’s result.';
  const plain = plainPause(reason);
  return plain !== reason ? plain : 'This session needs a check before more work can run. Review Details and unlock again.';
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
    : report.exit_status === 0 ? 'passed' : `failed (exit ${report.exit_status})`;
  paragraph(parent, `${commandSummary(report.command)} — ${result}`);
  rawDetails(parent, report);
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
  paragraph(parent, 'Completion means Delivered (service and TCP checks only). Differences leave the task paused as Handed over with findings. Incomplete reads leave Findings unknown until a complete re-check.');
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
  paragraph(facts, purchase ? 'The purchase card records the approved billing interval and currency. App Lock and Stop task do not cancel the VM or its billing. Payment remains external, and this page does not change automatic renewal.' : "Recurring means each machine is billed by its vendor every month from the moment it is created until it is destroyed or abandoned, whether or not setup finishes. tau-web never pays for a machine and cannot stop a vendor's billing; only you can.");
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
    for (const ended of (store.sessions ?? []).filter(s => s.session_state === 'ended' && s.bound_set.includes(machine.entry.machine))) {
      paragraph(section, 'An earlier session ended. Its approvals can no longer be used.');
      rawDetails(section, ended, ['ended-session', ended.identity]);
    }
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
const fileKey = (task, offer) => JSON.stringify([task, offer]);
const updateFileRow = (row, task, file) => {
  const state = fileDownloads.get(fileKey(task, file.id));
  const button = row.querySelector('[data-file-download]');
  button.disabled = !!state?.pending;
  button.textContent = state?.pending ? `Downloading ${file.label}…` : state?.error ? `Retry download ${file.label}` : `Download ${file.label}`;
  row.querySelector('[data-file-error]')?.remove();
  if (state?.error) {
    const error = paragraph(row, state.error === 'too-large' ? `${file.label} is larger than 1 MiB; it wasn't downloaded.` : state.error);
    error.dataset.fileError = '';
  }
};
const interruptFileDownloads = () => {
  for (const [key, state] of fileDownloads) {
    if (!state.pending) continue;
    state.pending = false; state.error = 'The download was interrupted. Try again.';
    const [task, offer] = JSON.parse(key);
    const row = document.querySelector(`[data-task="${CSS.escape(task)}"] [data-file-offer="${CSS.escape(offer)}"]`);
    if (row) updateFileRow(row, task, state.file);
  }
};
const receiveFileDownload = (data, current) => {
  const key = fileKey(data.id, data.offer);
  const state = fileDownloads.get(key);
  try {
    if (worker !== current || data.generation !== current.generation || document.visibilityState === 'hidden' ||
        !state?.pending || state.request !== data.request) return;
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
    const row = document.querySelector(`[data-task="${CSS.escape(data.id)}"] [data-file-offer="${CSS.escape(data.offer)}"]`);
    if (row) updateFileRow(row, data.id, state.file);
  } catch {
    state.error = 'The download could not be saved. Try again.';
    state.pending = false;
    const row = document.querySelector(`[data-task="${CSS.escape(data.id)}"] [data-file-offer="${CSS.escape(data.offer)}"]`);
    if (row) updateFileRow(row, data.id, state.file);
  } finally {
    if (data.bytes instanceof Uint8Array) data.bytes.fill(0);
    delete data.bytes;
  }
};

const renderTasks = (store) => {
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
  for (const task of store.tasks ?? []) {
    const card = document.createElement('section');
    card.dataset.task = task.id;
    const session = (store.sessions ?? []).find(s => s.identity === task.start_session && s.session_state !== 'ended' && s.bound_set.length === 1 && s.bound_set[0] === task.machine);
    paragraph(card, `Setting up ${task.machine}: ${taskStatus(task.status, task)}.`);
    if (task.goal.length <= 120) paragraph(card, task.goal);
    else {
      const firstSentence = task.goal.match(/^.*?[.!?](?=\s|$)/s)?.[0] ?? task.goal;
      paragraph(card, shortLine(firstSentence, 120));
      rawDetails(card, {goal: task.goal}, ['task', task.id, 'goal']);
    }
    if (task.inference_retry) {
      paragraph(card, 'Waiting before trying the AI connection again.');
      rawDetails(card, {retry: task.inference_retry}, ['task', task.id, 'retry']);
    }
    paragraph(card, `${task.requests} of ${task.limits.requests} AI replies used; ${task.steps} of ${task.limits.steps} steps used.`);
    for (const [id, tool, outcome] of task.completed.filter(([id]) => !id.startsWith('$report:'))) {
      if (id.startsWith('$verify:') || tool.name === 'offer_file' && outcome.content?.status === 'offered') continue;
      if (tool.name === 'request_ai_key') {
        const created = outcome?.content?.status === 'created';
        const declined = outcome?.content?.status === 'declined';
        const application = shortLine(tool.arguments.application, 64);
        const line = paragraph(card, created ? `Created an AI key for ${application} on this machine (limit 0.25 USD, expires in 30 days)` : declined ? `Didn't create an AI key for ${application}.` : `Couldn't create an AI key: ${shortLine(outcome?.content?.reason ?? 'the outcome is unavailable', 160)}.`);
        line.dataset[created ? 'aiKeyCreated' : declined ? 'aiKeyDeclined' : 'aiKeyFailed'] = '';
      } else paragraph(card, id.startsWith('$before:') ? 'Read the listening ports before setup.' : tool.name === 'exec' ? `Ran: ${commandSummary(tool.arguments.command)} (${commandResultWord(outcome)})` : tool.name === 'propose_declaration' ? 'The AI proposed requirements.' : tool.name === 'done' ? 'The AI handed the work over for checks.' : 'Completed a step.');
      const machineKey = tool.name === 'request_ai_key' ? (store.poc_targets ?? []).find(target => target.machine === task.machine)?.application_inference_keys?.find(key => key.path === outcome?.content?.path) : undefined;
      rawDetails(card, {tool: tool.name === 'done' ? {name: tool.name, arguments: {machine: tool.arguments.machine}} : tool, outcome, ...(machineKey ? {application_inference_key: machineKey} : {})}, ['task', task.id, 'completed', id]);
    }
    for (const file of task.file_offers ?? []) {
      const row = document.createElement('div'); row.dataset.fileOffer = file.id;
      const button = document.createElement('button'); button.type = 'button'; button.dataset.fileDownload = file.id;
      button.addEventListener('click', () => {
        const key = fileKey(task.id, file.id);
        if (fileDownloads.get(key)?.pending) return;
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
      if (awaitingAiKey(task)) {
        const requestCard = document.createElement('section');
        requestCard.dataset.aiKeyRequest = '';
        paragraph(requestCard, `Create an AI key for ${shortLine(task.proposal.tool.arguments.application, 64)} on this machine (limit 0.25 USD, expires in 30 days)?`);
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
      } else paragraph(card, task.proposal.call_id.startsWith('$before:') ? 'Next: read the listening ports before setup.' : task.proposal.call_id.startsWith('$verify:') ? 'Next: check the machine setup.' : task.proposal.tool.name === 'exec' ? `Next: ${commandSummary(task.proposal.tool.arguments.command)}` : task.proposal.tool.name === 'propose_declaration' ? 'Next: a requirements proposal from the AI.' : task.proposal.tool.name === 'done' ? 'Next: the handover from the AI.' : task.proposal.tool.name === 'request_ai_key' ? `Creating an AI key for ${shortLine(task.proposal.tool.arguments.application, 64)} and saving it on the machine.` : 'Next: a step.');
      rawDetails(card, task.proposal.tool, ['task', task.id, 'proposal', task.proposal.call_id]);
    }
    if (task.pending && task.proposal?.report == null) {
      paragraph(card, 'Waiting for the earlier command. Resume checks its result without running it twice.');
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
    if (task.verdict) paragraph(card, task.verdict);
    for (const finding of task.findings ?? []) {
      const service = finding.service?.name;
      paragraph(card, service ? `${service} does not match the approved setup.` : finding.field === 'inbound' ? 'The listening ports do not match the approved setup.' : 'A setup check found a difference or could not finish. Open Details to review it.');
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
    if (['complete', 'abandoned'].includes(task.status)) { slot.append(card); continue; }
    paragraph(card, 'If you close this page, work that can continue picks up after you unlock and resupply any requested key. The task keeps the same session, machine, approvals and limits. Use Resume if it stays paused.');
    const action = (text, request) => {
      const button = document.createElement('button');
      button.type = 'button'; button.textContent = text;
      button.addEventListener('click', () => { button.disabled = true; worker.postMessage({ task: { id: task.id, ...request } }); });
      card.append(button);
    };
    if (session && store.lifecycle_state !== 'ended' && !awaitingAiKey(task)) {
      action('Resume', { action: 'resume', session: session.identity });
    } else if ((store.sessions ?? []).some(s => s.identity === task.start_session && s.session_state === 'ended')) paragraph(card, 'This task’s session has ended. Its history stays here, but it cannot continue.');
    else if (!session) paragraph(card, 'Unlock to restore this task’s session.');
    if (session && task.verifying && task.status === 'paused' && !task.pending) {
      action('Prepare complete re-check', { action: 'retry-checks', session: session.identity });
    }
    if (session && store.lifecycle_state !== 'ended' && task.disposition_offer) {
      const offer = task.disposition_offer;
      const labels = {as_if_not_done: "Carry on as if it didn't run", as_if_done: 'Carry on as if it ran'};
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
        paragraph(confirmation, 'The AI may then run the same command again.');
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
    } else if (task.disposition_refusal) {
      paragraph(card, 'The page cannot accept a choice about the unknown result yet. Review Details before continuing.');
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

const renderDelivery = (section, machine, store) => {
  const worker = snapshotWorker();
  const delivery = (store.delivery ?? []).find(d => d.machine === machine);
  if (!delivery) return;
  const card = document.createElement('section');
  card.dataset.deliveryCard = machine;
  const heading = document.createElement('h3');
  heading.textContent = `Delivery for ${machine}`;
  card.append(heading);
  paragraph(card, delivery.fixture_limit);
  const verdict = document.createElement('p');
  verdict.dataset.deliveryVerdict = machine;
  verdict.textContent = delivery.verdict;
  if (delivery.verdict_is_historical && delivery.last_completed_check) paragraph(card, 'The last completed result is historical; a final demonstration is still needed.');
  card.append(verdict);
  paragraph(card, 'Delivered covers the declared machine state and the fixed lockdown checks.');
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
    paragraph(application, `${name} is an AI that acts on this server by itself. tau-web's promises cover what tau-web's AI does, not what ${name} does.`);
    paragraph(application, `It does not mean ${name} works`);
    card.append(application);
  }
  for (const session of delivery.subsequent_placement_sessions ?? []) paragraph(card, 'Placement since the last check in session ' + session + '; final lifecycle demonstration not supplied.');
  if (delivery.reports?.length) {
    paragraph(card, delivery.report_label);
    for (const [index, report] of delivery.reports.entries()) rawDetails(card, report, ['delivery', machine, 'report', index]);
  }
  const session = (store.sessions ?? []).find(s => s.session_state !== 'ended' && s.bound_set.includes(machine));
  if (session && session.inference_limits?.state !== 'clock-withheld') {
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
const invoiceControls = (parent, savedInvoice, expires) => {
  const wallet = document.createElement('a'); wallet.textContent = 'Open in wallet'; wallet.href = `lightning:${savedInvoice}`;
  const copy = document.createElement('button'); copy.type = 'button'; copy.textContent = 'Copy';
  copy.addEventListener('click', async () => {
    try { await navigator.clipboard.writeText(savedInvoice); copy.textContent = 'Copied'; }
    catch { copy.textContent = 'Copy unavailable'; }
  });
  const remaining = document.createElement('span'); remaining.dataset.invoiceExpires = String(expires);
  remaining.textContent = `${Math.max(0, Math.ceil((expires - Date.now() / 1000) / 60))} minutes left`;
  parent.append(wallet, ' ', copy, ' ', remaining);
};
let providerCloseState = {purchase: {}, enabled: false};
const updateProviderClose = () => {
  const {purchase, enabled} = providerCloseState;
  const closeEligible = Boolean(purchase.vm_id) && !purchase.target && (!purchase.payment || (purchase.payment.is_paid === false && Math.floor(Date.parse(purchase.payment.expires) / 1000) <= Math.floor(Date.now() / 1000)));
  $('provider-close').hidden = !closeEligible;
  $('provider-close').disabled = !enabled || !closeEligible;
};
setInterval(() => {
  for (const node of document.querySelectorAll('[data-invoice-expires]')) node.textContent = `${Math.max(0, Math.ceil((Number(node.dataset.invoiceExpires) - Date.now() / 1000) / 60))} minutes left`;
  updateProviderClose();
}, 1000);
const renderCredit = (store, enabled) => {
  const credit = store.credit;
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
    if (!['paid', 'seen'].includes(invoice.outcome)) invoiceControls(row, invoice.bolt11, invoice.expires_at);
    slot.append(row);
  }
};
$('credit-invoice').addEventListener('click', () => {
  $('credit-invoice').disabled = true;
  worker.postMessage({credit_request:{action:'invoice',amount:Number($('credit-amount').value)}});
});
$('credit-check').addEventListener('click', () => worker.postMessage({credit_request:{action:'check'}}));
$('credit-configure').addEventListener('click', () => worker.postMessage({credit_request:{action:'configure',endpoint:$('poc-endpoint').value,model:$('poc-model').value}}));

let providerCatalogue = null;
let providerCompletedMachine = null;
let providerSelectionDirty = true;
let providerReviewToken = null;
let providerDisplayedBilling = null;
let providerDisplayedSelection = null;
let providerDisplayedOrigin = null;
const providerRequest = action => worker.postMessage({provider_request: action});
const renderProvider = (store, enabled) => {
  const worker = snapshotWorker();
  const recorded = store.provider_configuration?.recorded === true;
  const account = store.provider_configuration?.account;
  $('provider-key-status').textContent = recorded
    ? (/^[0-9a-f]{64}$/.test(account ?? '') ? `Provider account public identity: ${account}` : 'Provider account recorded; public identity unavailable.')
    : 'The first provider action creates and keeps one provider account.';
  const fixed = recorded || Boolean(store.procurement?.phase || store.procurement?.closed);
  $('provider-key-form').hidden = fixed;
  $('provider-account-fixed').hidden = !fixed;
  const deployed = store.provider_configuration?.relay_deployed === true;
  $('provider-relay-guidance').textContent = deployed
    ? 'Registering the machine SSH public key with the provider does not enroll the relay. The deployment relay key is in use. You still need published pins and approvals for the goal, class, access and installation declaration.'
    : 'Registering the machine SSH public key with the provider does not enroll the relay. Before configuration, copy the separate relay public key and ask your relay operator to enroll it. You still need published pins and approvals for the goal, class, access and installation declaration.';
  $('relay-task-guidance').textContent = deployed
    ? 'After enrollment, configure inference, then press Start session for the displayed model and machine. Copy its public keys. Install the SSH line. The deployment relay key is in use.'
    : 'After enrollment, configure inference, then press Start session for the displayed model and machine. Copy its public keys. Install the SSH line and enroll the separate relay public key with the relay operator.';
  $('relay-deployment-status').textContent = deployed ? 'The deployment relay key is in use.' : 'No valid deployment relay key is loaded. The seed-derived relay key requires manual enrollment.';
  const purchase = store.procurement ?? {};
  const completedMachine = purchase.phase === 'handed_off' ? purchase.machine : purchase.completed?.at(-1)?.machine ?? null;
  if (providerCompletedMachine !== completedMachine) {
    providerCompletedMachine = completedMachine;
    providerCatalogue = null;
    providerSelectionDirty = true;
    $('provider-catalogue-view').replaceChildren();
    $('provider-offer').replaceChildren(new Option('Choose a fetched offer', ''));
    $('provider-image').replaceChildren(new Option('Choose a fetched image', ''));
    $('provider-machine').value = '';
    $('provider-class').value = '';
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
        const label = `${kind}: ${offer.name}; ${offer.region?.name}; ${kind === 'fixed' ? `${offer.cpu} CPU, ${offer.memory} memory bytes, ${offer.disk_size} disk bytes; ${terms.amount} ${terms.currency} smallest units; ` : 'choose resources and request price; '}${terms.interval_amount} ${terms.interval_type}${hourly ? ' — unsupported credit-only hourly plan' : ''}`;
        paragraph(catalogue, label);
        const option = new Option(label, `${kind}:${offer.id}`); option.disabled = hourly; offerSelect.add(option);
        if (kind === 'custom') { readableFacts(catalogue, offer); rawDetails(catalogue, offer); }
      }
    }
    const images = $('provider-image'); images.replaceChildren(new Option('Choose a fetched image', ''));
    for (const image of providerCatalogue.images) {
      const unsupported = image.encrypted || image.distribution !== 'archlinux' || (image.default_username && image.default_username !== 'arch');
      const label = `${image.distribution} ${image.flavour} ${image.version}${unsupported ? ' — unsupported (requires unencrypted Arch without console unlock)' : ''}`;
      const option = new Option(label, String(image.id)); option.disabled = unsupported; images.add(option);
    }
    providerSelectionDirty = true; $('provider-approve-charge').checked = false;
  }
  if (store.provider_selection_reviewed || renewal) providerSelectionDirty = false;
  const selection = $('provider-selection-view'); selection.replaceChildren();
  if (purchase.selection) {
    paragraph(selection, `Provider origin: ${purchase.origin}`);
    const c = purchase.selection.charge;
    paragraph(selection, `Recurring charge: ${c.amount} ${c.currency === 'BTC' ? 'millisats' : c.currency + ' cents'} per ${c.interval_amount} ${c.interval_type}. Tax and processing fee are shown on the initial invoice.`);
    const selected = purchase.selection;
    const resources = selected.resources ?? selected.offer;
    paragraph(selection, `${selected.offer.name}; ${selected.offer.region?.name ?? 'region not stated'}; ${selected.image.distribution} ${selected.image.flavour} ${selected.image.version}.`);
    paragraph(selection, `${resources.cpu} CPUs; ${resources.memory} bytes of memory; ${resources.disk_size ?? resources.disk} bytes of disk space.`);
    rawDetails(selection, purchase.selection, ['purchase', purchase.origin, purchase.account ?? null]);
  }
  const progress = $('provider-progress'); progress.replaceChildren();
  if (purchase.closed) {
    paragraph(progress, 'The provider no longer has the earlier machine or its payment records, and this purchase recorded no payment. You can approve a new purchase. If you paid, keep your proof of payment; these checks cannot establish whether you paid.');
    rawDetails(progress, {closed: purchase.closed}, ['purchase-closed']);
  }
  if (purchase.phase) {
    paragraph(progress, `${purchase.machine}: ${purchaseStatus(purchase)}`);
    rawDetails(progress, purchase, ['purchase-progress', purchase.machine]);
    paragraph(progress, `Machine provider: ${purchase.origin}`);
    paragraph(progress, `Automatic renewal: ${purchase.auto_renewal_enabled === true ? 'on' : purchase.auto_renewal_enabled === false ? 'off' : 'unknown'}. This page does not change it.`);
    if (purchase.billing) {
      const quote = purchase.billing.terms;
      paragraph(progress, `Initial Lightning quote: ${quote.amount}, plus tax ${quote.tax} and processing fee ${quote.processing_fee} (${quote.currency === 'BTC' ? 'millisats' : quote.currency + ' cents'}), covering ${quote.time} seconds. Review these terms before requesting the invoice. Refresh may update the quote.`);
    }
    if (purchase.payment) {
      const pay = purchase.payment;
      paragraph(progress, `Invoice ${pay.is_paid ? 'paid' : 'awaiting payment'}; expires ${pay.expires}. Amount ${pay.amount}, tax ${pay.tax}, processing fee ${pay.processing_fee} (${pay.currency === 'BTC' ? 'millisats' : pay.currency + ' cents'}).`);
      if (!pay.is_paid) {
        invoiceControls(progress, pay.data.lightning, Math.floor(Date.parse(pay.expires) / 1000));
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
        paragraph(progress, readiness?.checked_at ? `Last machine check: ${new Date(readiness.checked_at).toISOString()}.` : 'The machine has not been checked yet.');
      }
    }
    if (purchase.public_keys) {
      paragraph(progress, deployed ? 'Registering the machine SSH public key with the provider does not enroll the relay. The deployment relay key is in use.' : 'Registering the machine SSH public key with the provider does not enroll the relay. Copy the separate relay public key and ask your relay operator to enroll it before configuration.');
      paragraph(progress, deployed ? 'Deployment relay public key:' : 'Relay public key — enroll this separately with the relay operator:');
      const publicKey = document.createElement('pre'); publicKey.textContent = purchase.public_keys.relay_pubkey; progress.append(publicKey);
    }
    if (purchase.target) paragraph(progress, `The machine’s published host key is saved. Press Start session ${purchase.machine} below to continue setup.`);
  }
  for (const completed of purchase.completed ?? []) {
    paragraph(progress, `${completed.machine}: Purchase completed. Provider: ${completed.origin}. VM: ${completed.vm_id ?? 'unknown'}. Payment: ${completed.payment_id ?? 'none'} (${completed.is_paid ? 'paid' : 'not recorded as paid'}). Target saved: ${completed.target_saved ? 'yes' : 'no'}.`);
  }
  const canReview = !purchase.phase || ['approved', 'registered', 'terms_changed', 'handed_off'].includes(purchase.phase);
  for (const control of $('provider-selection-form').elements) control.disabled = !enabled || !canReview;
  for (const control of $('provider-approval-form').elements) control.disabled = !enabled || (Boolean(purchase.phase) && !renewal && purchase.phase !== 'handed_off') || providerSelectionDirty || !purchase.selection;
  if (renewal) {
    for (const name of ['provider-machine', 'provider-relay', 'provider-class']) $(name).disabled = true;
  }
  providerCloseState = {purchase, enabled};
  updateProviderClose();
  $('provider-resume').disabled = !enabled || !purchase.phase;
  $('provider-invoice').disabled = !enabled || purchase.phase !== 'initial_invoice' || !purchase.billing;
};
$('provider-key-form').addEventListener('submit', event => {
  event.preventDefault();
  const field = $('provider-key'), bytes = new TextEncoder().encode(field.value); field.value = '';
  const origin = $('provider-origin').value; $('provider-origin').value = '';
  try { worker.postMessage({provider_configure: {key: bytes, origin}}, [bytes.buffer]); }
  finally { if (bytes.byteLength) bytes.fill(0); }
});
$('provider-catalogue').addEventListener('click', () => providerRequest({action: 'catalogue'}));
$('provider-selection-form').addEventListener('input', () => {
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
$('provider-resume').addEventListener('click', () => providerRequest({action: 'resume'}));
$('provider-invoice').addEventListener('click', () => providerRequest({action: 'initial_invoice', billing: providerDisplayedBilling}));
const clearPocInputs = () => {
  rawFoldChoices.clear();
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
  creditGoalDrafts.clear();
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

const startInputs = (row, machine, initialGoal = '', documentSource = true, creditMode = false) => {
  const goal = document.createElement('textarea'); if (creditMode) goal.dataset.creditGoal = machine; goal.dataset.startGoal = machine;
  goal.setAttribute('aria-label', 'Goal before Start session'); goal.value = creditGoalDrafts.get(machine) ?? initialGoal;
  goal.addEventListener('input', () => creditGoalDrafts.set(machine, goal.value));
  const source = document.createElement('input'); source.type = 'url'; source.dataset.documentSource = '';
  source.setAttribute('aria-label', 'Optional document source (https URL)');
  source.value = startDrafts.get(machine)?.[1] ?? '';
  source.addEventListener('input', () => startDrafts.set(machine, ['', source.value]));
  paragraph(row, 'Acting on a goal with no brief');
  row.append(goal); if (documentSource) row.append(source);
  return () => ({goal:goal.value, document_source:source.value || null});
};

const renderPoc = (store) => {
  if (typeof store.credit_started_machine === 'string') creditGoalDrafts.delete(store.credit_started_machine);
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
  $('poc-key-status').textContent = store.poc_configuration?.key_set === true ? 'Key set.' : store.poc_configuration?.key_set === false ? 'Key unset.' : 'Key status unavailable.';
  if (['locked', 'none', 'refused', 'lost', 'starting'].includes(store.state) || store.lifecycle_state === 'ended') clearPocInputs();
  const targets = $('poc-targets');
  targets.replaceChildren();
  for (const target of store.poc_targets ?? []) {
    const row = document.createElement('section');
    paragraph(row, `${target.machine} is ready for setup.`);
    paragraph(row, `Connect to ${target.host} on port ${target.port} as ${target.user}. ${target.elevation === 'sudo -n' ? 'Commands can use administrator access without a password.' : target.elevation === 'none' ? 'Commands use this login’s normal access.' : 'Open Details for command access settings.'}`);
    paragraph(row, `Trusted machine host key: ${target.pin}`);
    rawDetails(row, target, ['target', target.machine]);
    const creditSession = (store.sessions ?? []).some(session => session.credit_backed && session.session_state !== 'ended' && (session.bound_set ?? []).includes(target.machine));
    const creditChoice = store.credit?.selected || !store.poc_configuration?.key_set;
    const readingCredit = store.credit?.account && store.credit.balance === null && !store.credit_error;
    const useCredit = creditSession || (creditChoice && Boolean(store.credit?.account));
    const configuration = document.createElement('p');
    if (useCredit) configuration.dataset.inferenceApproval = '';
    else configuration.textContent = `Inference endpoint: ${store.poc_configuration?.configuration?.endpoint ?? 'unavailable'}; model: ${store.poc_configuration?.configuration?.model ?? 'unavailable'}.`;
    row.append(configuration);
    paragraph(row, `Start session approves the selected AI connection for ${target.machine}.`);
    const inputs = startInputs(row, target.machine, '', !useCredit, useCredit);
    if (useCredit) {
      paragraph(row, store.credit.disclosure);
      if (readingCredit) paragraph(row, 'Reading AI credit balance…');
      else if (store.credit_error) paragraph(row, store.credit_error);
      else if (!store.credit.can_start) paragraph(row, store.credit.balance_text);
    }
    for (const [kind, label] of [['poc_bind', 'Start session'], ['poc_public_keys', 'Show public keys']]) {
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
      row.append(button);
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
  const bytes = new TextEncoder().encode(field.value);
  field.value = '';
  try {
    worker.postMessage({ poc_configure: {
      endpoint: $('poc-endpoint').value,
      model: $('poc-model').value,
      key: bytes,
    } }, [bytes.buffer]);
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

const start = () => {
  goalOutcomes.clear();
  show('starting', 'Starting the harness…');
  render({ state: 'starting' });
  suspended = false;
  ceremony = false;
  worker = new Worker(new URL('./worker.js', import.meta.url), { type: 'module' });
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
    try { nativePost({initialize: incarnation, deployment: {origin: material.provider_origin, key, public_fields: JSON.stringify(material.fields ?? {})}}, [key.buffer]); }
    finally { if (key.byteLength) key.fill(0); }
  });
  worker.onmessage = ({ data }) => {
    if (data.file_download) { receiveFileDownload(data.file_download, current); return; }
    if (worker !== current) return;
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
    if (data.harness_ready) show('ready', `Harness ready (spec ${data.harness_ready}).`);
    else if (data.store) {
      const { store_state: state, store_error: error, store_reason: reason, ...rest } = data.store;
      if (rest.goal_outcome) goalOutcomes.set(rest.goal_outcome.session, rest.goal_outcome.outcome);
      render({ state, error, reason, ...rest });
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
    current.terminate();
    clearWords();
    $('seed-backup-input').value = '';
    $('passphrase').value = $('confirm').value = '';
    render({ state: 'lost' });
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
document.addEventListener('visibilitychange', () => {
  const hidden = document.visibilityState === 'hidden';
  if (hidden) interruptFileDownloads();
  if (hidden && ceremony) { lock(); return; }
  worker?.postMessage({ lifecycle: hidden ? 'hidden' : 'visible' });
});
document.addEventListener('freeze', () => {
  interruptFileDownloads();
  if (ceremony) { lock(); return; }
  suspended = true;
  worker?.postMessage({ lifecycle: 'freeze' });
});
document.addEventListener('resume', () => {
  if (suspended) { suspended = false; worker?.postMessage({ lifecycle: 'resume' }); }
});
addEventListener('pagehide', lock);
addEventListener('pageshow', (event) => {
  if (event.persisted) lock();
});
$('lock').addEventListener('click', lock);

const send = (kind) => {
  const passphrase = $('passphrase');
  const confirm = $('confirm');
  const differ = kind === 'create' && passphrase.value !== confirm.value;
  const bytes = differ ? null : new TextEncoder().encode(passphrase.value);
  passphrase.value = '';
  confirm.value = '';
  if (differ) {
    render({ state: 'none', error: 'The two passphrases differ.' });
    return;
  }
  render({ state: 'working' });
  const operation = kind === 'unlock' && redisplay ? 'seed_backup_redisplay' : kind;
  redisplay = false;
  worker.postMessage({ [operation]: bytes }, [bytes.buffer]);
};
$('create').addEventListener('click', () => send('create'));
$('unlock').addEventListener('click', () => send('unlock'));

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

// STA-23: "The browser MUST request persistent storage and visibly report a refusal." Asked once
// per load, unless already granted.
const persist = $('persist');
const request = async () => {
  try {
    return (await navigator.storage.persisted()) || (await navigator.storage.persist());
  } catch {
    return false;
  }
};
request().then((granted) => {
  persist.dataset.state = granted ? 'granted' : 'refused';
  persist.textContent = `${granted
    ? 'Persistent storage is granted.'
    : 'Persistent storage: the browser refused the request.'} This is a request, not a guarantee: eviction, device loss or corruption can still lose the local store, so the seed backup and recovery remain necessary.`;
});

start();
