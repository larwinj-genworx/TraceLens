const state = {
  jobId: null,
  report: null,
  issues: [],
  activeFilter: 'all',
  eventSource: null,
  pollTimer: null,
  dockerStatus: {},
};

const elements = {
  reposInput: document.getElementById('reposInput'),
  runtimeToggle: document.getElementById('runtimeToggle'),
  llmToggle: document.getElementById('llmToggle'),
  timeoutInput: document.getElementById('timeoutInput'),
  runBtn: document.getElementById('runBtn'),
  clearBtn: document.getElementById('clearBtn'),
  jobStatus: document.getElementById('jobStatus'),
  eventsList: document.getElementById('eventsList'),
  scoreValue: document.getElementById('scoreValue'),
  criticalCount: document.getElementById('criticalCount'),
  highCount: document.getElementById('highCount'),
  mediumCount: document.getElementById('mediumCount'),
  issuesBody: document.getElementById('issuesBody'),
  assumptionsList: document.getElementById('assumptionsList'),
  rawJson: document.getElementById('rawJson'),
  copyJsonBtn: document.getElementById('copyJsonBtn'),
  filterButtons: Array.from(document.querySelectorAll('.filter-btn')),
  toast: document.getElementById('toast'),
  toastMessage: document.getElementById('toastMessage'),
  dockerStatusBody: document.getElementById('dockerStatusBody'),
  dockerStatusEmpty: document.getElementById('dockerStatusEmpty'),
};

const API_PREFIX_CANDIDATES = ['', '/api/v1'];

function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

async function apiFetch(path, options = {}) {
  let fallbackResponse = null;

  for (const prefix of API_PREFIX_CANDIDATES) {
    const url = `${prefix}${path}`;
    const response = await fetch(url, options);

    if (response.status !== 404) {
      return response;
    }

    fallbackResponse = response;
  }

  return fallbackResponse;
}

function getPayload() {
  const repos = elements.reposInput.value
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean);

  return {
    repos,
    enable_runtime: elements.runtimeToggle.checked,
    enable_llm_enhancement: elements.llmToggle.checked,
    runtime_timeout_seconds: Number(elements.timeoutInput.value || 240),
  };
}

function setJobStatus(text, tone = 'default') {
  elements.jobStatus.textContent = text;
  elements.jobStatus.className = 'text-sm';

  if (tone === 'ok') {
    elements.jobStatus.classList.add('text-brand-700', 'font-medium');
  } else if (tone === 'warn') {
    elements.jobStatus.classList.add('text-amber-700', 'font-medium');
  } else if (tone === 'error') {
    elements.jobStatus.classList.add('text-red-700', 'font-medium');
  } else {
    elements.jobStatus.classList.add('text-slate-600');
  }
}

function showToast(message, tone = 'success') {
  if (!elements.toast || !elements.toastMessage) {
    return;
  }

  elements.toastMessage.textContent = message;
  elements.toast.className = 'pointer-events-none fixed right-4 top-4 z-50 rounded-xl border bg-white px-4 py-3 text-sm font-medium shadow-lg';
  if (tone === 'success') {
    elements.toast.classList.add('border-brand-200', 'text-brand-700');
  } else if (tone === 'error') {
    elements.toast.classList.add('border-red-200', 'text-red-700');
  } else {
    elements.toast.classList.add('border-slate-200', 'text-slate-700');
  }

  elements.toast.classList.remove('hidden');
  window.setTimeout(() => {
    elements.toast.classList.add('hidden');
  }, 2800);
}

function appendEvent(event) {
  const li = document.createElement('li');
  li.className = 'rounded-lg border border-slate-200 bg-slate-50 p-2';

  const stage = escapeHtml(event.stage || 'stage');
  const message = escapeHtml(event.message || '');
  const timestamp = escapeHtml(event.timestamp || new Date().toISOString());
  const payloadPreview = event.payload ? escapeHtml(JSON.stringify(event.payload, null, 2)) : '';

  li.innerHTML = `
    <div class="flex items-center justify-between gap-3">
      <span class="font-semibold text-slate-800">${stage}</span>
      <span class="text-xs text-slate-500">${timestamp}</span>
    </div>
    <p class="mt-1 text-slate-700">${message}</p>
    ${payloadPreview ? `<pre class="mt-2 max-h-28 overflow-auto rounded bg-slate-100 p-2 text-xs text-slate-600">${payloadPreview}</pre>` : ''}
  `;

  elements.eventsList.prepend(li);

  if (event && event.payload && event.payload.service_status) {
    updateDockerStatus(event.payload.service_status);
  }
}

function resetVisualization() {
  state.report = null;
  state.issues = [];
  state.activeFilter = 'all';
  state.dockerStatus = {};

  elements.eventsList.innerHTML = '';
  elements.scoreValue.textContent = '-';
  elements.criticalCount.textContent = '0';
  elements.highCount.textContent = '0';
  elements.mediumCount.textContent = '0';
  elements.issuesBody.innerHTML = '';
  elements.assumptionsList.innerHTML = '';
  elements.rawJson.textContent = '{}';
  elements.dockerStatusBody.innerHTML = '';
  elements.dockerStatusEmpty.classList.remove('hidden');

  updateFilterButtons();
}

function severityBadgeClass(severity) {
  if (severity === 'critical') {
    return 'bg-red-100 text-red-700 border border-red-200';
  }
  if (severity === 'high') {
    return 'bg-amber-100 text-amber-700 border border-amber-200';
  }
  return 'bg-blue-100 text-blue-700 border border-blue-200';
}

function renderIssues() {
  const filtered = state.activeFilter === 'all'
    ? state.issues
    : state.issues.filter((issue) => issue.severity === state.activeFilter);

  if (!filtered.length) {
    elements.issuesBody.innerHTML = `
      <tr>
        <td colspan="7" class="py-6 text-center text-slate-500">No issues for selected filter.</td>
      </tr>
    `;
    return;
  }

  elements.issuesBody.innerHTML = filtered
    .map((issue) => {
      const endpoint = issue.endpoint ? escapeHtml(issue.endpoint) : '-';
      const location = issue.file ? `${escapeHtml(issue.file)}${issue.line ? `:${issue.line}` : ''}` : '-';
      return `
        <tr class="border-b border-slate-100 align-top">
          <td class="py-3 pr-3">
            <span class="inline-flex rounded-full px-2 py-1 text-xs font-semibold ${severityBadgeClass(issue.severity)}">${escapeHtml(issue.severity)}</span>
          </td>
          <td class="py-3 pr-3 font-medium text-slate-800">${escapeHtml(issue.type)}</td>
          <td class="py-3 pr-3 text-slate-700">${escapeHtml(issue.service)}</td>
          <td class="py-3 pr-3 text-slate-600">${endpoint}</td>
          <td class="py-3 pr-3 text-slate-600">${location}</td>
          <td class="py-3 pr-3 text-slate-700">
            <p>${escapeHtml(issue.description || '')}</p>
            <p class="mt-2 text-xs text-slate-500">Impact: ${escapeHtml(issue.impact || '')}</p>
          </td>
          <td class="py-3 pr-3 text-slate-700">
            <p>${escapeHtml(issue.fix || '')}</p>
            <details class="mt-2 text-xs">
              <summary class="cursor-pointer text-slate-500">Evidence</summary>
              <pre class="mt-1 max-h-32 overflow-auto rounded bg-slate-100 p-2">${escapeHtml(JSON.stringify(issue.evidence || {}, null, 2))}</pre>
            </details>
          </td>
        </tr>
      `;
    })
    .join('');
}

function statusBadgeClass(status) {
  const normalized = String(status || '').toLowerCase();
  if (normalized.includes('running') || normalized.includes('healthy') || normalized === 'up') {
    return 'bg-brand-100 text-brand-700 border border-brand-200';
  }
  if (normalized.includes('starting') || normalized.includes('created')) {
    return 'bg-amber-100 text-amber-700 border border-amber-200';
  }
  if (normalized.includes('exited') || normalized.includes('dead') || normalized.includes('error') || normalized.includes('unhealthy')) {
    return 'bg-red-100 text-red-700 border border-red-200';
  }
  return 'bg-slate-100 text-slate-700 border border-slate-200';
}

function updateDockerStatus(serviceStatus) {
  state.dockerStatus = { ...state.dockerStatus, ...serviceStatus };
  const entries = Object.entries(state.dockerStatus);
  if (!entries.length) {
    elements.dockerStatusBody.innerHTML = '';
    elements.dockerStatusEmpty.classList.remove('hidden');
    return;
  }

  elements.dockerStatusEmpty.classList.add('hidden');
  elements.dockerStatusBody.innerHTML = entries
    .map(([service, status]) => `
      <tr class="border-b border-slate-200 last:border-0">
        <td class="py-1 pr-2 font-medium text-slate-700">${escapeHtml(service)}</td>
        <td class="py-1">
          <span class="inline-flex rounded-full px-2 py-0.5 text-[11px] font-semibold ${statusBadgeClass(status)}">${escapeHtml(String(status))}</span>
        </td>
      </tr>
    `)
    .join('');
}

function renderAssumptions(assumptions) {
  if (!assumptions || !assumptions.length) {
    elements.assumptionsList.innerHTML = '<li class="text-slate-500">No assumptions reported.</li>';
    return;
  }

  elements.assumptionsList.innerHTML = assumptions
    .map((item) => `<li class="rounded-lg border border-slate-200 bg-slate-50 p-2">${escapeHtml(item)}</li>`)
    .join('');
}

function renderReport(report) {
  state.report = report;
  state.issues = Array.isArray(report.issues) ? report.issues : [];

  const summary = report.summary || {};
  elements.scoreValue.textContent = String(summary.score ?? '-');
  elements.criticalCount.textContent = String(summary.critical ?? 0);
  elements.highCount.textContent = String(summary.high ?? 0);
  elements.mediumCount.textContent = String(summary.medium ?? 0);

  renderAssumptions(report.assumptions || []);
  renderIssues();

  elements.rawJson.textContent = JSON.stringify(report, null, 2);
}

function updateFilterButtons() {
  for (const button of elements.filterButtons) {
    const isActive = button.dataset.filter === state.activeFilter;
    button.className = 'filter-btn rounded-lg border px-3 py-1.5 text-sm font-medium transition';

    if (isActive) {
      button.classList.add('border-brand-600', 'bg-brand-600', 'text-white');
    } else {
      button.classList.add('border-slate-300', 'text-slate-700', 'hover:bg-slate-50');
    }
  }
}

function closeStreams() {
  if (state.eventSource) {
    state.eventSource.close();
    state.eventSource = null;
  }
  if (state.pollTimer) {
    clearInterval(state.pollTimer);
    state.pollTimer = null;
  }
}

function startEventStream(jobId) {
  closeStreams();

  const source = new EventSource(`/analysis/jobs/${jobId}/events`);
  state.eventSource = source;

  source.onmessage = (event) => {
    try {
      const payload = JSON.parse(event.data);
      appendEvent(payload);

      if (payload.stage === 'failed') {
        setJobStatus('Analysis failed', 'error');
      }
      if (payload.stage === 'complete') {
        setJobStatus('Analysis complete', 'ok');
      }
    } catch (error) {
      appendEvent({ stage: 'parse_error', message: `Invalid event payload: ${error.message}` });
    }
  };

  source.onerror = () => {
    source.close();
  };
}

async function checkJob(jobId) {
  const response = await apiFetch(`/analysis/jobs/${jobId}`);
  if (!response.ok) {
    setJobStatus('Unable to fetch job status', 'error');
    return;
  }

  const job = await response.json();

  if (job.status === 'completed') {
    setJobStatus('Analysis complete', 'ok');
    closeStreams();
    if (job.result) {
      renderReport(job.result);
    }
    showToast('Report generated successfully.', 'success');
    elements.runBtn.disabled = false;
    elements.runBtn.textContent = 'Run Analysis';
  } else if (job.status === 'failed') {
    setJobStatus(`Failed: ${job.error || 'Unknown error'}`, 'error');
    showToast('Analysis failed. See runtime details.', 'error');
    closeStreams();
    elements.runBtn.disabled = false;
    elements.runBtn.textContent = 'Run Analysis';
  } else {
    setJobStatus(`Running (job ${job.id.slice(0, 8)})`, 'warn');
  }
}

async function runAnalysis() {
  const payload = getPayload();

  if (!payload.repos.length) {
    setJobStatus('Add at least one repository URL', 'error');
    return;
  }

  resetVisualization();
  elements.runBtn.disabled = true;
  elements.runBtn.textContent = 'Running...';

  setJobStatus('Submitting analysis request...', 'warn');

  const response = await apiFetch('/analysis/async', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    const err = await response.text();
    setJobStatus(`Request failed: ${err}`, 'error');
    elements.runBtn.disabled = false;
    elements.runBtn.textContent = 'Run Analysis';
    return;
  }

  const data = await response.json();
  state.jobId = data.job_id;
  appendEvent({ stage: 'job_created', message: `Job ${state.jobId} created` });
  setJobStatus(`Running (job ${state.jobId.slice(0, 8)})`, 'warn');

  startEventStream(state.jobId);

  state.pollTimer = setInterval(() => {
    checkJob(state.jobId).catch((error) => {
      setJobStatus(`Polling error: ${error.message}`, 'error');
    });
  }, 2000);

  await checkJob(state.jobId);
}

function clearAll() {
  closeStreams();
  state.jobId = null;
  resetVisualization();
  setJobStatus('Idle');
  elements.runBtn.disabled = false;
  elements.runBtn.textContent = 'Run Analysis';
}

elements.runBtn.addEventListener('click', () => {
  runAnalysis().catch((error) => {
    setJobStatus(`Unexpected error: ${error.message}`, 'error');
    elements.runBtn.disabled = false;
    elements.runBtn.textContent = 'Run Analysis';
  });
});

elements.clearBtn.addEventListener('click', clearAll);

elements.copyJsonBtn.addEventListener('click', async () => {
  try {
    await navigator.clipboard.writeText(elements.rawJson.textContent || '{}');
    setJobStatus('Raw JSON copied to clipboard', 'ok');
  } catch {
    setJobStatus('Clipboard copy failed', 'error');
  }
});

for (const button of elements.filterButtons) {
  button.addEventListener('click', () => {
    state.activeFilter = button.dataset.filter || 'all';
    updateFilterButtons();
    renderIssues();
  });
}

clearAll();
updateFilterButtons();
