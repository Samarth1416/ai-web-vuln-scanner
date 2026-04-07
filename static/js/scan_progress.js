/**
 * scan_progress.js — CyberScan AI
 * Real-time SSE terminal animation for scan progress
 */

function startScan(token) {
  const termBody   = document.getElementById('termBody');
  const progBar    = document.getElementById('progBar');
  const progPct    = document.getElementById('progPct');
  const doneActns  = document.getElementById('doneActions');
  const resultsBtn = document.getElementById('resultsBtn');

  if (!termBody) return;

  // Progress mapping — each log message advances the bar
  let progress = 5;
  const PROGRESS_STEPS = {
    'Initialising':     15,
    'Target:':          20,
    'Crawling':         30,
    'SQL Injection':    50,
    'Cross-Site':       65,
    'Open Redirect':    78,
    'security headers': 90,
    'Scan complete':    100,
  };

  function addLine(text, cls = 'info') {
    const line = document.createElement('div');
    line.className = `t-line ${cls}`;
    line.textContent = text;
    termBody.appendChild(line);
    termBody.scrollTop = termBody.scrollHeight;
  }

  function classifyLine(text) {
    if (text.includes('[!]')) return 'warn';
    if (text.includes('[✓]')) return 'success';
    if (text.includes('error') || text.includes('Error')) return 'error';
    return 'info';
  }

  function updateProgress(text) {
    for (const [keyword, pct] of Object.entries(PROGRESS_STEPS)) {
      if (text.includes(keyword) && pct > progress) {
        progress = pct;
        progBar.style.width = progress + '%';
        progPct.textContent = progress + '%';
        break;
      }
    }
  }

  // Add blinking cursor
  const cursorLine = document.createElement('div');
  cursorLine.className = 't-line';
  cursorLine.innerHTML = '<span class="t-cursor"></span>';
  termBody.appendChild(cursorLine);

  // Connect SSE
  const source = new EventSource(`/scan/stream/${token}`);

  source.onmessage = (event) => {
    // Remove blinking cursor temporarily
    if (cursorLine.parentNode) cursorLine.remove();

    const text = event.data;
    addLine(text, classifyLine(text));
    updateProgress(text);

    // Re-append cursor
    termBody.appendChild(cursorLine);
    termBody.scrollTop = termBody.scrollHeight;
  };

  source.addEventListener('done', (event) => {
    source.close();
    cursorLine.remove();

    // Fill bar to 100%
    progBar.style.width = '100%';
    progPct.textContent = '100%';

    addLine('', 'info');
    addLine('[✓] Report generated. Redirecting...', 'success');

    // Show "View Report" button
    const doneToken = event.data;
    resultsBtn.href = `/results/${doneToken}`;
    doneActns.style.display = 'block';

    // Auto-redirect after 2s
    setTimeout(() => {
      window.location.href = `/results/${doneToken}`;
    }, 2000);
  });

  source.onerror = () => {
    source.close();
    addLine('[!] Connection lost. The scan may have completed.', 'error');
    cursorLine.remove();
  };
}
