#!/usr/bin/env node
// Context exhaustion monitor — PostToolUse hook
// Reads bridge file from statusline.js, injects warnings at threshold levels.
//
// Thresholds: WARNING at ≤35% remaining, CRITICAL at ≤25% remaining
// Debounced: 5 tool uses between alerts (severity escalation bypasses)

'use strict';

const fs = require('fs');

// --- Configuration ---
const WARNING_THRESHOLD = 35;  // % remaining
const CRITICAL_THRESHOLD = 25; // % remaining
const DEBOUNCE_CALLS = 5;      // tool uses between alerts
const METRICS_MAX_AGE_MS = 60000; // ignore stale metrics (>60s)

// --- Read stdin with timeout ---
function readStdin(timeoutMs) {
  return new Promise((resolve) => {
    let data = '';
    const timer = setTimeout(() => {
      process.stdin.destroy();
      resolve(data);
    }, timeoutMs);

    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (chunk) => { data += chunk; });
    process.stdin.on('end', () => { clearTimeout(timer); resolve(data); });
    process.stdin.on('error', () => { clearTimeout(timer); resolve(data); });
  });
}

// --- Main ---
async function main() {
  let input = {};
  try {
    const raw = await readStdin(1000);
    if (raw.trim()) input = JSON.parse(raw);
  } catch {
    return; // Can't parse input — exit silently
  }

  const sessionId = input.session_id || '';
  if (!sessionId) return;

  // Security: reject path traversal in session ID
  if (sessionId.includes('/') || sessionId.includes('..')) return;

  // Read bridge file from statusline
  const bridgePath = `/tmp/claude-ctx-${sessionId}.json`;
  let metrics;
  try {
    const raw = fs.readFileSync(bridgePath, 'utf8');
    metrics = JSON.parse(raw);
  } catch {
    return; // No bridge file yet — statusline hasn't run
  }

  // Ignore stale metrics
  if (Date.now() - (metrics.timestamp || 0) > METRICS_MAX_AGE_MS) return;

  const remainingPct = metrics.remainingPct || 100;

  // Determine severity
  let severity = null;
  if (remainingPct <= CRITICAL_THRESHOLD) {
    severity = 'CRITICAL';
  } else if (remainingPct <= WARNING_THRESHOLD) {
    severity = 'WARNING';
  }

  if (!severity) return;

  // Debounce: track alert count per session
  const statePath = `/tmp/claude-ctx-alert-${sessionId}.json`;
  let state = { lastSeverity: null, callsSinceAlert: 0 };
  try {
    state = JSON.parse(fs.readFileSync(statePath, 'utf8'));
  } catch { /* first alert */ }

  state.callsSinceAlert = (state.callsSinceAlert || 0) + 1;

  // Allow alert if: first time, debounce expired, or severity escalated
  const severityEscalated = severity === 'CRITICAL' && state.lastSeverity === 'WARNING';
  const debounceExpired = state.callsSinceAlert >= DEBOUNCE_CALLS;

  if (!debounceExpired && !severityEscalated && state.lastSeverity) {
    // Update counter and exit
    try { fs.writeFileSync(statePath, JSON.stringify(state)); } catch {}
    return;
  }

  // Reset counter and emit alert
  state.callsSinceAlert = 0;
  state.lastSeverity = severity;
  try { fs.writeFileSync(statePath, JSON.stringify(state)); } catch {}

  const remaining = Math.round(remainingPct);
  const used = Math.round(metrics.usedPct || 0);

  if (severity === 'CRITICAL') {
    process.stdout.write(
      `<context-alert severity="CRITICAL">` +
      `Context nearly exhausted: ${remaining}% remaining (${used}% used). ` +
      `Consider: (1) /compact to free context, (2) save important state to files, ` +
      `(3) start a new session for remaining work.` +
      `</context-alert>`
    );
  } else {
    process.stdout.write(
      `<context-alert severity="WARNING">` +
      `Context usage high: ${remaining}% remaining (${used}% used). ` +
      `Plan to compact or wrap up current task soon.` +
      `</context-alert>`
    );
  }
}

main().catch(() => process.exit(0));
