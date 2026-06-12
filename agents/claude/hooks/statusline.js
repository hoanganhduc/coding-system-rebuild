#!/usr/bin/env node
// StatusLine hook — displays context usage bar, model, and session task
// Output goes to Claude Code's status bar at bottom of terminal.
//
// Input (stdin JSON): { session_id, cwd, ... }
// Output (stdout): formatted status line text
//
// Bridge file: /tmp/claude-ctx-<session_id>.json — consumed by context-monitor.js

'use strict';

const fs = require('fs');
const path = require('path');

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

// --- Context bar rendering ---
function contextBar(usedPct) {
  const segments = 10;
  const filled = Math.round((usedPct / 100) * segments);
  const empty = segments - filled;

  // Color thresholds (based on % used, not remaining)
  let color;
  if (usedPct < 50)      color = '\x1b[32m'; // green
  else if (usedPct < 65)  color = '\x1b[33m'; // yellow
  else if (usedPct < 80)  color = '\x1b[38;5;208m'; // orange
  else                     color = '\x1b[31m'; // red

  const reset = '\x1b[0m';
  const dim = '\x1b[2m';

  const bar = color + '\u2588'.repeat(filled) + dim + '\u2591'.repeat(empty) + reset;
  const pctStr = `${Math.round(usedPct)}%`;

  return `[${bar}] ${color}${pctStr}${reset}`;
}

// --- Read session title from activator's temp file ---
function getSessionTask(sessionId) {
  if (!sessionId) return '';
  const markerPath = `/tmp/.claude-session-titled-${sessionId}`;
  // The activator just touches this file; the title is in the hook output, not the file.
  // Read from a dedicated task file if we write one, otherwise return empty.
  const taskPath = `/tmp/.claude-task-${sessionId}`;
  try {
    return fs.readFileSync(taskPath, 'utf8').trim().slice(0, 40);
  } catch {
    return '';
  }
}

// --- Short model name ---
function shortModel(model) {
  if (!model) return '';
  if (model.includes('opus')) return 'Opus';
  if (model.includes('sonnet')) return 'Sonnet';
  if (model.includes('haiku')) return 'Haiku';
  // Trim version suffixes for brevity
  return model.replace(/^claude-/, '').replace(/-\d{8}$/, '').slice(0, 15);
}

// --- Write bridge file for context-monitor.js ---
function writeBridge(sessionId, metrics) {
  if (!sessionId) return;
  const bridgePath = `/tmp/claude-ctx-${sessionId}.json`;
  try {
    fs.writeFileSync(bridgePath, JSON.stringify({
      ...metrics,
      timestamp: Date.now(),
    }));
  } catch {
    // Non-critical — silently ignore
  }
}

// --- Main ---
async function main() {
  let input = {};
  try {
    const raw = await readStdin(500);
    if (raw.trim()) {
      input = JSON.parse(raw);
    }
  } catch {
    // Parse failure — proceed with empty input
  }

  const sessionId = input.session_id || '';
  const cwd = input.cwd || process.cwd();
  const model = input.model || process.env.CLAUDE_MODEL || '';

  // Context metrics — field names vary by Claude Code version
  const tokensUsed = input.tokens_used || input.tokensUsed || 0;
  const contextWindow = input.context_window || input.contextWindow || input.max_tokens || 0;

  // Build segments
  const parts = [];

  // Model
  const modelName = shortModel(model);
  if (modelName) {
    const dim = '\x1b[2m';
    const reset = '\x1b[0m';
    parts.push(`${dim}${modelName}${reset}`);
  }

  // Context bar (only if we have metrics)
  if (contextWindow > 0 && tokensUsed >= 0) {
    // Account for ~16.5% autocompact buffer
    const effectiveWindow = contextWindow * 0.835;
    const usedPct = Math.min(100, (tokensUsed / effectiveWindow) * 100);
    parts.push(contextBar(usedPct));

    // Write bridge for context-monitor. usedPct and remainingPct are
    // complementary (both relative to effectiveWindow) so downstream
    // consumers see a single consistent view.
    writeBridge(sessionId, {
      tokensUsed,
      contextWindow,
      effectiveWindow,
      usedPct,
      remaining: Math.max(0, effectiveWindow - tokensUsed),
      remainingPct: Math.max(0, 100 - usedPct),
    });
  }

  // Session task
  const task = getSessionTask(sessionId);
  if (task) {
    const dim = '\x1b[2m';
    const reset = '\x1b[0m';
    parts.push(`${dim}${task}${reset}`);
  }

  // CWD (short — just last 2 components)
  if (cwd) {
    const short = cwd.split(path.sep).slice(-2).join('/');
    const dim = '\x1b[2m';
    const reset = '\x1b[0m';
    parts.push(`${dim}${short}${reset}`);
  }

  // Output
  if (parts.length > 0) {
    process.stdout.write(parts.join('  '));
  }

  // Also log input to debug file (first 5 calls only, for schema discovery)
  const debugPath = `/tmp/claude-statusline-debug-${sessionId}.jsonl`;
  try {
    const stat = fs.statSync(debugPath).size;
    if (stat < 5000) {
      fs.appendFileSync(debugPath, JSON.stringify(input) + '\n');
    }
  } catch {
    try {
      fs.writeFileSync(debugPath, JSON.stringify(input) + '\n');
    } catch { /* ignore */ }
  }
}

main().catch(() => process.exit(0));
