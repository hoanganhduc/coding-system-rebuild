#!/usr/bin/env node
// Prompt injection guard — PreToolUse hook for Write/Edit
// Advisory-only: logs warnings, never blocks operations.
//
// Scans content being written for common injection patterns:
// - "ignore previous instructions" and variants
// - System/instruction XML tags
// - Invisible Unicode characters
// - BibTeX/LaTeX injection patterns (research-specific)

'use strict';

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

// --- Injection patterns ---
const PATTERNS = [
  // Classic prompt injection
  { regex: /ignore\s+(all\s+)?previous\s+instructions/i, label: 'ignore-previous-instructions' },
  { regex: /you\s+are\s+now\s+(a|an)\s+/i, label: 'role-override' },
  { regex: /act\s+as\s+(a|an|if)\s+/i, label: 'role-override' },
  { regex: /print\s+(your\s+)?system\s+prompt/i, label: 'system-prompt-extraction' },
  { regex: /reveal\s+(your\s+)?system\s+prompt/i, label: 'system-prompt-extraction' },
  { regex: /disregard\s+(all\s+)?prior/i, label: 'ignore-prior' },
  { regex: /forget\s+(all\s+)?previous/i, label: 'forget-previous' },
  { regex: /new\s+instructions?\s*:/i, label: 'instruction-override' },
  { regex: /override\s+(all\s+)?instructions/i, label: 'instruction-override' },

  // XML/tag injection
  { regex: /<system>/i, label: 'system-tag' },
  { regex: /<\/system>/i, label: 'system-tag-close' },
  { regex: /\[INST\]/i, label: 'inst-tag' },
  { regex: /<<SYS>>/i, label: 'llama-sys-tag' },
  { regex: /<\|im_start\|>/i, label: 'chatml-tag' },
  { regex: /<\|endoftext\|>/i, label: 'endoftext-tag' },

  // Research-specific
  { regex: /\\input\{[^}]*\.\.\//i, label: 'latex-path-traversal' },
  { regex: /\\write18\{/i, label: 'latex-shell-escape' },
  { regex: /\\immediate\\write/i, label: 'latex-write-command' },
];

// Invisible Unicode patterns (zero-width chars, RTL overrides, etc.)
const INVISIBLE_REGEX = /[\u200B-\u200F\u2028-\u202F\u2060-\u206F\uFEFF\uFFF9-\uFFFB]/;

// --- Main ---
async function main() {
  let input = {};
  try {
    const raw = await readStdin(3000);
    if (raw.trim()) input = JSON.parse(raw);
  } catch {
    return; // Can't parse — exit silently
  }

  // Extract content being written
  const toolInput = input.tool_input || input.input || {};
  const content = toolInput.content || toolInput.new_string || '';
  const filePath = toolInput.file_path || '';

  if (!content) return;

  // Scan for patterns
  const findings = [];

  for (const p of PATTERNS) {
    if (p.regex.test(content)) {
      findings.push(p.label);
    }
  }

  if (INVISIBLE_REGEX.test(content)) {
    findings.push('invisible-unicode');
  }

  // Report findings (advisory only)
  if (findings.length > 0) {
    const unique = [...new Set(findings)];
    process.stdout.write(
      `<prompt-guard severity="advisory">` +
      `Potential injection patterns detected in content being written to ${filePath}: ` +
      `[${unique.join(', ')}]. ` +
      `Review the content source before proceeding. This is advisory — the operation is NOT blocked.` +
      `</prompt-guard>`
    );
  }

  // Always exit 0 — advisory only, never block
}

main().catch(() => process.exit(0));
