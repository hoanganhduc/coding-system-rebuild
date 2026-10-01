# Manuscript Writing Style Adapter

Use this file only for manuscript and paper-editing tasks. It adapts the user's
mathematical writing preferences to DeepSeek TUI workflows. On the remote host,
also read `{{ HOME }}/.openclaw/workspace/data/writing-style.md`, which is
the canonical OpenClaw writing profile.

- Preserve the local style of the paper under edit.
- Prefer simple words, short transitions, and explicit logical roles.
- Remove redundant prose that does not support the argument.
- Make section openings state the sequence of material and its purpose.
- Explain the role of each statement before or near the statement.
- Start proofs with a proof strategy sentence and vary nearby proof openings.
- In `.tex`, split if-and-only-if proofs into itemized `($\Rightarrow$)` and
  `($\Leftarrow$)` directions when the split helps readability.
- In `.tex`, list proof cases with `itemize` when the cases are parallel.
- Use explicit case headings such as `Case 1`, `Case 2`, and so on. Put the
  heading in the item body, for example `\item \textbf{Case 1: ...}`, not in an
  optional `\item[...]` label.
- Use one emphasis style for case headings; prefer bold if the paper has no
  competing local convention.
- When a statement has many labelled conclusions, such as (a), (b), (c), and so
  on, use `\begin{enumerate}[a]` and `\end{enumerate}` from the `enumerate`
  package. Use the same `enumerate` structure in the proof for the corresponding
  parts.
- Define repeated notation and concepts before repeated use, preferably in
  Preliminaries.
- Define local notation formally before repeated use: state its domain,
  codomain when applicable, rule, and local scope.
- Use `\emph{...}` at the first introduction of important concepts.
- Prefer standard graph notation, including `\deg_G(v)` and `\Delta(G)`.
- Prefer established terminology from cited sources or standard frameworks over
  near-synonyms invented for the draft.
- Avoid "Write ..." as a proof command; prefer "Let", "Set", "Denote", or direct
  wording.
- Keep minor formulas inline in `.tex`; reserve display math for long or central
  formulas.
- Use `\displaystyle` in inline math only for tall or stacked operators such as
  `\frac`, `\binom`, `\sum`, `\prod`, `\bigcup`, and `\bigcap`; do not add it to
  ordinary inline formulas.
- Introduce named external results with the right result type at first use and
  refer back to that introduction later.
- Keep result summaries and table entries concise but self-contained. Do not
  list open cases unless the table is meant to track open problems.
- Explain coined terms when they are defined.
