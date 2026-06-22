# Manuscript Writing Style Profile

Use this profile when editing mathematical papers or LaTeX manuscript prose.
On the remote host, also read `{{ HOME }}/.openclaw/workspace/data/writing-style.md`,
which is the canonical OpenClaw writing profile.

- Match the current manuscript first; keep prose simple, direct, and logically
  necessary.
- Open each section, except Introduction and Concluding Remarks, with a short
  outline paragraph saying what appears in the section, in order, and why those
  parts are needed.
- Do not put the role of a theorem, proposition, lemma, corollary, definition,
  or remark only in a short optional bracket title. Add one to three short
  sentences before the statement explaining informally what it says and how it
  is used in the proof.
- Begin every long, complicated, or important proof with a short strategy
  paragraph explaining the proof idea, such as the main induction, reduction,
  counting argument, case split, invariant, or obstruction mechanism. Vary
  nearby proof openings.
- In `.tex`, split if-and-only-if proofs into itemized `($\Rightarrow$)` and
  `($\Leftarrow$)` directions when this improves clarity.
- In `.tex`, list parallel proof cases with `itemize`.
- Use explicit case headings such as `Case 1`, `Case 2`, and so on. Put the
  heading in the item body, for example `\item \textbf{Case 1: ...}`, not in an
  optional `\item[...]` label.
- Use one emphasis style for case headings; prefer bold if the paper has no
  competing local convention.
- When a statement has many labelled conclusions, such as (a), (b), (c), and so
  on, use `\begin{enumerate}[a]` and `\end{enumerate}` from the `enumerate`
  package. Use the same `enumerate` structure in the proof for the corresponding
  parts.
- Define repeated concepts, invariants, and notation before repeated use,
  preferably in Preliminaries.
- Define local notation formally: state its domain, codomain when applicable,
  rule, and local scope.
- Use `\emph{...}` for the first introduction of important concepts in `.tex`.
- Prefer standard graph notation, including `\deg_G(v)` and `\Delta(G)`.
- Prefer established terminology from cited sources or standard frameworks over
  near-synonyms invented for the draft.
- Avoid imperative "Write ..."; use "Let", "Set", "Denote", or direct wording.
- Keep short, noncentral formulas inline; display only long or important
  formulas.
- Use `\displaystyle` in inline math only for tall or stacked operators such as
  `\frac`, `\binom`, `\sum`, `\prod`, `\bigcup`, and `\bigcap`; do not add it to
  ordinary inline formulas.
- Introduce named external results with the correct mathematical type at first
  use, then cite that introduction consistently later.
- Keep result summaries and table entries concise but self-contained. Do not
  list open cases unless the table is meant to track open problems.
- Explain coined names at first definition and avoid unnecessary new terms.
