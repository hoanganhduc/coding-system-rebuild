---
paths: ["**/*.tex", "**/*.bib", "**/*.sty", "**/*.cls"]
---

- Never break mid-sentence across lines in LaTeX source — wrap at sentence boundaries.
- Use \cref{} (cleveref) for cross-references, not \ref{}.
- BibTeX keys: use format `AuthorYear` (e.g., `Diestel2017`).
- Prefer \( \) and \[ \] for math in LaTeX source (note: this is LaTeX convention, distinct from the $$...$$ rule for Claude markdown output).
- Use \textbf{} and \textit{} over \bf and \it.
- When editing .bib files, preserve existing formatting and field order.
