---
paths: ["**/*.py"]
---

- Use type hints on all function signatures and return types.
- Prefer dataclasses or NamedTuple over plain dicts for structured data.
- Use f-strings for string formatting, not .format() or %.
- Imports: stdlib first, then third-party, then local — separated by blank lines.
- Use pathlib.Path over os.path for file operations.
- Use `if __name__ == "__main__":` guard in scripts.
