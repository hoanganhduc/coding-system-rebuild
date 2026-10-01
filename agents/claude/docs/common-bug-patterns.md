# Common Bug Patterns

Ordered by frequency. Covers ~80% of bugs across stacks.

## 1. Null/Undefined Access
- Accessing property of null/undefined return value
- Missing return statement → function returns None/undefined
- Destructuring null object
- Optional parameter without default

**Symptom**: `TypeError`, `AttributeError`, `NoneType has no attribute`

## 2. Off-by-One / Boundary
- Wrong loop bounds (< vs <=, range(n) vs range(n+1))
- Fence-post errors (n items → n-1 gaps)
- Inclusive vs exclusive range ends
- Empty collection not handled (len=0 edge case)

**Symptom**: missing first/last element, index out of range

## 3. Async / Timing
- Missing `await` on async call
- Race condition between concurrent operations
- Stale closure capturing old value
- Initialization order (using before ready)
- Leaked timers/intervals

**Symptom**: intermittent failures, undefined values, resource leaks

## 4. State Management
- Shared mutable state modified concurrently
- Stale state after update (reading old copy)
- Dual source of truth (two variables tracking same thing)
- Invalid state transition (e.g., "complete" before "started")

**Symptom**: inconsistent behavior, data corruption

## 5. Import / Module
- Circular dependency (A imports B imports A)
- Wrong export name (named vs default)
- Path case sensitivity (Linux vs Windows)
- Missing file extension in import

**Symptom**: `ImportError`, `ModuleNotFoundError`, undefined at import

## 6. Type / Coercion
- String vs number comparison (`"5" > "10"` is true in JS)
- Implicit type coercion (`0 == ""` is true)
- Floating point precision (`0.1 + 0.2 != 0.3`)
- Falsy valid values (0, empty string treated as missing)

**Symptom**: wrong comparisons, unexpected branch taken

## 7. Environment / Config
- Missing environment variable (undefined, not error)
- Hardcoded path that differs across systems
- Port conflict (another process using same port)
- Permission denied (file/directory not readable/writable)
- Missing dependency (package not installed)

**Symptom**: works on one machine, fails on another

## 8. Data Shape / API Contract
- API response shape changed (field renamed/removed)
- Wrong container type (list vs dict, array vs object)
- Missing required field in request/response
- Date format mismatch (ISO vs timestamp vs locale)
- Encoding mismatch (UTF-8 vs Latin-1)

**Symptom**: `KeyError`, unexpected None, garbled text

## 9. Regex / String
- Regex sticky `lastIndex` not reset between calls
- Missing escape for special chars (`.` matches anything)
- Greedy match consuming too much
- Wrong quote type in shell (single vs double)

**Symptom**: no match when expected, partial match, wrong capture

## 10. Error Handling
- Swallowed exception (empty `except:` / `catch {}`)
- Wrong error type caught (catching parent instead of specific)
- Error in error handler itself
- Unhandled promise rejection / uncaught async error

**Symptom**: silent failure, misleading error, crash in recovery

## 11. Scope / Closure
- Variable shadowing (inner scope hides outer)
- Loop variable captured by reference (all closures see final value)
- Lost `this`/`self` binding in callback
- Global vs local scope confusion

**Symptom**: all iterations show same value, method fails when passed as callback

---

## Research-Specific Patterns

### BibTeX
- Missing required fields (author, title, year for @article)
- Duplicate keys (silently uses last definition)
- Encoding issues in author names (UTF-8 vs LaTeX escapes)
- Mismatched braces in field values

### LaTeX
- Missing `\end{environment}` (error points to wrong line)
- Package conflict (two packages redefine same command)
- Float placement (`[h]` doesn't mean "here" — use `[htbp]`)
- Math mode escaping (`_` and `^` outside math)

### Zotero API
- Pagination (only 100 items per page — must paginate)
- Version conflicts (item modified since last read)
- Rate limiting (too many requests too fast)
- Key vs query confusion (`zot.sh get` takes query, not key)

### SageMath
- Integer overflow in combinatorial computation
- Graph isomorphism check is expensive (avoid in loops)
- `show()` blocks in non-interactive mode (use `print()`)
- Sage integers vs Python integers (mixing types)

---

## Symptom → Category Quick Reference

| Symptom | Check first |
|---------|------------|
| `TypeError` / `AttributeError` | #1 Null access |
| Off by one element | #2 Boundary |
| Intermittent / flaky | #3 Async |
| Works sometimes | #4 State |
| Import fails | #5 Module |
| Wrong comparison | #6 Type coercion |
| Works locally, fails remote | #7 Environment |
| `KeyError` on API response | #8 Data shape |
| Regex no match | #9 Regex |
| Silent failure | #10 Error handling |
| All same value in loop | #11 Scope |
