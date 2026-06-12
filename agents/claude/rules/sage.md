---
paths: ["**/*.sage", "**/*.spyx"]
---

- SageMath runs in Docker via the skill runner: `bash ~/.claude/skills/_run.sh skills/sagemath/run_sage.sh "<code>"`
- Docker container: 3 CPUs, 16GB RAM, no network access.
- Use Sage-native types (Integer, Rational, Graph) over Python equivalents.
- For graph construction, prefer graphs.PetersenGraph() style named constructors when available.
- Use show() for interactive output, save() for file output.
- For parallel computation, use @parallel decorator over multiprocessing.
