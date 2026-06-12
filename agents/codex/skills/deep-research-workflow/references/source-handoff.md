# Source Handoff

Carry source information from search to analysis using a compact structure:

```text
source_id:
title:
url:
date:
source_type:
key_facts:
relevant_claims:
confidence:
```

Rules:

- keep one source record per distinct source
- link major claims back to source ids
- mark uncertainties instead of smoothing them away
