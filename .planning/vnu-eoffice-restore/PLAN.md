# VNU eOffice Restore Plan

1. Add the VNU package as a pinned rebuild component at the workspace-visible path.
2. Add a value-redacting credential bridge and cover its output in the secrets manifest.
3. Align live and source launcher defaults with the workspace checkout.
4. Run offline tests, rebuild verification, and a no-notification live network check.
