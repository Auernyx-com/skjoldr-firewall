# Bastion-to-Skjoldr Gate Adapter

## Contract
- **ALLOW:** Skjoldr proceeds as normal.
- **PAUSE:** Skjoldr does nothing, exits non-zero, no firewall changes. Requires human correction.
- **DENY/unknown/missing:** Skjoldr refuses, logs, exits hard.
- **Emergency lockdown:** Only via SKJOLDR_EMERGENCY=FORTRESS or explicit operator command, never implicit.

## Usage
```
pwsh -NoProfile -ExecutionPolicy Bypass -File integrations/bastion/Invoke-BastionGate.ps1 -Decision <decision.json> -Skjoldr <SkjoldrFirewall.ps1> [<SkjoldrArgs>]
```

- To force lockdown: `SKJOLDR_EMERGENCY=FORTRESS` in the environment.

## Governance
- This adapter is a locked interface. Changes require explicit review.
- No implicit escalation from PAUSE to lockdown.
- Auditable, fail-closed, and human-bound.
