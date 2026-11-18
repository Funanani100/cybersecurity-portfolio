# Windows Memory Forensics - Portfolio Case Study

> **Non-spoiler portfolio summary** · TryHackMe training exercise: **Day-O**  
> This document records the skills and analysis approach practised in the lab. Challenge-specific answers, indicators, commands, recovered secrets, and the flag are intentionally omitted while the room is treated as active.

## Overview

This case study documents a Windows memory-forensics investigation involving an application that exhibited suspicious runtime behaviour during a document-review workflow.

The goal was to practise evidence-led analysis of a preserved memory image: establish process context, investigate anomalous memory, correlate memory-resident content with related artefacts, examine code behaviour safely, and validate recovered data.

**Focus areas:** Windows memory forensics, suspicious memory analysis, x86 reverse engineering, API-call analysis, PowerShell inspection, and recovery of protected artefacts.

## Lab scope

- **Platform:** TryHackMe - Day-O
- **Category:** Memory forensics / malware analysis
- **Difficulty:** Medium
- **Environment:** Supplied Windows memory image analysed from a Linux analysis workstation
- **Authorisation:** Work was restricted to the challenge-provided evidence and lab environment.

No production systems or third-party systems were tested as part of this exercise.

## Tools used

| Tool | Use in the investigation |
|---|---|
| Volatility 3 | Windows memory-image triage, process inspection, memory-region analysis, handle inspection, and artefact recovery |
| Python 3.12 | Binary inspection, byte comparison, hashing, decoding, and archive validation |
| GNU `objdump` | Static disassembly of recovered x86 code |
| Speakeasy | Controlled emulation to corroborate observed API behaviour without directly executing the recovered sample on the host |
| PyCryptodome | Cryptographic analysis of recovered data within the isolated lab workflow |

Ghidra was available in the lab toolset but was not required for the analysis documented here.

## Analysis capabilities demonstrated

### Windows memory triage

- Identified the operating-system and architecture context of the memory image.
- Reviewed the process inventory and parent-process context.
- Examined process memory for anomalous executable regions and assessed their protection and allocation characteristics.
- Inspected process handles to identify files relevant to the application’s activity.

### Memory and file-artifact correlation

- Recovered selected memory and file-cache artefacts from the supplied image.
- Compared recovered byte sequences to determine whether separate artefacts represented the same content.
- Used SHA-256 hashes to verify byte-for-byte agreement between independently recovered copies.
- Distinguished a valid file header from evidence that the complete file content had been recovered.

### Static and controlled code analysis

- Disassembled recovered x86 code and reviewed its behaviour at instruction level.
- Examined dynamic API-resolution logic and the construction of command data.
- Inspected decoded script content as text rather than executing it.
- Used controlled emulation to corroborate an API invocation and its arguments.

### Recovery and validation

- Analysed recovered encrypted data using the parameters evidenced in the decoded script.
- Validated the decryption result through padding and archive-integrity checks.
- Inspected recovered archive metadata and contents as data, without running recovered files.

## Evidence-handling practices

- Preserved the original memory image and worked with extracted copies.
- Recorded hashes when comparing independently recovered artefacts.
- Treated recovered code and documents as untrusted.
- Did not directly execute the recovered payload or extracted documents.
- Used local analysis tools and kept the work within the authorised lab environment.

## Lessons learned

1. **A process name is not enough.** Process context becomes more useful when compared with memory mappings, protections, and associated handles.
2. **Memory artefacts need corroboration.** A suspicious region should be connected to other evidence rather than treated as malicious based on one indicator alone.
3. **File signatures are only a starting point.** A file may have a valid header while containing incomplete data or additional content outside its normal format structure.
4. **Static analysis and emulation complement one another.** Disassembly helps explain implementation details; controlled emulation can provide independent behavioural evidence.
5. **Validate every recovery step.** Hashes, lengths, cryptographic padding checks, and archive-integrity tests help distinguish a successful recovery from a plausible-looking but incomplete result.

## Publication note

This repository intentionally does **not** publish challenge-specific answers, exact indicators, memory addresses, command sequences, payload details, cryptographic secrets, recovered document contents, or the flag.

TryHackMe's Acceptable Use Policy prohibits publishing flags, answers, solutions, or step-by-step walkthroughs for content that is still active. Content not marked as retired must be treated as active. See [TryHackMe Acceptable Use Policy, section 8](https://tryhackme.com/legal/acceptable-use-policy).

If the room is later marked as retired, this summary can be reviewed and expanded in line with the platform's then-current write-up guidance.

## References

- [TryHackMe — Day-O](https://tryhackme.com/room/dayo)
- [TryHackMe — Acceptable Use Policy](https://tryhackme.com/legal/acceptable-use-policy)
- [Volatility 3 documentation](https://volatility3.readthedocs.io/)
- [Speakeasy](https://github.com/mandiant/speakeasy)
- [MITRE ATT&CK](https://attack.mitre.org/)

---

*This is a learning portfolio summary, not a malware attribution report or a claim that the lab sample represents a real-world campaign.*
