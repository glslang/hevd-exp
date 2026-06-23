# Security Policy

This repository contains Windows kernel exploit proof-of-concepts targeting [HackSys Extreme Vulnerable Driver (HEVD)](https://github.com/hacksysteam/HackSysExtremeVulnerableDriver) for security research and education. The exploit techniques here are intentional.

## Supported Versions

Security fixes are applied to the `main` branch only.

## What Is Not a Vulnerability in This Repository

Please do **not** report the following here:

- Vulnerabilities in HEVD — they are by design. See the [HEVD project](https://github.com/hacksysteam/HackSysExtremeVulnerableDriver).
- Vulnerabilities in the Windows kernel — report to [Microsoft Security Response Center](https://msrc.microsoft.com/create-report).
- The presence of exploit code, shellcode, or privilege-escalation techniques in this repository.

## What to Report

Please report:

- Unintended security issues in this repository (for example, a supply-chain risk in build tooling or dependencies).
- Security vulnerabilities in the [`win-kexp`](https://github.com/glslang/win-kexp) library that affect consumers of this project.

## How to Report

1. **Preferred:** [Open a private security advisory](https://github.com/glslang/hevd-exp/security/advisories/new) on GitHub.
2. **Alternative:** Email [glslang@gmail.com](mailto:glslang@gmail.com) with a description of the issue and steps to reproduce.

Please allow reasonable time for triage before public disclosure. We will acknowledge reports and work toward a fix when applicable.
