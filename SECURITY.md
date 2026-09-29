# Security

SignalBridge is a local proof of concept. It is designed to run on one trusted machine and bind to `127.0.0.1` only. Don't expose the console to a network.

If you find a security issue, please open a GitHub issue without exploit details, or contact me through the email on [my portfolio](https://aman-agarwal6.github.io/#contact), and I'll follow up privately. Use synthetic data in any report.

Scope and limits:

- Local administrators are trusted. The console's access controls don't protect against someone with direct access to the machine or database.
- Lab scripts run only fixed, reviewed scenarios. They aren't a sandbox for untrusted code, so don't point them at unapproved targets or add executable samples.
- Recorded test and lab results don't prove the absence of vulnerabilities.

Design details and known gaps are in [docs/DESIGN.md](docs/DESIGN.md).
