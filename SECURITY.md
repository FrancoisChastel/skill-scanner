# Security

## Reporting a vulnerability

Email francois@chastel.co with a description and, if you can, a reproduction. Please do not open a public issue for a way to get a malicious skill past the scanner's install gates, for a way to make the scanner execute scanned content, or for anything that could expose credentials. You will get an acknowledgement within a few days and a fix or a plan before any public disclosure.

A skill that should be flagged but is not (a detection gap) is not a vulnerability in this sense. Open an issue with the smallest skill that reproduces it, using reserved domains such as `example.com` and no live credentials.

## What skill-scanner does and does not do with what it scans

- It never executes scanned content. Files are read as bytes; archives are opened in memory; symlinks are recorded, never followed.
- It never reads configuration from the directory it scans. Allowlists and suppressions come from `~/.skill-scanner/config.json` or an explicit `--config`.
- Secrets it recognises are redacted in every output: terminal, JSON, SARIF, hook messages, and anything sent to the optional judge.
- It does not use the network unless you scan a remote source (fetched with your own git or npm, as the install would), enable the jev judge, or enable an external analyzer that uses the network (osv-scanner, registry rules for semgrep).
- The jev judge, when enabled, receives the skill's text files, redacted, never more than 24,000 characters. The API key is read from the environment, sent only to the provider's HTTPS endpoint, and redirects are refused.
- Hooks installed by `setup` run a pinned copy of the scanner from `~/.skill-scanner/bin` with an absolute Node path.

## What it is not

It is not a sandbox and not the last line of defence. It raises the cost of shipping a malicious skill; it does not make an untrusted skill safe. Anything that must never happen belongs in the harness's permission system or a kernel-level sandbox.

## Supported versions

The latest minor release receives fixes. Earlier versions do not.
