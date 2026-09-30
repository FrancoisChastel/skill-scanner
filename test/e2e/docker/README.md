# End-to-end suite (Docker)

Installs the package the way a user would, in a container with the real Claude Code, Codex, OpenCode, Pi, and `skills` CLIs and the optional analyzers (gitleaks, osv-scanner, semgrep, NVIDIA SkillSpector, Cisco skill-scanner), then checks every command end to end. Nothing runs on the host except `docker build` and `docker run --rm`.

```bash
bun run e2e             # pre-release: pack this checkout and test the tarball
bun run e2e:registry    # post-release: test the latest version on npm
bash scripts/e2e-docker.sh registry 0.1.0   # or a specific one
```

The run prints one `PASS`, `FAIL`, or `SKIP` line per check and exits 1 when anything fails. It needs Docker and network access (npm, GitHub, osv.dev). The image is about 5 GB; remove it with `docker image rm skill-scanner-e2e`.

| File | Role |
|---|---|
| `Dockerfile` | Node 22, git, the harnesses at their latest versions, the analyzers, and the package from `pkg/*.tgz` or npm |
| `run.sh` | The checks, grouped by area: install, CLI, local scans, remote sources, `add`, `guard`, `setup`, hooks, gated updates (`git pull`, `pi update`) and `codex plugin add`, audit and trust, adapters, judge, analyzers, library types, uninstall |
| `fixtures.py` | Creates the test skills and git repositories inside the container; payload strings are assembled at run time |
| `mock-jev.mjs` | A local stand-in for TypeSafe's System One endpoint that answers and logs judge requests |
| `adapters.mjs` | Loads the published OpenCode plugin and Pi extension, and the shims `setup` writes, with fake hosts |

The harness CLIs are installed at their latest versions on purpose: the weekly workflow run catches a harness change that breaks the hooks or adapters before users do.
