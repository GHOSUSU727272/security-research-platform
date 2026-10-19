# CTF AutoSolver: implemented scope and limits

The live panel extends Research Platform v0.4.1. Existing offline CLI modules and registry stay compatible.
Main entry: `.venv/bin/python -m ctf.panel --workspace /home/anonim/ctf-workspace --port 8765`.
The panel uses a persistent enabled user systemd service `ctf-autosolver`, automatic restart on failure, and the existing Windows SSH tunnel. Solver version: `agent-2.1`.

## Implemented

- Async challenge queue, 1–4 concurrent challenge workers; Fast/Balanced/Deep allocations 30 / 20+120 / 20+120+360 seconds, capped by the selected 5–600 second task budget.
- Separate Linux Bubblewrap processes without network, writable per-attempt scratch, read-only inputs. Address-space, CPU, output-file, file-descriptor and wall-clock limits. Cancellation kills the entire process group.
- SQLite attempt cache keyed by solver version, sampled input hash, category/scope and pass. Completed exhaustive checks are reusable across budgets; interrupted checks resume by rerunning the unfinished pass. Mutable registry bookkeeping does not invalidate the cache. Finding a candidate stops further expensive passes.
- Optional watch mode runs for up to 24 hours from the button press, polls every 30–900 seconds (default 120), backs off on failures to at most 900 seconds, and resumes an unexpired run after service restart. Stop clears the saved intent. New/changed tasks are analyzed; unchanged completed inputs are skipped. Unsolved web targets can be revisited after 15 minutes. VM sleep/offline time still counts toward the wall-clock deadline.
- Existing registry, ELF, PNG, PCAP/PCAPNG, strings and deterministic solvers reused. New bounded transform graph supports nested ZIP/TAR/GZIP/BZIP2/XZ, Base32/85, binary, ASCII arrays, big integers and source character/substring constraints.
- RSA exact low-exponent root, supplied factors/totient/private exponent, bounded Fermat/rho, Wiener, shared-prime/common-modulus and three-modulus broadcast cases; supplied-key AES ECB/CBC, supplied-key Vigenere/XOR; crib-based periodic XOR. Longer crib-based recoveries are labelled heuristic and excluded from automatic submission.
- UTF-16, reversed data, escaped characters, HTML entities, URL-safe Base64, spaced hex and ROT47. Python assertion checkers have a deliberately strict AST-to-Z3 subset: fixed-length printable input, arithmetic/bitwise equality checks, unique solution required and concrete reevaluation. Arbitrary Python is never executed by that extractor.
- Smart pass calls available readelf, objdump, tshark, exiftool, pdftotext and zbarimg. RGB/RGBA/channel bit planes 0–1 in both bit orders, PCM WAV LSB, PNG text/compressed chunks and PNG/JPEG appended data are inspected. Packet payload extraction is bounded; concatenation is not full TCP reassembly. Partial evidence is checkpointed before expensive tools and recovered after timeout/failure when available. Missing tools and failures appear in history. Ghidra headless is an optional Deep-pass invocation, not an automatic semantic reverse-engineering solver.
- Web pass only for URLs in a challenge's explicit scope. At most ten GETs per target, half-second spacing, same-origin scripts/redirects, size/time limits. Supports HTML/JS flag recovery and limited SQL-error/template-expression hypotheses; these hypotheses are not successful exploit claims. Platform hosts are excluded. Private-address lab targets need a separate adapter.
- Optional OpenAI-compatible LLM loop only in Deep mode when configured: at most three proposals with previous results as feedback, duplicate script suppression, bounded input/output and shared task deadline. Returned Python runs in the offline sandbox. Generated results require manual review and are excluded from auto-submission. No model or API key has been configured or used in validation.
- Live Russian panel: start, stop, watch state/deadline, modes, budgets, separate platform/local views, candidates, source/method evidence, history, copy and JSON export. Auto-submission and processing local examples are off by default. Polling transfers compact attempt summaries; full tool output is in JSON export.

## SolarCTF

Adapter derives from the first-party frontend `https://solarctf.ru/static/js/main.d9059984.js`, inspected on 2026-10-16. Backend is `https://backend.solarctf.ru`. Operations: `/get-status`, `/get-categories`, `/get-tasks`, `/get-task`, `/check-flag`; exact observed parameter names are used. Runtime schema checks fail clearly rather than guessing.

The login button opens a dedicated Chromium profile on the Kali desktop. The user signs in on the real SolarCTF page. Playwright saves the session under the CTF workspace with mode 0600; no passwords are embedded. This dedicated profile does not automatically import an existing Windows-browser login. The session is not mounted inside worker sandboxes.

Before start, the adapter records `Not Started` and does not request task lists. Authenticated status retrieval has been checked against the actual site. Discovery has a 90-second overall budget and 200-call ceiling; imported tasks are persisted incrementally. Task details and files refresh at most once per ten minutes after successful import. Explicit organizer-linked HTTPS CDN files are supported without platform credentials; platform credentials only go to the exact platform origins. Redirects are bounded and destination DNS is checked for public addresses. Downloads replace files atomically and are capped at 16 MiB. This is a hostname-based downloader, not a general-purpose SSRF-resistant proxy; DNS pinning is not implemented.

Submission is OFF by default. The user enables it in the panel. Only tasks with matching numeric platform identifiers qualify; name prefixes alone do not qualify. Heuristic/LLM candidates require manual review. A durable per-flag record is written before a network submission so ambiguous responses are never automatically retried. Only a `toast: success` response marks a flag accepted. Rejected or unknown attempts remain in history. An accepted response has not yet been validated against a live competition task.

## Optional LLM setup

Set `CTF_LLM_URL` to the complete chat-completions endpoint, `CTF_LLM_MODEL`, and optionally `CTF_LLM_KEY` in the panel service environment. Local HTTP endpoints must use localhost; remote endpoints must use HTTPS. When configured, challenge descriptions and bounded evidence are sent to that endpoint. There is no automatic API-key discovery. Do not store keys in source files or reports.

## Explicitly unfinished

This is a working bounded analysis/solving pipeline, not completion of the entire requested AutoSolver specification. No general angr strategy, arbitrary-program Z3 constraint discovery, pwntools exploit synthesis, automatic ROP-chain construction, APK/.NET decompilation workflow, general audio/spectrogram recovery, memory-dump workflow, general OSINT agent, complete SQLi/SSTI/LFI/IDOR/deserialization exploitation suite or Docker challenge orchestration is implemented. Ghidra invocation and optional live LLM/web paths need broader integration testing. Unknown executables are not directly run except explicit generated solver subprocesses inside the sandbox.

Input limits: 100 files, 4 MiB per sampled file, 32 MiB total; graph maximum 400 nodes / depth 5; archive limits and oversized-file truncation mean some large challenges cannot be solved. The panel does not claim full coverage or guaranteed solve times. Workspaces contain flag candidates and should remain local.

## Validation

`pytest -q`: 170 passed, one skipped after this upgrade. `tests/test_ctf_agent.py` and `tests/test_ctf_upgrade.py` cover isolation, cancellation, cache invalidation, watch backoff/resume/deadline, interrupted attachment discovery and replacement, timeout, codecs, crypto, bounded Z3, media, archive boundaries, false positives, submission deduplication and target restrictions. Source reconstruction returns candidates and is not proof that arbitrary program control flow accepts the result.

`/home/anonim/ctf-workspace/benchmark-report.json`: 5/7 public training cases; the source-only picoCTF store case lacks an interactive service/hidden flag. `upgrade-benchmark-report.json`: 11 randomized positive cases recovered exactly and two negative controls without candidates (13/13 checks, about 17 seconds). These synthetic cases validate supported methods, not general competition effectiveness. `soak-report.json`: 60 offline cycles in about 65 seconds, three tasks, one changed input and one agent recreation; four real worker launches and no remaining scratch directories. This is not a 24-hour endurance test. Live task discovery and accepted submissions remain untested until the competition starts.

Backup before edits: `/home/anonim/research-backups/before-autosolver-20261016-225847.tar.gz`.
Backup immediately before this upgrade: `/home/anonim/research-backups/before-agent-upgrade-20261017.tar.gz`.
