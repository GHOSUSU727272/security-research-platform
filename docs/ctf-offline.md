# CTF Offline Triage (initial SolarCTF preparation)

Use only challenge files supplied by the organizers or obtained within competition rules.

Run from the project root:

```bash
.venv/bin/python -m ctf.triage /path/to/challenge-directory --output /path/outside/challenge-directory/ctf-report
```

Open `index.html` for a local dashboard; `report.json` is machine-readable.
The scanner does not execute files, decompress archives, contact targets, or submit flags.
It searches candidate flags matching common prefixes (flag, ctf, solarctf, solar);
actual event flag syntax must be confirmed from the organizers. A 64 MiB per-file
scan limit prevents huge files from exhausting memory; truncated files are marked.
The original Research Engine and its state remain unchanged.

Future work: per-category parsers, safe archive inspection with extraction limits,
challenge metadata intake, evidence review and an optional authenticated LAN dashboard.

## Challenge registry

```bash
.venv/bin/python -m ctf.challenges --workspace ~/ctf-workspace add sample ~/my-challenge --category misc
.venv/bin/python -m ctf.challenges --workspace ~/ctf-workspace analyze sample
.venv/bin/python -m ctf.challenges --workspace ~/ctf-workspace list
```

Generated HTML: `~/ctf-workspace/reports/sample/index.html`.
ZIP manifests can be inspected without extracting or executing contents:

```bash
.venv/bin/python -m ctf.archive ~/my-challenge/archive.zip
```

To view reports from another computer, use SSH port forwarding to localhost
rather than exposing an unauthenticated HTTP server to the LAN. In Kali:

```bash
cd ~/ctf-workspace
python3 -m http.server 8765 --bind 127.0.0.1
```

From another computer with SSH access to Kali, tunnel remote 8765 to local
8765 and open `http://127.0.0.1:8765/reports/sample/index.html`.
The HTTP server is read-only for normal requests but has no authentication,
so keep it bound to localhost and only use it with trusted SSH tunnels.

## Offline encoding hints

Use the bounded, single-layer Base64 / hexadecimal / URL-percent decoder
for text files:

```bash
.venv/bin/python -m ctf.decoders /path/to/challenge/text.txt
```

Only potential flag matches are reported; no arbitrary payload execution,
network access, brute forcing or automatic flag submission.

## Automatic offline inbox processing

Put each challenge's downloaded files into a separate folder inside
`~/ctf-inbox/`. Run the watcher to import and analyze new folders:

```bash
mkdir -p ~/ctf-inbox
cd ~/research-platform-v0.4
.venv/bin/python -m ctf.watch ~/ctf-inbox --workspace ~/ctf-workspace --interval 10
```

Use `--once` to process a single batch. The watcher never accesses
the Internet, executes challenge binaries or submits flags.
The dashboard is refreshed when new challenges are registered or analyzed.

## Deep offline inspection (ELF / classic PCAP / static HTML)

\`ctf.deep\` works only on local challenge artifacts. It does not run binaries,
access remote hosts, execute JavaScript, or submit flags. It inspects the first
4 MiB per file. ELF metadata includes architecture, entry point, security
indicators and static section candidates; PCAP extraction covers bounded
Ethernet/IPv4 TCP/UDP payloads, simple DNS names and HTTP request lines.
HTML inspection collects comments, hidden fields and linked resource names.
PCAPNG and full TCP stream reassembly are not supported yet. Every candidate
remains **unverified** until accepted by the event.

\`\`\`bash
cd ~/research-platform-v0.4
.venv/bin/python -m ctf.deep /path/to/challenge/evidence.pcap
\`\`\`

When using \`ctf.challenges analyze\` or the automatic inbox watcher, this
inspection runs alongside the existing bounded solvers and appears in JSON and
HTML reports.

## SolarCTF 2026 flag filtering

The official 2026 competition rules define the flag syntax as
\`SOLARCTF{[A-Za-z0-9_]+}\`. See https://solarctf.ru/.

The pipeline retains generic CTF results for training, but separately
displays **SOLARCTF format candidates** in the HTML/JSON reports and
dashboard. Matching the syntax is not verification by the organizers.

PCAPNG Enhanced Packet Blocks (Ethernet linktype) and PNG \`zTXt\` compressed
text are now supported, subject to bounded read/decompression limits.
Other PCAPNG block types and fragmented/reassembled TCP flows are not decoded.
