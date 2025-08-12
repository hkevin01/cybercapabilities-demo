# Reverse Engineering Analysis

Suggested workflow (choose your tools):
- Static: Ghidra or Cutter/radare2 — identify `derive_key`, `checksum`, and XOR routine.
- Dynamic: Run under `ltrace/strace` or with a debugger (gdb) to watch derived bytes.
- Reconstruct keygen: implement in Python or C to produce a license for any username.

Deliverables:
- Brief write-up in this folder: approach, findings, function graphs/screenshots (if permissible).
- Optional: Ghidra script or r2 notes.
