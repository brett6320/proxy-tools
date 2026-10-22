# proxy-tools

- `what-scope.sh` (bash 3.2+, curl) and `what-scope.ps1` (PowerShell 5.1 and 7+) are two implementations of one tool. Keep them functionally equivalent: any change to options, parsing, output, or exit codes goes into both in the same change.
- `README.md` is the user documentation. Update it in the same change as any behavior change, including the "Small differences between the two versions" list.
- `what-scope.ps1`: the C# in `Add-Type` must stay C# 5 (no `$""`, `?.`, `=>` members) so Windows PowerShell 5.1 can compile it. Keep the file ASCII-only; 5.1 reads BOM-less files as ANSI.
- `what-scope.sh`: must run on macOS's bash 3.2 (no associative arrays, `mapfile`, `${var,,}`).
- Run `tests/run-linux.sh` (Docker) after changes. It needs `samples/notskope.html`; `samples/` is gitignored.
