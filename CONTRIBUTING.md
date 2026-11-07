# Contributing

Thanks for helping make NetLedger better. Bug reports, platform output samples and pull requests
are all welcome.

## Development setup

```bash
git clone https://github.com/SalamoneJack/NetLedger.git
cd NetLedger
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest
ruff check src tests
netledger demo            # simulated network + dashboard on http://127.0.0.1:8080
```

## Adding or fixing a platform

The most valuable contribution is **real command output** from a device. Parsers are pure
functions (see `src/netledger/drivers/`) tested against samples in `tests/test_parsers.py`.

1. Add or adjust the parser function in the platform's driver module.
2. Add a test with the output you captured, run through `netledger sanitize` (see below).
3. If the configuration contains timestamps or other text that changes without a real change,
   add a `volatile` rule in `src/netledger/platforms.py`; add `secrets` rules for passwords/keys.
4. Run `pytest` and open a pull request.

See [docs/writing-drivers.md](docs/writing-drivers.md) for the driver API.

## Sharing configurations and command output

Never paste a real configuration into an issue or a test as it is. `netledger sanitize` makes it safe to
share and keeps it parseable:

```bash
netledger sanitize running-config.txt -o sanitized.txt     # a file you saved
some-command | netledger sanitize > sanitized.txt          # standard input
netledger sanitize --device core-sw01 -o core-sw01.txt     # the latest backup of a device
```

It replaces:

- secrets, using the platform's rules (`--platform ios`, guessed from the syntax otherwise);
- IPv4 and IPv6 addresses, mapped consistently so subnets still contain their hosts;
- host, domain and user names, SNMP communities, descriptions and comments, MAC addresses, serial numbers,
  AS numbers (to 64512 and up), banners, certificates and keys.

It keeps what the parsers need: sections, indentation, keywords, masks, wildcards and prefix lengths.
`--keep-private` leaves RFC 1918 addresses as they are when they matter for the bug. Read the result before
you post it: names that only your network uses, such as VLAN or object names, are kept.

## Screenshots

`python scripts/screenshots.py` regenerates every image in `docs/images` from the demo
(simulated devices only). It needs Chrome or Edge for the dashboard shots.

## Pull requests

- Keep changes focused and covered by tests.
- Update the docs when behaviour or configuration changes.
- Never include real hostnames, IP addresses, serial numbers or secrets in tests or issues:
  `netledger sanitize` removes them for you.
