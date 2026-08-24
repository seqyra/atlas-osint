# ATLAS OSINT

ATLAS OSINT is a lightweight terminal application for collecting information from public sources. It provides a saved local profile, an ASCII welcome screen, and focused lookups for usernames, domains, IP addresses, and email-domain infrastructure.

> Use ATLAS only for lawful research on data you are authorized to investigate. The project does not query stolen databases, reveal private phone ownership, or identify vehicle owners.

## Features

- Username checks across GitHub, GitLab, Reddit, TikTok, Instagram, X, Twitch, Pinterest, Telegram, VK, OK, Steam, Medium, and Keybase
- Domain DNS records, RDAP registration data, and Certificate Transparency subdomains
- IP and ASN registration details through RDAP
- Email syntax, MX, SPF, and DMARC checks without sending mail
- JSON export of every lookup
- Nickname saved locally in `~/.config/atlas-osint/config.json`

## Installation

### Termux

```bash
pkg update
pkg install python -y
python -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
python main.py
```

### Ubuntu / Debian / UserLAnd

```bash
sudo apt update
sudo apt install -y python3 python3-venv
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
python main.py
```

## Usage

Run `python main.py`. On first launch ATLAS asks for a nickname and stores it locally. Choose a lookup from the menu, enter a target, and optionally export the result as JSON.

Results are leads, not proof. Sites can return false positives, rate-limit automated requests, or change their public pages. Verify important findings manually.

## Data sources

- Public profile pages on supported platforms
- DNS resolvers
- RDAP services discovered through IANA bootstrap data
- Certificate Transparency data from `crt.sh`

No API keys or secrets are required.

## Roadmap

- Optional Sherlock integration for broader username coverage
- Parallel lookups and confidence scoring
- CSV and HTML exports
- Investigation history and relationship graphs

## License

No license has been granted yet. All rights are reserved by the repository owner.

