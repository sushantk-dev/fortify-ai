"# fortify-ai"

python fortifyai.py --release <RELEASE\_ID>

python fortifyai.py --release 1723380

python fortifyai.py --release 1723380 --verbose   # DEBUG logging



\# Repo from CLI — overrides whatever is in .env

python fortifyai.py --release 1723380 --repo org/repo\_name



\# Combined with offline mode

python fortifyai.py --report report.json --repo org/repo\_name



\# New: supply app name, latest release resolved automatically

python fortifyai.py --app-name 1038\_US\_D360-Citi-Triggers-on-Cloud\_USIS



\# Can still combine with --repo

python fortifyai.py --app-name 1038\_US\_D360-Citi-Triggers-on-Cloud\_USIS --repo acme/backend

