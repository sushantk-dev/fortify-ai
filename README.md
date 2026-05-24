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



\# List all releases for an app, then exit — no pipeline run

python fortifyai.py --app-name 1038\_US\_D360-Citi-Triggers-on-Cloud\_USIS --list-releases



\# --verbose shows DEBUG logs too

python fortifyai.py --app-name 1038\_US\_D360-Citi-Triggers-on-Cloud\_USIS --list-releases --verbose



uvicorn api\_server:app --host 0.0.0.0 --port 8000 --reload



GET /releases?app\_name=1038\_US\_MyApp\_USIS



GET /config/validate //validate .env



GET /health //liveness probe

&#x20;

/pipeline/app-name

{

&#x20; "app\_name": "1038\_US\_MyApp\_USIS",    // required

&#x20; "config": { /\* ConfigOverrides \*/ }    // optional

}



/pipeline/dry-run

{

&#x20; "release\_id": 1723380,               // optional (pick one source)

&#x20; "report\_path": null,                 // optional

&#x20; "app\_name": null,                    // optional

&#x20; "config": { /\* ConfigOverrides \*/ }    // optional

}



/pipeline/live

{

&#x20; "release\_id": 1723380,          // required

&#x20; "config": { /\* ConfigOverrides \*/ } // optional

}



/pipeline/offline



{

&#x20; "report\_path": "/tmp/report.json",  // required

&#x20; "release\_id": 0,                   // optional (0 = read from file)

&#x20; "config": { /\* ConfigOverrides \*/ }   // optional

}

