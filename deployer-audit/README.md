# DeployersToGSheet

A Python script to get the current list of active WMF deployers via an admin
yaml file and store/update within a shared, private Google Sheet. 

## Prerequisites

```
python3
argparse
datetime
dotenv
google-api-python-client
pickle
os
re
requests
sys
urllib.parse
yaml
```

## Installing

1. ```pip install --upgrade google-api-python-client google-auth-httplib2 google-auth-oauthlib```
2. ```git clone "https://gerrit.wikimedia.org/r/wikimedia/security/tooling"```

## Usage

1. Configure ```.env``` to your liking and run something like ```eval $(cat .env | sed 's/^/export /')``` - example values provided within sample.env.
2. Set up Google auth via: https://developers.google.com/sheets/api/quickstart/python
3. Download credentials.json file from step (2)
4. Run app, which then prompt you to auth in browser via Google's App Workflow system.  This should only need to happen once per install.
2. ```chmod +x DeployersToGSheet.py && ./DeployersToGSheet.py {args...}```
3. DeployersToGSheet.py has a few arguments:
	1. ```-h```, ```--help``` = show this help message and exit
    2. ```-p```, ```--phab``` = Optionally print Phab-formatted table to stdout
    3. ```-n```, ```--nodeploys``` = Only print "no deploy" users for Phab-formatted table 

## Authors

* **Scott Bassett** [sbassett@wikimedia.org]

## License

This project is licensed under the Apache 2.0 License - see the [LICENSE](../LICENSE) file for details.
