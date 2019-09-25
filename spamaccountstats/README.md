# SpamAccountStats

A Python script to generate statistics for new account creations to determine
if the Users/IPs are within stopforumspam.com's spam lists.  Developed to
1) analyze the potential efficacy of stopforumspam.com's spam lists related
to suspicious account creations upon various Wikimedia projects and 2) to serve
as a basic proof-of-concept for security-monitoring tooling for certain
suspicious events as the occur on various Wikimedia projects.

n.b. As it currently exists, this should NOT be considered production code.

## Prerequisites

```
python 3.7.3
argparse
csv
datetime
dotenv
hashlib
json
lxml
os
re
requests
sys
time
urllib.parse
zlib
```

## Installing

1. ```git clone "https://gerrit.wikimedia.org/r/wikimedia/security/tooling"```

## Usage

1. Configure ```.env``` to your liking - example values provided.
2. ```chmod +x SpamAccountStats.py && ./SpamAccountStats.py {args...}```
3. SpamAccountStats.py has a few arguments:
   1. ```-h``` = displays help/arguments and exits.
   2. ```{project}``` = in the form of {lang code}.{project type}, e.g. ```en.wikipedia```.
   3. ```-d```, ```--date``` = a date range in a few different supported formats:
      1. -d {int}h = e.g. 1h, range of current utc to 1 hour ago.
      2. -d {int}d = e.g. 30d, range of current utc to 30 days ago.
      3. -d YYYY-MM-DD = range of current utc to YYYY-MM-DD days ago.
      4. -d YYYY-MM-DD-yyyy-mm-dd = date range (utc) from YYYY-MM-DD to yyyy-mm-dd.
      5. -d YYYY-MM-DDTHH:MM:SSZ = range of current utc to YYYY-MM-DDTHH:MM:SSZ days ago.
      6. -d YYYY-MM-DDTHH:MM:SSZ-yyyy-mm-ddThh:mm:ssZ = date range (utc) from YYYY-MM-DDTHH:MM:SSZ to yyyy-mm-ddThh:mm:ssZ (what mediawiki API tends to use).
   4. ```-r```, ```--raw``` = raw CSV report output, no informational header.
   5. ```--sfsapi``` = also check the StopForumSpam API via url defined as the ```SFS_API_URL``` environment variable.

## TODO

1. Actually use logstash structured data to search for IPs instead of gross
regexps of json string representations within ```search_user_within_logstash()```
2. Refactor to more proper python app.
3. Support beta.wmflabs.org sites (might not be possible via logstash...)

## Authors

* **Scott Bassett** [sbassett@wikimedia.org]

## License

This project is licensed under the Apache 2.0 License - see the [LICENSE](LICENSE) file for details.
