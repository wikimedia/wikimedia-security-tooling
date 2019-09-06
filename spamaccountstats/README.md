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

## TODO

1. Actually use logstash structured data to search for IPs instead of gross
regexps of json string representations within ```search_user_within_logstash()``` 
2. Refactor to more proper python app.
3. Support beta.wmflabs.org sites (might not be possible via logstash...)

## Authors

* **Scott Bassett** [sbassett@wikimedia.org]

## License

This project is licensed under the Apache 2.0 License - see the [LICENSE](LICENSE) file for details.

