# GitMonitor.sh

Some quick-and-dirty bash to monitor string patterns within the commits to a git repo.  Designed to be run via cron - see Usage.

## Prerequisites

```
* plain old bash
* cd
* git
* printf
* cut
* date
* hostname
* basename
* grep
* sendmail (as an env var)
```

*n.b. built and tested against Debian Stretch - tools like ```date``` and ```hostname``` may differ across platforms.*

## Installing

1. ```git clone https://gerrit.wikimedia.org/r/wikimedia/security/tooling```
2. Configure various environment variables - see comments within ```GitMonitor.sh``` header or [sample file provided](GM_env.sh).  Note that GM_env* is a default pattern in [.gitignore](.gitignore)
3. Set proper execute perms and go!

## Usage

1. Simply configure the relevant environment variables and run ```./GitMonitor.sh```
2. Set up as a cron (e.g. every 2 minutes):
```bash
PATH=/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin
SHELL=/bin/bash
*/2 * * * * cd /path/to/wikimedia/security/tooling/gitmonitor && source GM_env.sh && ./GitMonitor.sh
```

## Authors

* **Scott Bassett** [sbassett@wikimedia.org]

## License

This project is licensed under the Apache 2.0 License - see the [LICENSE](https://opensource.org/licenses/Apache-2.0) file for details.
