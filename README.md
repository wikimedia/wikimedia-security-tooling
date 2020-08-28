# Wikimedia Security Tooling

This repository is an incubator of sorts for ad-hoc wikimedia security tooling, currently managed by [the Wikimedia Security Team](https://www.mediawiki.org/wiki/Wikimedia_Security_Team).  Please direct any comments or questions to one of the authors listed below.

## Usage

For now, simply clone this repository:

```
git clone https://gerrit.wikimedia.org/r/wikimedia/security/tooling
```

Useful but not necessarily production-worthy code should be placed within the ```bin``` directory with a README or appropriate, clear code comments.  If these scripts and projects ever develop into larger, more mature codebases, then they should be migrated to their own directories under the more general ```wikimedia/security``` namespace (e.g. https://w.wiki/ado).  See [this related task](https://phabricator.wikimedia.org/T246392) for an example of this process.

Here is a current list of larger, more stand-alone tools:

1. [Deployer Audit](https://gerrit.wikimedia.org/r/admin/repos/wikimedia/security/deployer-audit)
1. [Github User Audit](https://gerrit.wikimedia.org/r/admin/repos/wikimedia/security/github-user-audit)
1. [Gitmonitor](https://gerrit.wikimedia.org/r/admin/repos/wikimedia/security/gitmonitor)
1. [PHP Security Tools](https://gerrit.wikimedia.org/r/admin/repos/wikimedia/security/php-security-tools)
1. [Spam Account Stats](https://gerrit.wikimedia.org/r/admin/repos/wikimedia/security/spamaccountstats)
1. [Usertracker](https://gerrit.wikimedia.org/r/admin/repos/wikimedia/security/usertracker)

## Authors

* **Chase Pettet** [cpettet@wikimedia.org]
* **Scott Bassett** [sbassett@wikimedia.org]

## License

This project is licensed under the Apache 2 License - see the [LICENSE](LICENSE) file for details.
