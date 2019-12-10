# PHP-Security-Tools

Some bash scripts which install, run and manage reports for various security-focused tools for the PHP programming language.

## Prerequisites
```
bash
composer
docker
git
node/npm
php72+
sed
```

## Installing
1. ```git clone "https://gerrit.wikimedia.org/r/wikimedia/security/tooling"```

## Usage
1. ```cd php-security-tools```
2. Configure ```.env``` to your liking and run something like: ```eval $(cat .env | sed 's/^/export /')``` - sample values provided within ```sample.env```
3. ```bin/build_dockers```
4. ```bin/run {args...}``` (args is typically just one argument: the path to the code)
5. Optionally alias ```bin/run``` to something shorter: ```alias pst="/path/to/pst/install/bin/run" or drop a similar script into /usr/local/bin or somewhere similar.
6. The PHP-Security-Tools run script has a few options/arguments:
   1. -h | --help | help = displays a help message with different tool options
   2. all = Runs all tools and create a report
   3. sec-check-ext = Runs phan mediawiki-optimized SecCheckPlugin (ext)
   4. sec-check-gen = Runs phan SecCheckPlugin general scan
   5. phan-sec = Runs security-focused phan checks
   6. phpcs-sec = Runs security-focused phpcs checks
   7. php-sec = Runs Symphony's security:check against composer.lock
   8. php-snyk = Runs Snyk's CLI (auth required) against composer.lock
   9. npm-sec = Run an npm audit if a valid package-lock.json exists
   10. npm-out = Run an npm outdated if a valid package-lock.json exists
   11. node-retire = Run retirejs
   12. node-snyk = Run Snyk's CLI against package-lock.json
   13. mw-php-sec = Runs mwSecSniff to find potentially dangerous PHP code
   14. mw-i18n-sec = Runs i18n script to find potentially dangerous HTML
   15. mw-http-leaks = Runs a very naive check for http leaks within HTML

## TODO
1. Additional tools to investigate, which *may* or *may not* be useful:
   1. FunctionFQNReplacer (code quality) - https://github.com/Roave/FunctionFQNReplacer
   2. psecio/parse (security) - https://github.com/psecio/parse
   3. unused-scanner (code quality) - https://github.com/Insolita/unused-scanner
   4. TaintPHP (security) - https://github.com/olivo/TaintPHP
   5. Progpilot (security) - https://github.com/designsecurity/progpilot
   6. Psalm (security) - https://psalm.dev/
   7. php-malware-finder (security) - https://github.com/nbs-system/php-malware-finder
   8. phortress (security, old) - https://github.com/lowjoel/phortress
   9. phpstan (code quality) - https://github.com/phpstan/phpstan
   10. phpcpd (code quality) - https://github.com/sebastianbergmann/phpcpd
   11. exakat (security, commercial?) - https://www.exakat.io/price-services/
   12. WAP (security, old) - https://github.com/asrulhadi/wap
   13. php mess detector (code quality) - http://phpmd.org/
   14. php-cs-fixer (code quality) - https://github.com/FriendsOfPHP/PHP-CS-Fixer
   15. phpdepend (code quality) - https://github.com/pdepend/pdepend
2. Write integration tests
3. Improve checks for mw_i18n_message_check (ensure i18n file/dir, etc.)
4. Fix issues (so many undeclareds, not very nice) with phan_sec()
5. Consolidate docker run commands a little better?
6. Improve portability/compatibility of various bin/ scripts with different Unix flavors

## Authors
* **Scott Bassett** [sbassett@wikimedia.org]

## License
This project is licensed under the Apache 2.0 License - see the [LICENSE](LICENSE) file for details.
