#/usr/bin/env bash
################################################################################
# Author: sbassett@wikimedia.org
# License: Apache 2 <https://opensource.org/licenses/Apache-2.0>
# Usage:
#   Searches recent logs for simple grep patterns
#   Env variables:
#     GM_REPO_URL    = gerrit repo url to clone and search (no .git at end)
#     GM_REPO_FILE   = a specific file within the repo that we care about
#     GM_REPO_BRANCH = master or whatever
#     GM_REPO_DIFF   = gitiles
#     GM_SINCE       = since time passed to --date=""
#     GM_GREP_PAT    = a text pattern for grep to search git show commit data
#     GM_SENDMAIL    = path to sendmail bin
#     GM_MAIL_TO     = email to send report
#     GM_DEBUG       = if true, outputs sendmail report string
#   (with set -u, script will exit if the above are not defined)
################################################################################
set -euo pipefail

# check binary dependencies
bins=("git" "grep" "printf" "cut" "date" "hostname" "basename")
for bin in "${bins[@]}"; do
    if [[ -z $(which $bin) ]]; then
        printf "dependency '$bin' does not appear to be installed - exiting.\n"
        exit 1
    fi
done

# clone repo locally
GM_REPO_PATH=${GM_REPO_URL##*/}
if [[ -d $GM_REPO_PATH ]]; then
	if [[ -n "$GM_REPO_BRANCH" ]]; then
		cd $GM_REPO_PATH && git checkout $GM_REPO_BRANCH && git pull && cd ..
	else
		rm -rf $GM_REPO_PATH && git clone $GM_REPO_URL
	fi
else
	if [[ -n "$GM_REPO_BRANCH" ]]; then
		git clone -b $GM_REPO_BRANCH $GM_REPO_URL
	else
		git clone $GM_REPO_URL
	fi
fi

# format SINCE
GM_SINCE=$(date --date="$GM_SINCE" "+%Y-%m-%d %H:%M:%S")

# build report
cd $GM_REPO_PATH

report_body=""
for git_hash in $(git log --since="$GM_SINCE" --pretty="%H" $GM_REPO_FILE)
do
    repo_diff_url=""
    if [[ -n "$GM_REPO_DIFF" ]]; then
        repo_path_for_url=${GM_REPO_URL#*://*/*/}
        repo_diff_url="<$GM_REPO_DIFF$repo_path_for_url/+/$git_hash%%5E%%21/#F0>\n"
    fi
    commit_marker=$(printf "\n" &&
        printf -- '*%.0s' {1..10} &&
        printf "\nCOMMIT ID: $git_hash\n\n" &&
        printf '%s' "$repo_diff_url" &&
        printf -- '*%.0s' {1..10})
    git_show=$(git show $git_hash | cut -c -80 | grep -C 3 "$GM_GREP_PAT" || true)
    if [[ -n "$git_show" ]]; then
        report_body="$report_body $commit_marker\n$git_show\n"
    fi
done

# send report, if necessary
if [[ -n "$report_body" ]]; then
    script_name=$(basename "$0")
    script_name=${script_name%%.*}
    from=${script_name##*/}"@"$(hostname -A)
    subject="Interesting git activity in: ${GM_REPO_URL#*://*/*/}"
    if [[ -n "$GM_DEBUG" ]]; then
        printf "To:$GM_MAIL_TO\nFrom:$from\nSubject: $subject\n\n$report_body \
			| $GM_SENDMAIL -t"
    else
        printf "To:$GM_MAIL_TO\nFrom:$from\nSubject: $subject\n\n$report_body" \
			| $GM_SENDMAIL -t
    fi
fi
