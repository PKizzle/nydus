#!/usr/bin/env bash
# Run a command as root, forwarding only the named environment variables.
#
#   sudo-env.sh NAME|GLOB... -- command [args...]
#
# Each NAME|GLOB is a variable name or a shell glob over names ('NYDUS_*').
# `sudo -E` is not portable: sudo-rs (the default sudo on Ubuntu 26.04)
# ignores it and runs with root's environment, and classic sudo resets PATH
# from secure_path even with it. `env` as the command forwards the values
# explicitly under both.
set -euo pipefail

patterns=()
while [ $# -gt 0 ] && [ "$1" != "--" ]; do
	patterns+=("$1")
	shift
done
if [ $# -lt 2 ] || [ ${#patterns[@]} -eq 0 ]; then
	echo "usage: $0 NAME|GLOB... -- command [args...]" >&2
	exit 2
fi
shift

assignments=()
while IFS= read -r -d '' entry; do
	name=${entry%%=*}
	for pattern in "${patterns[@]}"; do
		# shellcheck disable=SC2053 # the pattern is a glob on purpose
		if [[ $name == $pattern ]]; then
			assignments+=("$entry")
			break
		fi
	done
done < <(env -0)

exec sudo env "${assignments[@]}" "$@"
