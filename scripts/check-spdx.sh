#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Fails if a tracked or new Go file lacks the SPDX licence header.
set -euo pipefail

missing=0
while IFS= read -r f; do
	if ! head -n 3 "$f" | grep -q 'SPDX-License-Identifier: Apache-2.0'; then
		echo "missing SPDX header: $f"
		missing=1
	fi
done < <(git ls-files --cached --others --exclude-standard -- '*.go')

if [ "$missing" -ne 0 ]; then
	echo
	echo "Add this as the first line of each file listed above:"
	echo "// SPDX-License-Identifier: Apache-2.0"
	exit 1
fi
echo "SPDX headers OK"
