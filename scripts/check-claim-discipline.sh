#!/usr/bin/env bash
#
# check-claim-discipline.sh
#
# Fails if any public doc claims a compliance *outcome* instead of
# "supporting controls / evidence for <article>". See CONTRIBUTING.md
# ("Compliance-claim discipline") and LIMITATIONS.md.
#
# Scope: README.md, docs/**, examples/**, and other root *.md files.
# Excluded: internal_docs/ (internal strategy notes), and the two files
# that intentionally quote the banned phrases as negative examples
# (LIMITATIONS.md, CONTRIBUTING.md).
#
# Usage: scripts/check-claim-discipline.sh
set -euo pipefail

cd "$(dirname "$0")/.."

# Outcome-guaranteeing phrases that must never appear in public docs.
# Deliberately narrow: a bare "<vendor> is GDPR compliant" inside quoted
# dialogue is allowed; only operator-facing outcome guarantees are banned.
PATTERN='makes? (you|your|them|it)[^.]{0,40}compliant'
PATTERN+='|(ensures?|guarantees?)[^.]{0,25}(compliance|gdpr|nis2|dora|iso ?27001|ai act)'
PATTERN+='|compliance (is )?guaranteed'
PATTERN+='|fully compliant'
PATTERN+='|100% compliant'
PATTERN+='|[0-9]+ (hours?|days?|weeks?) to compliant'
PATTERN+='| to compliant\b'

# Build the list of files to scan (newline-delimited), excluding the two
# files that intentionally quote the banned phrases as negative examples.
file_list=$(
  {
    [ -f README.md ] && echo README.md
    find docs examples -type f -name '*.md' 2>/dev/null || true
    find . -maxdepth 1 -type f -name '*.md' 2>/dev/null || true
  } | sed 's#^\./##' | sort -u | grep -vxE '(LIMITATIONS|CONTRIBUTING)\.md' || true
)

if [ -z "$file_list" ]; then
  echo "check-claim-discipline: no files to scan"
  exit 0
fi

if matches=$(printf '%s\n' "$file_list" | tr '\n' '\0' | xargs -0 grep -niE "$PATTERN" 2>/dev/null); then
  echo "ERROR: compliance-claim discipline violation(s) found." >&2
  echo "Use 'supporting controls / evidence for <article>' wording instead." >&2
  echo "See CONTRIBUTING.md (Compliance-claim discipline) and LIMITATIONS.md." >&2
  echo >&2
  echo "$matches" >&2
  exit 1
fi

echo "check-claim-discipline: no compliance-outcome claims found in public docs"
