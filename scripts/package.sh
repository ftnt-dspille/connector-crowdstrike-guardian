#!/usr/bin/env bash
# Build the connector bundle FortiSOAR installs.
#
# The tarball contains the single `crowdstrike_guardian/` directory holding the
# git-tracked files inside it, minus the development-only ones. Packaging the
# working directory wholesale is how a small bundle becomes huge: `.venv/`
# gets swept in.
set -euo pipefail

cd "$(dirname "$0")/.."
NAME=$(python3 -c "import json;print(json.load(open('crowdstrike_guardian/info.json'))['name'])")
VERSION=$(python3 -c "import json;print(json.load(open('crowdstrike_guardian/info.json'))['version'])")
OUT="dist/${NAME}-${VERSION}.tgz"

# Never shipped: tests, generators, docs and repo furniture live outside the
# package directory anyway; inside it, skip nothing but VCS noise and the
# playbook compiler (the appliance imports playbooks.json, never rebuilds it).
EXCLUDE='^(\.DS_Store$|__.*/$|.*\.pyc$|crowdstrike_guardian/playbooks/build\.py$)'

FILES=()
while IFS= read -r f; do FILES+=("$f"); done < <(git ls-files -- "crowdstrike_guardian/" | grep -Ev "$EXCLUDE" || true)
if [ ${#FILES[@]} -eq 0 ]; then
    echo "package: no files matched - run from a git checkout" >&2
    exit 1
fi

for required in info.json connector.py operations.py client.py models.py playbooks/playbooks.json; do
    printf '%s\n' "${FILES[@]}" | grep -qx "crowdstrike_guardian/$required" \
        || { echo "package: crowdstrike_guardian/$required missing from the bundle (git add it?)" >&2; exit 1; }
done

rm -rf dist && mkdir -p "dist/stage/${NAME}"
for f in "${FILES[@]}"; do
    mkdir -p "dist/stage/$(dirname "$f")"
    cp "$f" "dist/stage/$f"
done
tar czf "$OUT" -C dist/stage "${NAME}"
echo "built $OUT ($(du -h "$OUT" | cut -f1))"
