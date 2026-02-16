#!/bin/sh
# mcp_context_prune.sh
# POSIX compliant context minimizer. Includes dynamic build artifact stripping.

MANIFEST=".llm_audit_manifest.json"
TMP_LIST="/tmp/mcp_prune_targets_$$"

# 1. Stage static bloat targets
for f in \
    "Cargo.lock" \
    "clients/vscode-mcp-j/LICENSE" \
    "clients/vscode-mcp-j/package-lock.json" \
    "clients/vscode-mcp-j/README.md" \
    "clients/vscode-mcp-j/resources/shield.svg" \
    "CONTRIBUTING.md" \
    "docs/INSTALL.md" \
    "docs/TROUBLESHOOTING.md" \
    "README.md"; do
    [ -f "$f" ] && echo "$f" >> "$TMP_LIST"
done

# 2. Stage dynamic artifact targets (ignore errors if dirs do not exist)
# Target specific pre-compiled bin dirs
find clients/vscode-mcp-j/bin -type f 2>/dev/null >> "$TMP_LIST"

# Target standard Rust/Node/TS artifact directories recursively
find . -type d \( -name "target" -o -name "dist" -o -name "out" -o -name "node_modules" \) -prune \
    -exec find {} -type f \; 2>/dev/null >> "$TMP_LIST"

# 3. Initialize JSON manifest
cat << 'EOF' > "$MANIFEST"
{
  "__metadata__": "Pruned Repository State",
  "system_directive": "Standard lockfiles, licenses, graphical assets, build artifacts, and generic documentation have been intentionally removed to optimize context limits. Core logic, architecture specs, and threat models remain intact. If your analysis requires a removed file, explicitly request it. Do not hallucinate implementations.",
  "pruned_assets": [
EOF

# 4. Execute deletion and append to manifest
FIRST=1
while IFS= read -r f; do
    rm -f "$f"
    if [ $FIRST -eq 1 ]; then
        printf '    "%s"' "$f" >> "$MANIFEST"
        FIRST=0
    else
        printf ',\n    "%s"' "$f" >> "$MANIFEST"
    fi
done < "$TMP_LIST"

# 5. Terminate JSON array and cleanup
printf '\n  ]\n}\n' >> "$MANIFEST"
rm -f "$TMP_LIST"

echo "Pruning complete. Expanded target manifest written to $MANIFEST"