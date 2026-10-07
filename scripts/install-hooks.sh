#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(git rev-parse --show-toplevel)"
HOOKS_DIR="$ROOT_DIR/.git/hooks"

echo "正在安装 Git 安全钩子到 $HOOKS_DIR..."

cat << 'EOF' > "$HOOKS_DIR/pre-commit"
#!/usr/bin/env bash
# 提交前敏感信息检查
"$(git rev-parse --show-toplevel)/scripts/security-check.sh" --staged
EOF
chmod +x "$HOOKS_DIR/pre-commit"

cat << 'EOF' > "$HOOKS_DIR/pre-push"
#!/usr/bin/env bash
# 推送前敏感信息检查
"$(git rev-parse --show-toplevel)/scripts/security-check.sh" --push
EOF
chmod +x "$HOOKS_DIR/pre-push"

echo "✅ Git pre-commit 与 pre-push 钩子安装成功！"
