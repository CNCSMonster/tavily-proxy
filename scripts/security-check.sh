#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# security-check.sh — 敏感凭证与密钥防外泄检查脚本
# 可作为 pre-commit 和 pre-push 钩子运行，防止将实际 API Key 推送到代码库。
# ==============================================================================

MODE="${1:---staged}"
FAILED=0

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "🔍 正在执行安全凭据检查 (模式: $MODE)..."

# 1. 检查敏感文件是否被意外添加进版本库
check_sensitive_files() {
    local files
    if [ "$MODE" = "--staged" ]; then
        files=$(git diff --cached --name-only || true)
    elif [ "$MODE" = "--push" ]; then
        files=$(git diff origin/main..HEAD --name-only 2>/dev/null || git diff HEAD~1..HEAD --name-only || true)
    else
        files=$(git status --porcelain | awk '{print $2}' || true)
    fi

    for f in $files; do
        case "$f" in
            config.toml|*.pem|*.key|id_rsa*|*.p12|*.pfx|.env|.env.*)
                echo -e "${RED}❌ 致命错误: 禁止提交敏感文件: $f${NC}"
                FAILED=1
                ;;
        esac
    done
}

# 2. 检查暂存区或提交差异中的真实密钥特征
check_secret_patterns() {
    local diff_content
    if [ "$MODE" = "--staged" ]; then
        diff_content=$(git diff --cached -U0 || true)
    elif [ "$MODE" = "--push" ]; then
        diff_content=$(git diff origin/main..HEAD -U0 2>/dev/null || git diff HEAD~1..HEAD -U0 || true)
    else
        diff_content=$(git diff -U0 || true)
    fi

    if [ -z "$diff_content" ]; then
        return 0
    fi

    # 仅过滤新增行 (+) 并排除 diff 标头 (+++)
    local added_lines
    added_lines=$(echo "$diff_content" | grep '^+[^+]' || true)

    if [ -z "$added_lines" ]; then
        return 0
    fi

    # 正则规则列表 (模式 | 说明)
    # 排除常见的测试占位符（如 tvly-aaa, tvly-dev-canary, sk-test, jev-xxx, tvly-xxx）
    local patterns=(
        'sk-or-v1-[a-zA-Z0-9]{32,}:OpenRouter API Key'
        'sk-(proj-)?[a-zA-Z0-9_-]{40,}:OpenAI API Key'
        'tvly-dev-[a-zA-Z0-9-]{30,}:Tavily Dev API Key'
        'tvly-[a-zA-Z0-9-]{30,}:Tavily Production API Key'
        'jev-[a-zA-Z0-9_-]{20,}:Jev AI API Key'
        'BEGIN [A-Z ]*PRIVATE KEY:私钥凭据文件'
    )

    for entry in "${patterns[@]}"; do
        local regex="${entry%%:*}"
        local desc="${entry##*:}"

        # 匹配新增行中是否命中模式，并排除明显的占位符
        # （jev-concurrency 开头的是实验文档文件名，不是密钥）
        local matched
        matched=$(echo "$added_lines" | grep -E "$regex" | grep -v -E '(tvly-dev-xxx|tvly-dev-yyy|tvly-dev-zzz|tvly-prod-aaa|tvly-xxx|tvly-yyy|tvly-zzz|sk-both|sk-test|tvly-dev-canary|-canary-|LOOKALIKE|jev-concurrency|placeholder|EXAMPLE|dummy)' || true)

        if [ -n "$matched" ]; then
            echo -e "${RED}❌ 发现疑似真实敏感凭证 (${desc})!${NC}"
            # 脱敏输出前 10 个字符后跟 ***
            echo "$matched" | sed -E 's/(tvly-[a-zA-Z0-9]{6})[a-zA-Z0-9-]+/\1...***/g' \
                             | sed -E 's/(sk-or-v1-[a-zA-Z0-9]{6})[a-zA-Z0-9-]+/\1...***/g' \
                             | sed -E 's/(sk-[a-zA-Z0-9]{6})[a-zA-Z0-9-]+/\1...***/g' \
                             | sed -E 's/(jev-[a-zA-Z0-9]{6})[a-zA-Z0-9-]+/\1...***/g' \
                             | head -n 5
            FAILED=1
        fi
    done
}

check_sensitive_files
check_secret_patterns

if [ "$FAILED" -ne 0 ]; then
    echo -e "${RED}🛑 安全检查未通过！已中止提交/推送。请从文件中移除真实敏感密钥后重试。${NC}"
    echo -e "${YELLOW}提示: 请将实际 key 存放在环境变量中（如 OPENROUTER_API_KEY、TAVILY_API_KEY），或在 config.toml（已 gitignore）中通过 api_key_env 配置。${NC}"
    exit 1
else
    echo -e "${GREEN}✅ 安全检查通过：未检测到敏感密钥或凭证${NC}"
    exit 0
fi
