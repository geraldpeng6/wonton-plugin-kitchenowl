# shellcheck shell=bash
# scripts/smoke.sh / e2e/smoke.sh 的一项一项探测，跟着插件走。没写的项会 FAIL 并给出写法，不会默认放行。
#
# 只用套件保证的东西：变量 SMOKE_STATE（数据标记文件，data_write 覆盖写、data_check 读）、SMOKE_JAR、
# SMOKE_WEB_URL、SMOKE_WEB_ORIGIN、SMOKE_OWNER、SMOKE_BASE、SMOKE_TOKEN、SMOKE_INSTANCE，助手 web_get、dweb。

# sso=oidc：入口 /signin?launch=custom 打开即发起云吞登录（DISABLE_USERNAME_PASSWORD_LOGIN + DISABLE_ONBOARDING）。
# 上游 0.8 起自带 MCP（KITCHENOWL_MCP_ENABLED，/mcp），但端点一律要求用户 JWT（15 分钟 access token，
# 长期凭据只能在应用里由用户手动建），没有适合核心总线的静态凭据，本次不接（README / PR 里有说明），所以没有 MCP 项。
# shellcheck disable=SC2034  # SSO/MCP 由冒烟套件读取
SSO=oidc
MCP=0

# SPA 首页的 <title>：核心的登录页/错误页不会以 KitchenOwl 为标题。
web_assert() { grep -qF '<title>KitchenOwl</title>'; }

# ---------- 探针内部助手：只用套件保证的变量 ----------
ko_api() { # <路径> [curl 参数…]：带核心会话 jar 打应用 API。入口路径带 query，API 一律拼在 SMOKE_WEB_ORIGIN 上。
  curl_t "$SMOKE_WEB_MAX_TIME" "$SMOKE_WEB_ORIGIN$1" --noproxy '*' -b "$SMOKE_JAR" "${@:2}"
}

ko_token() { # 走一遍 OIDC 登录链换应用 access token（打到标准输出，诊断打到标准错误）。
  local resp login_url effective state code token
  resp="$(ko_api '/api/auth/oidc?provider=custom')" ||
    { echo "OIDC 登录地址请求失败：$resp"; return 1; }
  login_url="$(jq -re '.login_url // empty' <<<"$resp" 2>/dev/null)" || login_url=""
  [[ -n "$login_url" ]] || { echo "响应里没有 login_url：$(head -c 200 <<<"$resp")"; return 1; }
  # 跟随授权地址（auth.<基础域名>），最后一跳落回应用的 /signin/redirect?code=…&state=…，取整条 URL 解析。
  effective="$(curl_t "$SMOKE_WEB_MAX_TIME" "$login_url" --noproxy '*' -b "$SMOKE_JAR" -c "$SMOKE_JAR" \
    -o /dev/null -w '%{url_effective}' -L --max-redirs 25)" ||
    { echo "跟随授权地址失败：$effective"; return 1; }
  state="$(sed -n 's/.*[?&]state=\([^&]*\).*/\1/p' <<<"$effective")"
  code="$(sed -n 's/.*[?&]code=\([^&]*\).*/\1/p' <<<"$effective")"
  [[ -n "$state" && -n "$code" ]] || { echo "回跳地址里没有 code/state：$effective"; return 1; }
  resp="$(ko_api /api/auth/callback -X POST -H 'Content-Type: application/json' \
    --data "$(jq -cn --arg s "$state" --arg c "$code" '{state:$s,code:$c,device:"smoke"}')")" ||
    { echo "callback 请求失败：$resp"; return 1; }
  token="$(jq -re '.access_token // empty' <<<"$resp" 2>/dev/null)" || token=""
  [[ -n "$token" ]] || { echo "callback 没回 access_token：$(head -c 200 <<<"$resp")"; return 1; }
  printf '%s' "$token"
}

ko_call() { # <token> <方法> <路径> [JSON 正文]：带应用 Bearer 的 API 调用，响应打到标准输出。
  local token="$1" method="$2" path="$3" data="${4:-}" args=()
  [[ -n "$data" ]] && args=(-H 'Content-Type: application/json' -d "$data")
  curl_t "$SMOKE_WEB_MAX_TIME" "$SMOKE_WEB_ORIGIN$path" --noproxy '*' -X "$method" \
    -H "Authorization: Bearer $token" "${args[@]}"
}

identity_check() { # 应用认出的是主人本人：OIDC 自动建号的 username 就是云吞用户名（preferred_username）。
  local token me
  token="$(ko_token)" || { echo "登录链没拿到 token：$token"; return 1; }
  me="$(ko_call "$token" GET /api/user)" || { echo "当前用户接口失败：$me"; return 1; }
  jq -e --arg owner "$SMOKE_OWNER" '.username == $owner' <<<"$me" >/dev/null ||
    { echo "当前用户不是主人 $SMOKE_OWNER：$(head -c 200 <<<"$me")"; return 1; }
  echo "当前用户：$(jq -r '.username' <<<"$me")（OIDC 建号）" >&2
}

data_write() { # 建一条带随机标记的购物清单条目；家庭/清单 id 和标记覆盖写进 $SMOKE_STATE。
  local token hh hid lists lid marker added
  token="$(ko_token)" || { echo "登录链没拿到 token：$token"; return 1; }
  hh="$(ko_call "$token" GET /api/household)" || { echo "列家庭失败：$hh"; return 1; }
  hid="$(jq -r '.[0].id // empty' <<<"$hh" 2>/dev/null)" || hid=""
  if [[ -z "$hid" ]]; then # 冒烟起点是干净数据库：第一个登录的用户还没有家庭
    hh="$(ko_call "$token" POST /api/household '{"name":"云吞之家"}')" ||
      { echo "建家庭失败：$hh"; return 1; }
    hid="$(jq -r '.id // empty' <<<"$hh")"
  fi
  [[ -n "$hid" ]] || { echo "拿不到家庭 id：$(head -c 200 <<<"$hh")"; return 1; }
  lists="$(ko_call "$token" GET "/api/household/$hid/shoppinglist")" ||
    { echo "列清单失败：$lists"; return 1; }
  lid="$(jq -r '.[0].id // empty' <<<"$lists" 2>/dev/null)" || lid=""
  [[ -n "$lid" ]] || { echo "家庭 $hid 里拿不到购物清单：$(head -c 200 <<<"$lists")"; return 1; }
  marker="ko-probe-$(date +%Y%m%d%H%M%S)-$RANDOM"
  added="$(ko_call "$token" POST "/api/shoppinglist/$lid/add-item-by-name" "{\"name\":\"$marker\"}")" ||
    { echo "加条目失败：$added"; return 1; }
  [[ "$(jq -r '.name // empty' <<<"$added" 2>/dev/null)" == "$marker" ]] ||
    { echo "加条目响应不对：$(head -c 200 <<<"$added")"; return 1; }
  printf 'KO_HH_ID=%q\nKO_LIST_ID=%q\nKO_MARKER=%q\n' "$hid" "$lid" "$marker" >"$SMOKE_STATE" ||
    { echo "写不进标记文件 \$SMOKE_STATE"; return 1; }
}

data_check() { # 断言 data_write 写的条目还在、名字一字不差（升级/重装后各跑一次）。
  local token items
  [[ -f ${SMOKE_STATE:-} && -s "$SMOKE_STATE" ]] || { echo "标记文件里没有数据：先跑 data_write"; return 1; }
  # shellcheck source=/dev/null
  . "$SMOKE_STATE"
  [[ -n "${KO_LIST_ID:-}" && -n "${KO_MARKER:-}" ]] || { echo "标记文件不完整：$SMOKE_STATE"; return 1; }
  token="$(ko_token)" || { echo "登录链没拿到 token：$token"; return 1; }
  items="$(ko_call "$token" GET "/api/shoppinglist/$KO_LIST_ID/items")" ||
    { echo "读清单 $KO_LIST_ID 失败：$items"; return 1; }
  jq -e --arg m "$KO_MARKER" 'map(.name) | index($m) != null' <<<"$items" >/dev/null ||
    { echo "清单 $KO_LIST_ID 里找不到标记 $KO_MARKER，看到：$(head -c 300 <<<"$items")"; return 1; }
  echo "重装后数据核对通过：清单 $KO_LIST_ID 的条目 $KO_MARKER" >&2
}
