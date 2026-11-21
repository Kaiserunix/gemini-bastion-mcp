/**
 * Interactive OAuth 2.1 + Cloudflare Tunnel Setup & Handshake Walkthrough Data
 * Aligned with docker/docker-compose.yml, .env.example, src/config.ts, and src/auth/*.ts
 */
export const SETUP_MODES = [
  {
    id: 'cloudflare',
    tabEn: '☁️ Option A: Cloudflare Tunnel + Docker (Recommended)',
    tabZh: '☁️ 方案 A：Cloudflare Tunnel + Docker（零端口暴露推荐）',
    steps: [
      {
        num: 1,
        titleEn: 'Generate Compose-Safe scrypt Password Hash & Signing Secret',
        titleZh: '生成兼容 Docker Compose 的 scrypt 密码哈希与签名密钥',
        noteEn:
          'Use scrypt:<saltHex>:<keyHex> so Docker Compose never misinterprets $ characters in .env. Requires >= 32 non-placeholder chars for OAUTH_SIGNING_SECRET in production.',
        noteZh:
          '推荐使用冒号分隔的 scrypt:<saltHex>:<keyHex> 格式，彻底避免 Docker Compose 将 $ 误解析为空变量；生产环境要求 OAUTH_SIGNING_SECRET 不少于 32 字节。',
        code: `node -e 'const c=require("node:crypto"),s=c.randomBytes(16).toString("hex");console.log("ADMIN_PASSWORD_HASH=scrypt:"+s+":"+c.scryptSync(process.argv[1],s,32,{N:16384,r:8,p:1}).toString("hex"))' 'your-strong-operator-password'
node -e 'console.log("OAUTH_SIGNING_SECRET=" + require("node:crypto").randomBytes(32).toString("hex"))'`,
      },
      {
        num: 2,
        titleEn: 'Configure Root .env (OAuth 2.1 DCR + Scoped Credentials)',
        titleZh: '配置根目录 .env（OAuth 2.1 DCR 域名白名单与分级密钥）',
        noteEn:
          'PUBLIC_DOMAIN must be an origin without path/query. OAUTH_ALLOWED_REDIRECT_HOSTS pre-allows Web Gemini & AI Studio; Google Connected Apps redirect URIs are built-in.',
        noteZh:
          'PUBLIC_DOMAIN 仅填写协议与域名（不含路径）；OAUTH_ALLOWED_REDIRECT_HOSTS 默认放行 Web Gemini，且内置 Google Connected Apps 回调域名规则。',
        code: `git clone https://github.com/Kaiserunix/gemini-bastion-mcp.git
cd gemini-bastion-mcp
cp .env.example .env

# Required core settings in .env:
PUBLIC_DOMAIN={{DOMAIN}}
TRUST_CF_CONNECTING_IP=true
ADMIN_PASSWORD_HASH=scrypt:<paste-from-step-1>
OAUTH_SIGNING_SECRET=<paste-64-hex-chars-from-step-1>
OAUTH_ALLOWED_REDIRECT_HOSTS=gemini.google.com,aistudio.google.com,accounts.google.com,claude.ai,chatgpt.com,localhost,127.0.0.1

# Gateway-only integrations (stripped from UID 1002 workspace subprocesses):
GH_TOKEN=ghp_your_scoped_pat
CLOUDFLARE_ACCOUNT_ID=your_cf_account_id
CLOUDFLARE_READONLY_API_TOKEN=your_cf_readonly_token
CLOUDFLARE_API_TOKEN=your_cf_edit_token
OPENAI_API_KEY=sk-your_openai_or_codex_key`,
      },
      {
        num: 3,
        titleEn: 'Bind Cloudflare Zero Trust Tunnel (Zero Host Ports Exposed)',
        titleZh: '绑定 Cloudflare Zero Trust 隧道（宿主机零端口暴露）',
        noteEn:
          'In Cloudflare Zero Trust -> Networks -> Tunnels, route your public hostname to http://gateway:8787 on edge_net. Keep CLOUDFLARE_TUNNEL_TOKEN in docker/.env — cloudflared never mounts ../.env!',
        noteZh:
          '在 Cloudflare Zero Trust 控制台将公开域名指向容器内网地址 http://gateway:8787。将隧道 Token 放入 docker/.env，使 cloudflared 容器绝不挂载主 .env 密钥文件。',
        code: `# 1. Cloudflare Zero Trust -> Networks -> Tunnels -> Public Hostname:
#    Public Hostname : {{HOST}}
#    Service Type    : HTTP
#    Service URL     : gateway:8787

# 2. Isolate tunnel token in docker/.env & launch stack:
echo "CLOUDFLARE_TUNNEL_TOKEN=eyJhIjoi..." > docker/.env
docker compose -f docker/docker-compose.yml up -d --build

# 3. Verify health & RFC 9728 / RFC 8414 OAuth discovery:
curl -fsS {{DOMAIN}}/healthz
curl -fsS {{DOMAIN}}/.well-known/oauth-protected-resource`,
      },
      {
        num: 4,
        titleEn: 'Optional: Fail-Closed Google / GitHub Operator SSO',
        titleZh: '可选：启用默认关闭 (Fail-Closed) 的 Google / GitHub 管理员单点登录',
        noteEn:
          'Enable one-tap operator approval on /oauth/authorize and /admin/login. In NODE_ENV=production, startup fails closed if client credentials are set without a non-empty allowlist.',
        noteZh:
          '在 /oauth/authorize 授权页与 /admin 登录页启用一键登录。生产模式下若配置了 Client ID/Secret 却未配置非空白名单，网关将在启动阶段直接熔断拒绝运行。',
        code: `# Register OAuth Callback URLs in Google Cloud / GitHub Developer Settings:
#   Google Callback : {{DOMAIN}}/auth/idp/google/callback
#   GitHub Callback : {{DOMAIN}}/auth/idp/github/callback

# Append to .env (both credentials AND allowlist are mandatory):
GOOGLE_OAUTH_CLIENT_ID=...
GOOGLE_OAUTH_CLIENT_SECRET=...
GOOGLE_OAUTH_ALLOWED_EMAILS=you@yourdomain.com

GITHUB_OAUTH_CLIENT_ID=...
GITHUB_OAUTH_CLIENT_SECRET=...
GITHUB_OAUTH_ALLOWED_USERS=your-github-handle`,
      },
      {
        num: 5,
        titleEn: 'Connect Web Gemini, Claude.ai & ChatGPT (1-Gate Policy)',
        titleZh: '接入 Web Gemini、Claude.ai 与 ChatGPT（配置唯一写闸门策略）',
        noteEn:
          'Paste your Streamable HTTP /mcp URL into Connected Apps / Custom Connectors. Set Tools 1–9 to Always Allow and keep publish_changes on Ask Before Running.',
        noteZh:
          '将 /mcp 地址填入 AI 客户端自定义连接器。开启工具 1–9 始终允许，仅保留 publish_changes 每次询问，获得丝滑零弹窗研发体验。',
        code: `# Stateless Streamable HTTP MCP Endpoint (POST /mcp):
{{DOMAIN}}/mcp

# Static Client Fallback (only if a client lacks RFC 7591 DCR):
#   Authorization URL : {{DOMAIN}}/oauth/authorize
#   Token URL         : {{DOMAIN}}/oauth/token
#   Operator Console  : {{DOMAIN}}/admin`,
      },
    ],
  },
  {
    id: 'nginx',
    tabEn: '🔒 Option B: Nginx TLS Reverse Proxy (Loopback)',
    tabZh: '🔒 方案 B：Nginx TLS 反向代理（本机回环绑定）',
    steps: [
      {
        num: 1,
        titleEn: 'Bind Gateway Strictly to 127.0.0.1 & Set TRUST_CF_CONNECTING_IP=false',
        titleZh: '仅绑定 127.0.0.1 本机回环端口并关闭 CF 头信任',
        noteEn:
          'When terminating TLS directly on Nginx (without Cloudflare in front), set TRUST_CF_CONNECTING_IP=false so clients cannot spoof CF-Connecting-IP rate-limit headers.',
        noteZh:
          '若由 VPS 本地 Nginx 直接终结 TLS（未经过 Cloudflare 代理），请务必设置 TRUST_CF_CONNECTING_IP=false 防止伪造请求头绕过限流。',
        code: `# docker-compose.override.yml
services:
  gateway:
    ports:
      - "127.0.0.1:8787:8787"

# Start gateway only (without cloudflared):
docker compose -f docker/docker-compose.yml up -d --build gateway`,
      },
      {
        num: 2,
        titleEn: 'Proxy HTTPS to Loopback with Buffering Disabled',
        titleZh: '配置 Nginx 反代（关闭缓冲以支持 Streamable HTTP 与 /admin SSE）',
        noteEn:
          'Disable proxy_buffering so stateless Streamable HTTP /mcp responses and /admin live SSE job logs stream cleanly.',
        noteZh:
          '关闭 proxy_buffering，确保 /mcp 流式响应与 /admin 实时任务日志 SSE 零延迟推送。',
        code: `# /etc/nginx/sites-available/{{HOST}}.conf
server {
  listen 443 ssl http2;
  server_name {{HOST}};

  location / {
    proxy_pass http://127.0.0.1:8787;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_buffering off;
    proxy_read_timeout 300s;
  }
}`,
      },
    ],
  },
  {
    id: 'local',
    tabEn: '💻 Option C: Local Dev & MCP Inspector (Node >= 22.23.4)',
    tabZh: '💻 方案 C：本地开发与 MCP Inspector 联调',
    steps: [
      {
        num: 1,
        titleEn: 'Install Dependencies, Keep DATA_DIR Outside WORKSPACES_DIR & Run',
        titleZh: '安装依赖、隔离存储目录并启动本地热重载服务',
        noteEn:
          'loadConfig() enforces non-overlapping canonical paths between DATA_DIR/ARTIFACTS_DIR and WORKSPACES_DIR even in local development.',
        noteZh:
          'loadConfig() 在本地同样强制校验 DATA_DIR/ARTIFACTS_DIR 与 WORKSPACES_DIR 物理路径不重叠。',
        code: `npm install
cp .env.example .env

# Minimal local .env overrides:
# PUBLIC_DOMAIN=http://localhost:8787
# DATA_DIR=./.local/data
# WORKSPACES_DIR=./.local/workspaces
# ARTIFACTS_DIR=./.local/data/artifacts

npm run typecheck && npm test
npm run dev`,
      },
    ],
  },
];

export const OAUTH_SEQUENCE = [
  {
    rfc: '1 · RFC 9728',
    route: 'GET /.well-known/oauth-protected-resource',
    descEn:
      'Unauthenticated /mcp call returns 401; client discovers canonical resource ({{DOMAIN}}/mcp), scopes (mcp:tools, mcp:read, mcp:write), and auth server.',
    descZh:
      '首次请求 /mcp 返回 401 后，客户端自动发现受保护资源标识 ({{DOMAIN}}/mcp)、权限范围及授权服务器元数据。',
  },
  {
    rfc: '2 · RFC 8414',
    route: 'GET /.well-known/oauth-authorization-server',
    descEn:
      'Advertises /oauth/authorize, /oauth/token, /oauth/revoke, /oauth/register, and enforces code_challenge_methods_supported: ["S256"].',
    descZh:
      '宣告授权、令牌、吊销与动态注册端点，强制要求 PKCE S256 挑战算法。',
  },
  {
    rfc: '3 · RFC 7591 DCR',
    route: 'POST /oauth/register',
    descEn:
      'Registers up to 16 redirect URIs per client (validating Google Connected Apps patterns & OAUTH_ALLOWED_REDIRECT_HOSTS; rate-limited per IP).',
    descZh:
      '单客户端支持注册最多 16 个回调地址（校验 Google Connected Apps 专属回调规则与域名白名单，内置 IP 限流）。',
  },
  {
    rfc: '4 · PKCE + RFC 8707',
    route: 'GET & POST /oauth/authorize',
    descEn:
      'Preserves state up to 8192 bytes, binds RFC 8707 resource, and verifies operator password (scrypt) or fail-closed Google/GitHub IdP with CSRF protection.',
    descZh:
      '无损保留最大 8KB state 参数并绑定 RFC 8707 resource，通过管理员密码或 Google/GitHub 白名单 SSO 完成授权确认。',
  },
  {
    rfc: '5 · Family Rotation',
    route: 'POST /oauth/token → POST /mcp',
    descEn:
      'Issues 1h access + 30d refresh token under token_family_id. Concurrent retries within 60s succeed smoothly; replay after 60s revokes the entire family.',
    descZh:
      '签发 1 小时访问令牌与 30 天刷新令牌，支持 60 秒并发重试宽限期；宽限期外重放旧令牌将立即熔断吊销整个令牌家族。',
  },
];
