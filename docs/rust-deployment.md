# Rust 服务部署

本文介绍 Rust 服务的独立部署方式。服务监听 HTTP，由 Nginx、Apache 或其他反向代理负责公网 TLS。Rust 迁移仍在进行中；切换旧站前请先在副本上验证协议、数据库和纹理文件。

## 构建

需要 Rust stable 工具链。源码构建：

```sh
cargo build --locked --release
```

可执行文件位于 `target/release/blessing-skin-rs`（Windows 为 `target/release/blessing-skin-rs.exe`）。仓库 CI 会在原生 runner 上检查和构建以下目标：

| 平台           | Rust target                 |
| -------------- | --------------------------- |
| Linux x86_64   | `x86_64-unknown-linux-gnu`  |
| Linux ARM64    | `aarch64-unknown-linux-gnu` |
| Windows x86_64 | `x86_64-pc-windows-msvc`    |
| macOS x86_64   | `x86_64-apple-darwin`       |
| macOS ARM64    | `aarch64-apple-darwin`      |

运行系统需能提供对应的系统库；不要把 Linux 构建产物复制到 Windows 或 macOS。构建产物不包含 Docker 镜像。

## 配置与旧安装

程序启动时会从当前工作目录读取 `.env`。旧站的 `.env` 可作为起点；将 [rust.env.example](../rust.env.example) 中的 Rust 专用项合并进去。PHP 专用项（例如 `CACHE_DRIVER`、`SESSION_DRIVER`、`QUEUE_CONNECTION`、`REDIS_*`）不会被 Rust 服务使用。

| 变量                                               | 用途与默认值                                                                                                           |
| -------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| `BS_LISTEN`                                        | 监听地址，默认 `127.0.0.1:3000`；建议仅绑定回环地址并由反向代理访问                                                    |
| `DB_CONNECTION`                                    | `sqlite`、`mysql`、`mariadb`、`pgsql`、`postgres` 或 `postgresql`，默认 `mysql`                                        |
| `DB_DATABASE`                                      | SQLite 文件路径；MySQL/PostgreSQL 数据库名                                                                             |
| `DB_HOST`, `DB_PORT`, `DB_USERNAME`, `DB_PASSWORD` | MySQL/PostgreSQL 连接参数                                                                                              |
| `DB_SOCKET`                                        | 可选的 MySQL/MariaDB Unix socket 路径；设定后通过该 socket 连接                                                        |
| `DB_PREFIX`                                        | 旧表前缀，只允许 ASCII 字母、数字和下划线                                                                              |
| `DB_FOREIGN_KEYS`                                  | SQLite 中设为 `false` 或 `0` 可关闭外键检查                                                                            |
| `STORAGE_PATH`                                     | 默认 `storage`；Passport 公钥默认从此目录的 `oauth-public.key` 读取                                                    |
| `PUBLIC_PATH`                                      | 默认 `public`；前端静态资源从此目录的 `app/` 子目录提供                                                                |
| `TEXTURES_DIR`                                     | 默认 `$STORAGE_PATH/textures`；请指向旧站实际纹理目录                                                                  |
| `PLUGINS_DIR`                                      | 默认 `$STORAGE_PATH/plugins`；只扫描 `.wasm` 组件，不运行 PHP 插件                                                     |
| `APP_URL`                                          | 对外站点 URL，默认 `http://localhost`                                                                                  |
| `APP_LOCALE`                                       | 默认 `zh_CN`                                                                                                           |
| `APP_KEY`                                          | 可选；新安装会在 `$STORAGE_PATH/app.key` 生成，用于签发网页登录 session。切换时用户需要重新登录                        |
| `PASSPORT_PUBLIC_KEY`                              | 可选；公钥文本或 `file:///绝对路径`。未设置时读取 `$STORAGE_PATH/oauth-public.key`                                     |
| `PASSPORT_PRIVATE_KEY`                             | 签发 OAuth 令牌所需；私钥文本或 `file:///绝对路径`。未设置时读取 `$STORAGE_PATH/oauth-private.key`。勿公开或更换旧私钥 |
| `PWD_METHOD`, `SALT`                               | 兼容旧密码格式所需设置；保留旧站的原值                                                                                 |
| `MAIL_MAILER`                                      | `smtp`、`log` 或 `array`；其余 SMTP 参数沿用 `MAIL_*`                                                                  |

Rust 直接读取旧数据库表和纹理文件；新站安装方法见 [rust-install.md](rust-install.md)，不要对已有 PHP 站点运行安装命令。切换前先备份数据库和纹理目录，并确认 `DB_PREFIX`、`TEXTURES_DIR`、`STORAGE_PATH` 与旧站一致。现有 OAuth/Passport 令牌验证依赖旧公钥；签发新令牌还需要旧 Passport 私钥，二者都不要更换。`/oauth/token` 支持 Passport `password` 与 `refresh_token` 授权，并沿用默认的一年令牌期限；密码授权需要旧数据库中有效的 `password_client`。Rust 已提供 Passport `/oauth/token` 的 password/refresh_token 授权、登录态下的 `/oauth/tokens` 列表/撤销、`/oauth/scopes` scope 列表，以及 `/oauth/personal-access-tokens` 个人访问令牌管理；个人访问令牌接口要求有效网页登录 session 和旧的 Passport personal access client。Rust 当前没有 PHP 插件兼容层。

官方发行包包含 `public/app` 下的旧站前端 bundle；从源码部署时，可运行 `yarn install --frozen-lockfile` 和 `yarn build` 生成这些资源。Rust 服务通过 `PUBLIC_PATH/app` 提供它们。

## 版本升级

从 [GitHub Releases](https://github.com/HELPMEEADICE/blessing-skin-rs/releases) 下载与你的系统和架构匹配的软件包。发行包包含独立 Rust 程序、前端资源和部署文档。升级前备份数据库与纹理目录；停止当前服务后替换程序和 `public/app`，保留 `.env`、`storage`、Passport 密钥和纹理文件，再启动服务并检查 `/health/ready`。已有 PHP 站点不需要重新运行安装器。

管理后台的“版本更新”页面提供当前程序版本和发行页入口。Rust 服务不在运行中覆盖自身文件，`POST /admin/update/download` 会返回人工升级提示。

## 本地启动

在服务工作目录准备 `.env`，确认数据库和文件目录可读写，再运行：

```sh
./blessing-skin-rs
```

Windows PowerShell：

```powershell
./blessing-skin-rs.exe
```

`GET /health/live` 检查进程是否响应，`GET /health/ready` 检查数据库是否可用。服务在数据库连接失败时仍会启动以提供健康端点，但业务接口不可用，应让进程管理器通过 readiness 检查判定为未就绪。

## Linux systemd 示例

将二进制放在 `/opt/blessing-skin-server/`，将数据放在 `/var/lib/blessing-skin-server/`，并创建专用无登录用户 `blessing`。把环境文件权限限制为服务用户可读：

```ini
# /etc/systemd/system/blessing-skin-server.service
[Unit]
Description=Blessing Skin Rust Server
After=network-online.target
Wants=network-online.target

[Service]
User=blessing
Group=blessing
WorkingDirectory=/var/lib/blessing-skin-server
EnvironmentFile=/etc/blessing-skin-server.env
ExecStart=/opt/blessing-skin-server/blessing-skin-rs
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/var/lib/blessing-skin-server

[Install]
WantedBy=multi-user.target
```

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now blessing-skin-server
sudo systemctl status blessing-skin-server
```

如果 SQLite 数据库或纹理位于其他目录，将对应目录加入 `ReadWritePaths` 并确保 `blessing` 用户有权限。

## Nginx 反向代理示例

```nginx
server {
    listen 443 ssl;
    server_name skin.example.com;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        client_max_body_size 64m;
    }
}
```

将 `APP_URL` 设为 `https://skin.example.com`，并在反向代理处配置证书和 HTTP 到 HTTPS 跳转。

## 迁移切换

切换按“只读影子比对 → 单业务域灰度 → 全站 Rust”推进。每个阶段至少观察 24 小时；任一阶段不满足退出条件时，不进入下一阶段。

### 切换前

1. 备份数据库和完整纹理目录，记录备份时间、文件数量及纹理哈希清单。先在隔离副本上验证，不直接对唯一生产数据做试运行。
2. 为 Rust 配置与旧站相同的 `DB_CONNECTION`、`DB_PREFIX`、`DB_SOCKET`（如有）、`TEXTURES_DIR`、`PWD_METHOD`、`SALT`、Passport 公私钥及 `APP_URL`。不要运行新站安装器，也不要更换 Passport 密钥。
3. 用 PHP 生成并保存代表性请求样本：Yggdrasil/CustomSkin、OAuth、用户与管理接口、纹理读取、图片预览和页面请求。记录状态码、内容类型、JSON 字段与错误体、ETag/缓存头及可稳定比较的响应内容；影子比较器仅重放无 session 和文件缓存副作用的只读白名单，上传、预览缓存及网页登录页面需在隔离副本中另行验证。
4. 检查所需插件是否已有 WASM 移植版本。Rust 不执行 PHP 插件；未移植插件的功能必须在切换前安排替代或接受停用。

### 只读影子比对（至少 24 小时）

- 只对明确列入只读白名单的请求做影子调用。认证挑战、OAuth 授权/令牌、任何写请求，以及可能更新 session、计数或状态的路由不得复制。
- 影子请求发到隔离的数据副本或只读凭据；不把 Rust 响应返回给访客，也不向 Rust 镜像写请求。比较 PHP 与 Rust 的状态码、内容类型、协议字段、错误语义、ETag/缓存头和纹理哈希。忽略预先标记的动态值（例如时间戳和随机 ID），但不能忽略业务字段差异。
- 记录每个样本的结果、差异和 Rust/PHP 错误率基线。存在未解释的数据或响应差异时，修复并重新开始本阶段的 24 小时观察。
  维护者可使用仓库内的只读探针比较器重放这些 GET 样本。它只接受显式白名单路由，拒绝 session、认证挑战、安装和写入路由，也不跟随重定向；头像/预览缓存等可能写文件的路由需在隔离副本上单独验证。比较器要求 Python 3.10+ 标准库：

```sh
export BS_SHADOW_OAUTH_TOKEN='只读 User.Read 测试令牌'
python3 tools/compat_compare.py \
  --php-url http://127.0.0.1:8080 \
  --rust-url http://127.0.0.1:3000 \
  --fixtures docs/compat-shadow.example.json
```

可在本机复制并修改 [示例探针](compat-shadow.example.json)，令牌应从环境变量传入，不要写入 fixture。动态 JSON 字段可用 `ignore_json_pointers` 标注；响应体中的其他字段、状态码和缓存相关头仍会比较。工具只打印差异类别、JSON 字段路径或非 JSON 响应的 SHA-256，不打印响应内容。

### 单业务域灰度（每个域至少 24 小时）

- 每个数据域在同一时刻只能由一个后端处理写入。将一个业务域的读写整体交给 Rust 后，停止 PHP 对该域的写入；禁止双写和写请求镜像。按域切换前，确认 Rust 写入的数据仍符合 PHP 回退读取格式。
- 登录、登出、网页登录授权及依赖网页登录 session 的页面和接口必须作为一个整体切换。切换后网页用户需重新登录；OAuth/Passport 令牌仍应使用旧密钥验证。
- 每个域观察至少 24 小时，核对数据库记录、玩家关联、纹理哈希与纹理文件内容，再切换下一个域。只有所有域通过后才进行全站切换。

### 立即回退条件与操作

出现任一数据库/纹理数据不一致时立即回退。Rust 错误率超过 PHP 切换前基线的两倍并持续 5 分钟，也立即回退；协议客户端无法登录、旧令牌失效或纹理内容错误时无需等待阈值。

回退时先停止 Rust 对受影响域的写入，再把该域流量切回 PHP；不要回滚或重建共享数据库和纹理目录。保留 Rust/PHP 日志、差异样本及触发时间用于修复。若 Rust 写入尚未被 PHP 安全读取验证，先保持该域停写并恢复兼容性，不能通过丢弃新数据来掩盖差异。

### PHP 回退窗口

全站切换后至少保留可启动的 PHP 部署和原路由配置 7 天。此期间持续观察协议错误、写入一致性、OAuth 令牌和纹理校验；达到 7 天且没有未解决差异或回退事件后，才移除 PHP 回退部署。删除 PHP 运行环境前再次备份数据库、纹理目录和审计记录。
