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

程序启动时会从当前工作目录读取 `.env`。旧站的 `.env` 可作为起点；将 [rust.env.example](../rust.env.example) 中的 Rust 专用项合并进去。PHP 专用项（例如 `CACHE_DRIVER`、`SESSION_DRIVER`、`QUEUE_CONNECTION`、`REDIS_*`）不会被 Rust 服务使用。 对旧 Laravel 保留值也保持兼容：`null` / `(null)` 按未配置处理，`empty` / `(empty)` 按空字符串处理；例如旧示例中的 `PLUGINS_DIR=null` 会采用 Rust 的默认插件目录。

| 变量                                                                                    | 用途与默认值                                                                                                                                                                                                                                          |
| --------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `BS_LISTEN`                                                                             | 监听地址，默认 `127.0.0.1:3000`；建议仅绑定回环地址并由反向代理访问                                                                                                                                                                                   |
| `DB_CONNECTION`                                                                         | `sqlite`、`mysql`、`mariadb`、`pgsql`、`postgres` 或 `postgresql`，默认 `mysql`                                                                                                                                                                       |
| `DB_DATABASE`                                                                           | SQLite 文件路径（未设置时默认 database/database.sqlite）；MySQL/PostgreSQL 数据库名（默认 forge）                                                                                                                                                     |
| `DATABASE_URL`                                                                          | 可选的旧 Laravel 数据库 URL；设置后按 `DB_CONNECTION` 解析，并优先于独立的 `DB_HOST`、`DB_PORT`、`DB_DATABASE`、`DB_USERNAME` 和 `DB_PASSWORD`                                                                                                        |
| `DB_HOST`, `DB_PORT`, `DB_USERNAME`, `DB_PASSWORD`                                      | 未设置 DATABASE_URL 时使用的 MySQL/PostgreSQL 连接参数                                                                                                                                                                                                |
| `DB_SOCKET`                                                                             | 可选的 MySQL/MariaDB Unix socket 路径；设定后通过该 socket 连接                                                                                                                                                                                       |
| `MYSQL_ATTR_SSL_CA`                                                                     | 可选的 MySQL/MariaDB CA 证书路径；连接 URL 的 `ssl-ca` 查询值会被该旧环境变量覆盖                                                                                                                                                                     |
| `DB_PREFIX`                                                                             | 旧表前缀，只允许 ASCII 字母、数字和下划线                                                                                                                                                                                                             |
| `DB_FOREIGN_KEYS`                                                                       | SQLite 中设为 `false` 或 `0` 可关闭外键检查                                                                                                                                                                                                           |
| `STORAGE_PATH`                                                                          | 默认 `storage`；Passport 公钥默认从此目录的 `oauth-public.key` 读取                                                                                                                                                                                   |
| `PUBLIC_PATH`                                                                           | 默认 `public`；提供 `app/` 前端 bundle 和其余公开静态文件；隐藏文件、`storage/` 路径和 PHP 源文件不会通过 Rust 服务                                                                                                                                   |
| `TEXTURES_DIR`                                                                          | 默认 `$STORAGE_PATH/textures`；请指向旧站实际纹理目录                                                                                                                                                                                                 |
| `PLUGINS_DIR`                                                                           | 默认 `$STORAGE_PATH/plugins`；只扫描 `.wasm` 组件，不运行 PHP 插件                                                                                                                                                                                    |
| `RUST_RELEASES_API_URL`                                                                 | 默认查询本项目 GitHub latest release；设为空字符串可关闭管理后台版本检查。检查失败不影响服务，升级仍由管理员下载匹配平台发行包并手动替换程序和前端资源                                                                                                |
| `WASM_PLUGIN_REGISTRY_URL`                                                              | 可选；管理员插件市场使用的可信版本 1 JSON 清单 URL，必须为公网 HTTPS；未设置时市场安装功能关闭                                                                                                                                                        |
| `APP_URL`                                                                               | 对外站点 URL，默认 `http://localhost`                                                                                                                                                                                                                 |
| `APP_LOCALE`                                                                            | 默认 `zh_CN`                                                                                                                                                                                                                                          |
| `BS_LEGACY_APP_VERSION`                                                                 | 旧协议和页面暴露的 Blessing Skin 版本，默认 `6.0.2`；旧 PHP 分支版本不同时可覆盖。Rust 二进制更新检查仍使用 Rust 发布版本                                                                                                                             |
| `APP_KEY`                                                                               | 可选；新安装会在 `$STORAGE_PATH/app.key` 生成，用于签发网页登录 session。切换时用户需要重新登录                                                                                                                                                       |
| `SESSION_LIFETIME`                                                                      | 旧 Laravel `.env` 中的空闲 session 时长，单位为分钟，默认 `120`；登录和注册 cookie 会按该值过期，已登录用户访问网页或网页登录 OAuth 时会滑动续期。`SESSION_DRIVER` 不用于 Rust 服务                                                                   |
| `PASSPORT_PUBLIC_KEY`                                                                   | 可选；公钥文本或 `file:///绝对路径`。未设置时读取 `$STORAGE_PATH/oauth-public.key`                                                                                                                                                                    |
| `PASSPORT_PRIVATE_KEY`                                                                  | 签发 OAuth 令牌所需；私钥文本或 `file:///绝对路径`。未设置时读取 `$STORAGE_PATH/oauth-private.key`。勿公开或更换旧私钥                                                                                                                                |
| `PWD_METHOD`, `SALT`, `BCRYPT_ROUNDS`                                                   | 兼容旧密码格式所需设置；保留旧站的 `PWD_METHOD`、`SALT`，`BCRYPT_ROUNDS` 用于新 bcrypt 密码，默认 `10`                                                                                                                                                |
| `MAIL_MAILER`, `MAIL_*`                                                                 | `MAIL_MAILER` 支持 `smtp`、`sendmail`、`mailgun`、`postmark`、`ses`、`ses-v2`、`log`、`array`、`failover`，默认 `smtp`；分散邮件配置未设置时沿用 Laravel 默认值（`smtp.mailgun.org:587`、`tls`、`hello@example.com`、`Example`）                      |
| `MAILGUN_DOMAIN`, `MAILGUN_SECRET`, `MAILGUN_ENDPOINT`, `POSTMARK_TOKEN`                | Mailgun 和 Postmark API mailer 凭据；Mailgun endpoint 默认 `api.mailgun.net`，要求 HTTPS。Postmark 可选 `POSTMARK_MESSAGE_STREAM_ID`，未设置时使用服务默认 stream                                                                                     |
| `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, `AWS_DEFAULT_REGION` | SES/SES v2 SigV4 凭据；region 默认 us-east-1；可选 session token 用于临时凭据                                                                                                                                                                         |
| `MAIL_SENDMAIL_PATH`                                                                    | `sendmail` 驱动的可执行命令，默认 `/usr/sbin/sendmail -bs -i`；支持 Symfony/Laravel 使用的 `-bs` 或 `-t` 模式及附加参数，命令按独立参数启动，不经过 shell                                                                                             |
| `MAIL_URL`                                                                              | 可选的 `smtp://[用户名:密码@]主机[:端口]` 连接 URL；URL 主机、端口和凭据覆盖对应的 `MAIL_HOST`、`MAIL_PORT`、`MAIL_USERNAME`、`MAIL_PASSWORD`。查询参数可进一步覆盖配置，并支持 `encryption`、`timeout`、`local_domain`；凭据中的特殊字符需百分号编码 |
| `MAIL_EHLO_DOMAIN`                                                                      | 可选的 SMTP EHLO/HELO 域名；也可通过 `MAIL_URL` 的 `local_domain` 查询参数设置                                                                                                                                                                        |

默认 `failover` 先通过 SMTP 发送；失败时记录到 Rust 日志，对应 Laravel 默认的 `smtp` → `log` 顺序。
`MAIL_ENCRYPTION=tls` 会在服务器支持时使用 STARTTLS（465 端口采用隐式 TLS）；设为 `starttls` 时必须成功升级，未设置加密时使用普通 SMTP。`MAIL_URL` 的 URL scheme 应为 `smtp`。

Rust 启动时会幂等创建 `{DB_PREFIX}rust_web_session_revocations`，保存网页登录 session ID 和 cookie 的 SHA-256 指纹，以便滑动续期后登出仍能撤销同一 session，并拒绝重放旧 cookie；受保护网页和网页登录 OAuth 请求会检查共享数据库，因此多实例部署也能立即识别撤销。服务启动时恢复未过期记录，并每 15 分钟清理过期记录。数据库账号需要对该 Rust 专属表拥有建表、查询、插入和删除权限。该表不修改 PHP 核心表，回退到 PHP 不依赖它。

网页表单与同源网页写请求使用签名的 `blessing_skin_csrf` HttpOnly cookie 和 `X-CSRF-TOKEN` 请求头；Rust 会为 HTML 页面注入动态 `csrf-token` meta 标签和非安全原生表单的 `_token` 隐藏字段，并为旧前端的 `fetch` 自动附加请求头。缺少或不匹配时返回 HTTP 419；首选 Accept 类型为 JSON 时返回带 `message` 字段的 JSON，浏览器表单请求返回 HTML 过期页。带每用户令牌的 HTML 响应设置 `Cache-Control: private, no-store`，并移除旧的内容长度、ETag 和 Last-Modified。OAuth token/API 与安装向导按各自协议处理，不使用此网页 CSRF 校验。

Rust 直接读取旧数据库表和纹理文件；新站安装方法见 [rust-install.md](rust-install.md)，不要对已有 PHP 站点运行安装命令。切换前先备份数据库和纹理目录，并确认 `DB_PREFIX`、`TEXTURES_DIR`、`STORAGE_PATH` 与旧站一致。现有 OAuth/Passport 令牌验证依赖旧公钥；签发新令牌还需要旧 Passport 私钥，二者都不要更换。`/oauth/token` 支持 Passport `password`、`authorization_code`、`refresh_token` 与 `client_credentials` 授权，并沿用默认的一年访问令牌期限；密码授权需要旧数据库中有效的 `password_client`。机机令牌使用旧 Passport 表且 `user_id` 为空，不签发 refresh token，也不能访问绑定用户身份的 API 路由。Passport 的 `*` scope 在 password 和 client_credentials grant 中允许所有 scope。Rust 还提供登录态下的 `/oauth/tokens` 列表/撤销、`/oauth/scopes` scope 列表，以及 `/oauth/personal-access-tokens` 个人访问令牌管理；个人访问令牌接口要求有效网页登录 session 和旧的 Passport personal access client。Rust 当前没有 PHP 插件兼容层。WASM 插件市场需要通过 `WASM_PLUGIN_REGISTRY_URL` 显式配置可信注册表，契约见 [plugin-registry-v1.md](plugin-registry-v1.md)；注册表不可用时市场安装会失败关闭。

官方发行包包含 `public/app` 下的旧站前端 bundle 和站点背景图、favicon；从源码部署时，运行 `yarn install --frozen-lockfile` 和 `yarn build` 后，还需将 `resources/assets/src/images/bg.webp` 与 `resources/assets/src/images/favicon.ico` 复制到 `public/app/`。Rust 服务通过 `PUBLIC_PATH/app` 提供这些资源。

## 版本升级

从 [GitHub Releases](https://github.com/HELPMEEADICE/blessing-skin-rs/releases) 下载与你的系统和架构匹配的软件包。发行包包含独立 Rust 程序、前端资源和部署文档。升级前备份数据库与纹理目录；停止当前服务后替换程序和 `public/app`，保留 `.env`、`storage`、Passport 密钥和纹理文件。重新启动前运行 `./blessing-skin-rs update`（Windows 为 `./blessing-skin-rs.exe update`），它会将旧数据库的兼容版本选项更新到 `BS_LEGACY_APP_VERSION`、执行适用的默认背景 URL 更新、删除可能过期的 `STORAGE_PATH/options.php` PHP 生成缓存，并确保 `STORAGE_PATH/install.lock` 存在。删除缓存可确保回退到 PHP 时重新从兼容数据库读取最新选项；该命令不会运行 PHP migrations 或修改其他业务数据。完成后启动服务并检查 `/health/ready`。已有 PHP 站点不需要重新运行安装器。切回 PHP 前如需预生成旧版选项缓存，可运行 `./blessing-skin-rs options:cache`（Windows 使用 `blessing-skin-rs.exe options:cache`）；该命令会写入数据库当前值到 `STORAGE_PATH/options.php`，Rust 服务本身直接读取数据库，不使用此缓存。

管理后台的“版本更新”页面查询配置的 latest release API，并显示最新版本和更新状态；尚无正式发行版时会明确提示，网络失败只显示提示，不影响服务。Rust 服务不在运行中覆盖自身文件，`POST /admin/update/download` 会返回人工升级步骤，需由管理员下载匹配平台发行包并停止服务后替换程序和前端资源。

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

将 `APP_URL` 设为 `https://skin.example.com`，并在反向代理处配置证书和 HTTP 到 HTTPS 跳转。`BS_POST_MAX_SIZE` 控制 Rust 的全局请求大小检查，支持字节数或 `K`、`M`、`G` 后缀，默认 `8M`；迁移时将它设为旧 PHP 的 `post_max_size`，并确保反向代理的 `client_max_body_size` 不低于该值。设为 `0` 可关闭 PHP 兼容的 `Content-Length` 检查；JSON 和表单预处理仍有 32 MiB 的内存缓冲上限。

Rust 会继续读取旧站的 `auto_detect_asset_url`、`site_url` 和 `force_ssl` 选项：自动检测开启时使用请求的 `Host`，关闭时使用有效的 `site_url`；`force_ssl` 或安全的反向代理头会强制生成 HTTPS URL。反向代理应保留并校验 `Host`，并按示例传递 `X-Forwarded-Proto`。缺少有效请求 Host 时回退到 `APP_URL`。

## 迁移切换

切换按“只读影子比对 → 单业务域灰度 → 全站 Rust”推进。每个阶段至少观察 24 小时；任一阶段不满足退出条件时，不进入下一阶段。

### 切换前

1. 备份数据库和完整纹理目录，记录备份时间、文件数量及纹理哈希清单。先在隔离副本上验证，不直接对唯一生产数据做试运行。
2. 为 Rust 配置与旧站相同的 `DB_CONNECTION`、`DB_PREFIX`、`DB_SOCKET`（如有）、`TEXTURES_DIR`、`PWD_METHOD`、`SALT`、Passport 公私钥及 `APP_URL`，并把旧 PHP `post_max_size` 的值映射到 `BS_POST_MAX_SIZE`。不要运行新站安装器，也不要更换 Passport 密钥。
3. 用 PHP 生成并保存代表性请求样本：Yggdrasil/CustomSkin、OAuth、用户与管理接口、纹理读取、图片预览和页面请求。记录状态码、内容类型、JSON 字段与错误体、ETag/缓存头及可稳定比较的响应内容；影子比较器仅重放无 session 和文件缓存副作用的只读白名单，上传、预览缓存及网页登录页面需在隔离副本中另行验证。
4. 检查所需插件是否已有 WASM 移植版本。Rust 不执行 PHP 插件；未移植插件的功能必须在切换前安排替代或接受停用。

### 只读影子比对（至少 24 小时）

- 只对明确列入只读白名单的请求做影子调用。认证挑战、OAuth 授权/令牌、任何写请求，以及可能更新 session、计数或状态的路由不得复制。
- 影子请求发到隔离的数据副本或只读凭据；不把 Rust 响应返回给访客，也不向 Rust 镜像写请求。比较 PHP 与 Rust 的状态码、内容类型、协议字段、错误语义、ETag/缓存头和纹理哈希。忽略预先标记的动态值（例如时间戳和随机 ID），但不能忽略业务字段差异。
- 记录每个样本的结果、差异和 Rust/PHP 错误率基线。存在未解释的数据或响应差异时，修复并重新开始本阶段的 24 小时观察。
  维护者可使用仓库内的只读探针比较器重放这些 GET 样本。它只接受显式白名单路由，拒绝 session、认证挑战、安装和写入路由，也不跟随重定向；比较器默认拒绝头像和预览等可能写入服务端缓存的路由；这些端点需对隔离副本显式开启。比较器要求 Python 3.10+ 标准库：

```sh
export BS_SHADOW_OAUTH_TOKEN='仅含 User.Read Player.Read Closet.Read Notification.Read 的测试令牌'
export BS_SHADOW_ADMIN_TOKEN='管理员的只读 UsersManagement.Read PlayersManagement.Read ReportsManagement.Read ClosetManagement.Read 测试令牌'
python3 tools/compat_compare.py \
  --php-url http://127.0.0.1:8080 \
  --rust-url http://127.0.0.1:3000 \
  --fixtures docs/compat-shadow.example.json
```

隔离副本中的缓存图像比对：

```sh
python3 tools/compat_compare.py \
  --php-url http://127.0.0.1:8080 \
  --rust-url http://127.0.0.1:3000 \
  --fixtures docs/compat-images-isolated.example.json \
  --allow-image-cache-in-isolated-clones
```

可在本机复制并修改 [示例探针](compat-shadow.example.json)，令牌应从环境变量传入，不要写入 fixture。动态 JSON 字段可用 `ignore_json_pointers` 标注；响应体中的其他字段、状态码和缓存相关头仍会比较。工具只打印差异类别、JSON 字段路径或非 JSON 响应的 SHA-256，不打印响应内容。

示例中的 `BS_SHADOW_ADMIN_TOKEN` 应属于有管理权限且只包含所需只读 scope 的测试账号；`BS_SHADOW_OAUTH_TOKEN` 需包含用户、玩家、衣柜和通知只读 scope。示例中的 `BS_SHADOW_PLAYER`、`BS_SHADOW_USER_ID`、`BS_SHADOW_TEXTURE_HASH` 和 `BS_SHADOW_TEXTURE_ID` 也从环境变量读取。默认探针覆盖用户与管理只读 API、皮肤库页面和列表，以及 Yggdrasil/CustomSkin 资料和原始纹理读取；不请求写路由、登录 session 页面或会生成缓存的图片路由。需要比较头像与预览的响应体、ETag 和缓存头时，只能对隔离副本使用 [图像探针样例](compat-images-isolated.example.json)，并额外传入 `--allow-image-cache-in-isolated-clones`；比较器会打印缓存写入警告。将它们设为 PHP 与 Rust 副本中都存在的玩家名、由 64 个十六进制字符组成的纹理哈希和纹理 ID，便可比较 Yggdrasil 玩家资料、按哈希读取纹理，以及在隔离副本中比较不同来源的头像和按 ID/哈希生成的皮肤预览响应。路径变量展开后会再次经过只读 GET 白名单校验；如果变量缺失、含控制字符或构造出其他路由，比较器会在发送请求前拒绝该 fixture。

### 单业务域灰度（每个域至少 24 小时）

- 每个数据域在同一时刻只能由一个后端处理写入。将一个业务域的读写整体交给 Rust 后，停止 PHP 对该域的写入；禁止双写和写请求镜像。按域切换前，确认 Rust 写入的数据仍符合 PHP 回退读取格式。
- 登录、登出、网页登录授权及依赖网页登录 session 的页面和接口必须作为一个整体切换。切换后网页用户需重新登录；OAuth/Passport 令牌仍应使用旧密钥验证。
- 每个域观察至少 24 小时，核对数据库记录、玩家关联、纹理哈希与纹理文件内容，再切换下一个域。只有所有域通过后才进行全站切换。

### 立即回退条件与操作

出现任一数据库/纹理数据不一致时立即回退。Rust 错误率超过 PHP 切换前基线的两倍并持续 5 分钟，也立即回退；协议客户端无法登录、旧令牌失效或纹理内容错误时无需等待阈值。

回退时先停止 Rust 对受影响域的写入，再把该域流量切回 PHP；不要回滚或重建共享数据库和纹理目录。保留 Rust/PHP 日志、差异样本及触发时间用于修复。若 Rust 写入尚未被 PHP 安全读取验证，先保持该域停写并恢复兼容性，不能通过丢弃新数据来掩盖差异。

### PHP 回退窗口

全站切换后至少保留可启动的 PHP 部署和原路由配置 7 天。此期间持续观察协议错误、写入一致性、OAuth 令牌和纹理校验；达到 7 天且没有未解决差异或回退事件后，才移除 PHP 回退部署。删除 PHP 运行环境前再次备份数据库、纹理目录和审计记录。
