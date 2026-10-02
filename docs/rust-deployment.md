# Rust 服务部署

本文介绍 Rust 服务的独立部署方式。服务监听 HTTP，由 Nginx、Apache 或其他反向代理负责公网 TLS。Rust 迁移仍在进行中；切换旧站前请先在副本上验证协议、数据库和纹理文件。

## 构建

需要 Rust stable 工具链。源码构建：

```sh
cargo build --locked --release
```

可执行文件位于 `target/release/blessing-skin-rs`（Windows 为 `target/release/blessing-skin-rs.exe`）。仓库 CI 会在原生 runner 上检查和构建以下目标：

| 平台 | Rust target |
| --- | --- |
| Linux x86_64 | `x86_64-unknown-linux-gnu` |
| Linux ARM64 | `aarch64-unknown-linux-gnu` |
| Windows x86_64 | `x86_64-pc-windows-msvc` |
| macOS x86_64 | `x86_64-apple-darwin` |
| macOS ARM64 | `aarch64-apple-darwin` |

运行系统需能提供对应的系统库；不要把 Linux 构建产物复制到 Windows 或 macOS。构建产物不包含 Docker 镜像。

## 配置与旧安装

程序启动时会从当前工作目录读取 `.env`。旧站的 `.env` 可作为起点；将 [rust.env.example](../rust.env.example) 中的 Rust 专用项合并进去。PHP 专用项（例如 `CACHE_DRIVER`、`SESSION_DRIVER`、`QUEUE_CONNECTION`、`REDIS_*`）不会被 Rust 服务使用。

| 变量 | 用途与默认值 |
| --- | --- |
| `BS_LISTEN` | 监听地址，默认 `127.0.0.1:3000`；建议仅绑定回环地址并由反向代理访问 |
| `DB_CONNECTION` | `sqlite`、`mysql`、`mariadb`、`pgsql`、`postgres` 或 `postgresql`，默认 `mysql` |
| `DB_DATABASE` | SQLite 文件路径；MySQL/PostgreSQL 数据库名 |
| `DB_HOST`, `DB_PORT`, `DB_USERNAME`, `DB_PASSWORD` | MySQL/PostgreSQL 连接参数 |
| `DB_PREFIX` | 旧表前缀，只允许 ASCII 字母、数字和下划线 |
| `DB_FOREIGN_KEYS` | SQLite 中设为 `false` 或 `0` 可关闭外键检查 |
| `STORAGE_PATH` | 默认 `storage`；Passport 公钥默认从此目录的 `oauth-public.key` 读取 |
| `PUBLIC_PATH` | 默认 `public`；前端静态资源从此目录的 `app/` 子目录提供 |
| `TEXTURES_DIR` | 默认 `$STORAGE_PATH/textures`；请指向旧站实际纹理目录 |
| `PLUGINS_DIR` | 默认 `$STORAGE_PATH/plugins`；只扫描 `.wasm` 组件，不运行 PHP 插件 |
| `APP_URL` | 对外站点 URL，默认 `http://localhost` |
| `APP_LOCALE` | 默认 `zh_CN` |
| `APP_KEY` | 可选；新安装会在 `$STORAGE_PATH/app.key` 生成，用于签发网页登录 session。切换时用户需要重新登录 |
| `PASSPORT_PUBLIC_KEY` | 可选；公钥文本或 `file:///绝对路径`。未设置时读取 `$STORAGE_PATH/oauth-public.key` |
| `PASSPORT_PRIVATE_KEY` | 签发 OAuth 令牌所需；私钥文本或 `file:///绝对路径`。未设置时读取 `$STORAGE_PATH/oauth-private.key`。勿公开或更换旧私钥 |
| `PWD_METHOD`, `SALT` | 兼容旧密码格式所需设置；保留旧站的原值 |
| `MAIL_MAILER` | `smtp`、`log` 或 `array`；其余 SMTP 参数沿用 `MAIL_*` |

Rust 直接读取旧数据库表和纹理文件；新站安装方法见 [rust-install.md](rust-install.md)，不要对已有 PHP 站点运行安装命令。切换前先备份数据库和纹理目录，并确认 `DB_PREFIX`、`TEXTURES_DIR`、`STORAGE_PATH` 与旧站一致。现有 OAuth/Passport 令牌验证依赖旧公钥；签发新令牌还需要旧 Passport 私钥，二者都不要更换。`/oauth/token` 支持 Passport `password` 与 `refresh_token` 授权，并沿用默认的一年令牌期限；密码授权需要旧数据库中有效的 `password_client`。Rust 已提供 Passport `/oauth/token` 的 password/refresh_token 授权、登录态下的 `/oauth/tokens` 列表/撤销、`/oauth/scopes` scope 列表，以及 `/oauth/personal-access-tokens` 个人访问令牌管理；个人访问令牌接口要求有效网页登录 session 和旧的 Passport personal access client。Rust 当前没有 PHP 插件兼容层。

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

先在数据库与纹理目录的副本上启动 Rust，并验证健康检查、登录、旧 OAuth 令牌、Yggdrasil/CustomSkin 客户端和纹理读取。每个数据域同一时段只能让一个后端处理写入；网页登录与 session 路由整体切换。回退时将流量切回 PHP，并保持数据库与纹理目录不变。不要让两个后端同时写同一数据域。
