# Rust 新站安装

安装器用于建立全新的 Blessing Skin 数据库并创建首位超级管理员。已有 PHP 站点应直接复用原数据库和纹理目录，不要运行此安装器。

## 准备

先按 [Rust 部署说明](rust-deployment.md) 准备 .env。确认 DB*CONNECTION、数据库凭据、DB_PREFIX、APP_URL 和 STORAGE_PATH 正确。SQLite 首次安装会创建数据库文件及其父目录。
也可启动服务后访问 `/setup` 使用双语 Web 安装向导。向导会测试数据库连接并保存 DB*\_ 配置到 `.env`（或 `BS_ENV_FILE` 指定的文件）；保存后需重启服务，再完成管理员信息。由 systemd 或其他进程管理器注入的 DB\_\_ 环境变量优先级更高，应同步更新这些变量。

安装器仅在 users、players、textures 表不存在或为空时继续；这些表中只要已有记录就会拒绝安装。选项表中已有的值会保留，缺失的默认值才会补入。

## 执行

Linux、macOS：

```sh
export BS_INSTALL_ADMIN_EMAIL=admin@example.com
export BS_INSTALL_ADMIN_NICKNAME=admin
export BS_INSTALL_ADMIN_PASSWORD='replace-with-a-long-password'
export BS_INSTALL_SITE_NAME='Blessing Skin'
./blessing-skin-rs install
```

Windows PowerShell：

```powershell
$env:BS_INSTALL_ADMIN_EMAIL = 'admin@example.com'
$env:BS_INSTALL_ADMIN_NICKNAME = 'admin'
$env:BS_INSTALL_ADMIN_PASSWORD = 'replace-with-a-long-password'
$env:BS_INSTALL_SITE_NAME = 'Blessing Skin'
./blessing-skin-rs.exe install
```

管理员密码必须为 8 至 32 个字符。安装器使用 PWD_METHOD 和 SALT 生成 PHP 兼容的密码哈希，将账号设为已验证的超级管理员，并应用 user_initial_score。 兼容旧 Artisan 的 `bs:install <email> <password> <nickname>` 命令也可创建首位超级管理员；它复用同一安全安装逻辑，检测到 `install.lock` 时按旧行为直接退出。

新站安装前可运行 `./blessing-skin-rs salt:random`（Windows 使用 `blessing-skin-rs.exe salt:random`）生成旧格式 32 位十六进制 SALT 并写入环境文件；添加 `--show` 只显示生成值。已安装站点会拒绝轮换 SALT，以免现有密码哈希失效。若服务由 systemd 等方式注入 SALT 环境变量，需同时更新进程管理器配置。

## 数据和密钥

安装器创建与当前 PHP migrations 对齐的 users、players、textures、options、closet、reports、notifications、scopes、jobs、language_lines 和 Passport 表，并写入旧站点默认选项。表名前缀沿用 DB_PREFIX。成功后在 STORAGE_PATH/install.lock 写入安装标记。

如果没有配置 Passport 公钥和私钥，安装器会生成 RSA 密钥对到 STORAGE_PATH/oauth-private.key 与 STORAGE_PATH/oauth-public.key。如果没有设置 APP_KEY，它会生成 STORAGE_PATH/app.key，Rust 服务之后从这里读取 session 密钥。请保护这些文件，并在服务启动后保留它们。旧站切换时必须继续使用旧站的 Passport 密钥和 APP_KEY。

若安装中断，可在确认没有写入用户数据后重新执行；现有选项不会被覆盖。若发现核心业务表已有记录，安装器会停止，避免改动站点数据。
