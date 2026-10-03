import React from 'react'
import { hot } from 'react-hot-loader/root'

type DatabaseSetupData = {
  csrf: string
  driver: string
  host: string
  port: string
  username: string
  database: string
  prefix: string
  error: string
  saved: boolean
}

const Database: React.FC = () => {
  const chinese = blessing.locale.startsWith('zh')
  const setup = blessing.extra.setup_database as DatabaseSetupData

  return (
    <>
      <h1>{chinese ? '数据库连接' : 'Database connection'}</h1>
      {setup.saved ? (
        <p className="notice">
          {chinese
            ? '连接测试成功，配置已写入环境文件。请重启 Rust 服务使新数据库配置生效，然后重新打开此页继续。若服务由 systemd、容器编排或其他进程管理器提供环境变量，请同时更新其中的 DB_* 值。'
            : 'The connection succeeded and the settings were saved to the environment file. Restart the Rust service to apply them, then reopen this page to continue. If systemd, a container manager, or another process manager provides DB_* variables, update those values there too.'}
        </p>
      ) : (
        <>
          <p className="notice">
            {chinese
              ? '数据库用于保存 Blessing Skin 数据。表前缀只能包含英文字母、数字和下划线。提交后服务会测试连接并保存配置。'
              : 'The database stores Blessing Skin data. Table prefixes may contain only ASCII letters, digits, and underscores. The service tests the connection before saving these settings.'}
          </p>
          {setup.error !== '' && (
            <p className="error" role="alert">
              {setup.error}
            </p>
          )}
          <form method="post" action="/setup/database">
            <input type="hidden" name="csrf" value={setup.csrf} />
            <label htmlFor="type">
              {chinese ? '数据库类型' : 'Database type'}
            </label>
            <select id="type" name="type" defaultValue={setup.driver}>
              <option value="mysql">MySQL / MariaDB</option>
              <option value="pgsql">PostgreSQL</option>
              <option value="sqlite">SQLite</option>
            </select>
            <label htmlFor="host">{chinese ? '服务器地址' : 'Host'}</label>
            <input
              id="host"
              name="host"
              defaultValue={setup.host}
              autoComplete="off"
            />
            <label htmlFor="port">
              {chinese
                ? '端口（留空使用默认值）'
                : 'Port (leave blank for the default)'}
            </label>
            <input
              id="port"
              name="port"
              inputMode="numeric"
              defaultValue={setup.port}
            />
            <label htmlFor="username">{chinese ? '用户名' : 'Username'}</label>
            <input
              id="username"
              name="username"
              defaultValue={setup.username}
              autoComplete="username"
            />
            <label htmlFor="password">{chinese ? '密码' : 'Password'}</label>
            <input
              id="password"
              name="password"
              type="password"
              autoComplete="new-password"
            />
            <label htmlFor="db">
              {chinese
                ? '数据库名称或 SQLite 文件路径'
                : 'Database name or SQLite file path'}
            </label>
            <input id="db" name="db" required defaultValue={setup.database} />
            <label htmlFor="prefix">
              {chinese ? '数据表前缀（可选）' : 'Table prefix (optional)'}
            </label>
            <input id="prefix" name="prefix" defaultValue={setup.prefix} />
            <button type="submit">
              {chinese ? '测试并保存' : 'Test and save'}
            </button>
          </form>
        </>
      )}
      <p>
        <a href="/setup">{chinese ? '上一步' : 'Back'}</a>
      </p>
    </>
  )
}

export default hot(Database)
