import React from 'react'
import { hot } from 'react-hot-loader/root'

type StatusGroup = {
  title: string
  fields: Array<{ label: string; value: string }>
}

type AdminStatusData = {
  groups: StatusGroup[]
  wasm_plugins: string[]
}

const SystemStatus: React.FC = () => {
  const chinese = blessing.locale.startsWith('zh')
  const { groups, wasm_plugins } = blessing.extra.admin_status as AdminStatusData

  return (
    <>
      <header>
        <h1>
          {chinese ? '系统状态' : 'System status'} - {blessing.site_name}
        </h1>
        <a href="/admin">{chinese ? '返回管理后台' : 'Admin dashboard'}</a>
      </header>
      {groups.map((group) => (
        <section key={group.title}>
          <h2>{group.title}</h2>
          <table>
            <tbody>
              {group.fields.map((field) => (
                <tr key={field.label}>
                  <th scope="row">{field.label}</th>
                  <td>{field.value}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      ))}
      <section>
        <h2>
          {chinese
            ? `已加载 WASM 插件（${wasm_plugins.length}）`
            : `Loaded WASM plugins (${wasm_plugins.length})`}
        </h2>
        {wasm_plugins.length === 0 ? (
          <p>{chinese ? '当前没有已加载的 WASM 插件。' : 'No WASM plugins loaded.'}</p>
        ) : (
          <table>
            <tbody>
              {wasm_plugins.map((plugin) => (
                <tr key={plugin}>
                  <td>{plugin}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </>
  )
}

export default hot(SystemStatus)
