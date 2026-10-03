import React from 'react'
import { hot } from 'react-hot-loader/root'

type OAuthAuthorizeData = {
  auth_token: string
  client_id: number
  client_name: string
  scopes: string[]
}

const OAuthAuthorize: React.FC = () => {
  const chinese = blessing.locale.startsWith('zh')
  const { auth_token, client_id, client_name, scopes } = blessing.extra
    .oauth as OAuthAuthorizeData

  return (
    <>
      <h1>{chinese ? '授权请求' : 'Authorization request'}</h1>
      <p>
        {chinese ? (
          <>
            <strong>{client_name}</strong> 请求访问你的 Blessing Skin 账户。
          </>
        ) : (
          <>
            <strong>{client_name}</strong> is requesting access to your Blessing
            Skin account.
          </>
        )}
      </p>
      <p>{chinese ? '批准后，此应用可以：' : 'If you approve, this app can:'}</p>
      <ul className="scopes">
        {scopes.map((scope) => (
          <li key={scope}>{scope}</li>
        ))}
      </ul>
      <div className="actions">
        <form method="post" action="/oauth/authorize">
          <input type="hidden" name="auth_token" value={auth_token} />
          <input type="hidden" name="client_id" value={client_id} />
          <button name="decision" value="approve">
            {chinese ? '批准' : 'Approve'}
          </button>
        </form>
        <form className="deny" method="post" action="/oauth/authorize">
          <input type="hidden" name="auth_token" value={auth_token} />
          <input type="hidden" name="client_id" value={client_id} />
          <input type="hidden" name="_method" value="DELETE" />
          <button>{chinese ? '拒绝' : 'Deny'}</button>
        </form>
      </div>
      <p>
        <small>
          {chinese ? '请确认你信任此应用。' : 'Only approve apps you trust.'}
        </small>
      </p>
    </>
  )
}

export default hot(OAuthAuthorize)
