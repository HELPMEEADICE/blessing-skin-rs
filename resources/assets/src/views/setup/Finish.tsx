import React from 'react'
import { hot } from 'react-hot-loader/root'

const Finish: React.FC = () => {
  const chinese = blessing.locale.startsWith('zh')

  return (
    <>
      <h1>{chinese ? '安装完成' : 'Installation complete'}</h1>
      <p>
        {chinese
          ? 'Blessing Skin Server 已安装。请重启 Rust 服务以加载新生成的 session 和 Passport 密钥，然后登录管理站点。'
          : 'Blessing Skin Server is installed. Restart the Rust service to load the newly generated session and Passport keys, then sign in.'}
      </p>
      <p>
        <a className="button" href="/">
          {chinese ? '返回首页' : 'Home'}
        </a>
      </p>
    </>
  )
}

export default hot(Finish)
