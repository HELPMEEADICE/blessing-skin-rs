import React from 'react'
import { hot } from 'react-hot-loader/root'

type SetupWelcomeData = {
  version: string
}

const Welcome: React.FC = () => {
  const chinese = blessing.locale.startsWith('zh')
  const { version } = blessing.extra.setup_welcome as SetupWelcomeData

  return (
    <>
      <h1>Blessing Skin Server</h1>
      <h2>{chinese ? '欢迎' : 'Welcome'}</h2>
      <p>
        {chinese
          ? `欢迎使用 Blessing Skin Server ${version}。安装向导将测试数据库连接、创建兼容旧版的数据表并建立首位超级管理员。`
          : `Welcome to Blessing Skin Server ${version}. The wizard tests the database connection, creates legacy-compatible tables, and sets up the first super administrator.`}
      </p>
      <p>
        <a className="button" href="/setup/database">
          {chinese ? '开始安装' : 'Start setup'}
        </a>
      </p>
    </>
  )
}

export default hot(Welcome)
