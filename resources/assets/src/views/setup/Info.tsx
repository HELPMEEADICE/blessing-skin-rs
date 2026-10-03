import React from 'react'
import { hot } from 'react-hot-loader/root'

type SetupInfoData = {
  csrf: string
  site_name: string
  error: string
}

const Info: React.FC = () => {
  const chinese = blessing.locale.startsWith('zh')
  const setup = blessing.extra.setup_info as SetupInfoData

  return (
    <>
      <h1>{chinese ? '管理员和站点信息' : 'Administrator and site details'}</h1>
      <p className="notice">
        {chinese
          ? '此账号将成为唯一的初始超级管理员。安装会创建与旧站兼容的数据表和 Passport 密钥。'
          : 'This account will be the first super administrator. Installation creates legacy-compatible database tables and Passport keys.'}
      </p>
      {setup.error !== '' && (
        <p className="error" role="alert">
          {setup.error}
        </p>
      )}
      <form method="post" action="/setup/finish">
        <input type="hidden" name="csrf" value={setup.csrf} />
        <label htmlFor="email">
          {chinese ? '管理员邮箱' : 'Administrator email'}
        </label>
        <input
          id="email"
          name="email"
          type="email"
          maxLength={100}
          required
          autoComplete="email"
        />
        <label htmlFor="nickname">{chinese ? '昵称' : 'Nickname'}</label>
        <input
          id="nickname"
          name="nickname"
          maxLength={50}
          required
          autoComplete="nickname"
        />
        <label htmlFor="password">
          {chinese ? '密码（8 至 32 个字符）' : 'Password (8 to 32 characters)'}
        </label>
        <input
          id="password"
          name="password"
          type="password"
          minLength={8}
          maxLength={32}
          required
          autoComplete="new-password"
        />
        <label htmlFor="password_confirmation">
          {chinese ? '确认密码' : 'Confirm password'}
        </label>
        <input
          id="password_confirmation"
          name="password_confirmation"
          type="password"
          minLength={8}
          maxLength={32}
          required
          autoComplete="new-password"
        />
        <label htmlFor="site_name">{chinese ? '站点名称' : 'Site name'}</label>
        <input
          id="site_name"
          name="site_name"
          maxLength={100}
          required
          defaultValue={setup.site_name}
        />
        <button type="submit">{chinese ? '开始安装' : 'Install'}</button>
      </form>
    </>
  )
}

export default hot(Info)
