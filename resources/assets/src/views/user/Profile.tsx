import React, { useState } from 'react'
import { hot } from 'react-hot-loader/root'
import { t } from '@/scripts/i18n'
import * as fetch from '@/scripts/net'
import { showModal, toast } from '@/scripts/notify'

type ProfileData = {
  nickname: string
  email: string
  avatar: number
  allow_delete: boolean
}

type ProfileWidget =
  | 'avatar'
  | 'password'
  | 'nickname'
  | 'email'
  | 'delete_account'

const Profile: React.FC = () => {
  const zh = blessing.locale.startsWith('zh')
  const initial = blessing.extra.profile as ProfileData
  const page_widgets = blessing.extra.page_widgets as ProfileWidget[]
  const [nickname, setNickname] = useState(initial.nickname)
  const [newNickname, setNewNickname] = useState(initial.nickname)
  const [avatar, setAvatar] = useState(initial.avatar)

  const saveNickname = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    const data = new FormData(event.currentTarget)
    const submittedNickname = String(data.get('new_nickname') ?? '')
    const { code, message } = await fetch.post<fetch.ResponseBody>(
      '/user/profile',
      { action: 'nickname', new_nickname: submittedNickname },
    )
    if (code === 0) {
      setNickname(submittedNickname)
      toast.success(message)
    } else {
      toast.error(message)
    }
  }

  const saveAvatar = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    const data = new FormData(event.currentTarget)
    const tid = Number(data.get('avatar'))
    const { code, message } = await fetch.post<fetch.ResponseBody>(
      '/user/profile/avatar',
      { tid },
    )
    if (code === 0) {
      setAvatar(tid)
      toast.success(message)
    } else {
      toast.error(message)
    }
  }

  const saveEmail = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    const data = new FormData(event.currentTarget)
    const email = String(data.get('email') ?? '')
    const password = String(data.get('password') ?? '')
    const { code, message } = await fetch.post<fetch.ResponseBody>(
      '/user/profile',
      { action: 'email', email, password },
    )
    await showModal({ mode: 'alert', text: message })
    if (code === 0) {
      window.location.href = `${blessing.base_url}/auth/login`
    }
  }

  const savePassword = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    const data = new FormData(event.currentTarget)
    const currentPassword = String(data.get('current_password') ?? '')
    const newPassword = String(data.get('new_password') ?? '')
    const confirmation = String(data.get('confirmation') ?? '')
    if (newPassword !== confirmation) {
      toast.error(t('auth.invalidConfirmPwd'))
      return
    }
    const { code, message } = await fetch.post<fetch.ResponseBody>(
      '/user/profile',
      {
        action: 'password',
        current_password: currentPassword,
        new_password: newPassword,
      },
    )
    await showModal({ mode: 'alert', text: message })
    if (code === 0) {
      window.location.href = `${blessing.base_url}/auth/login`
    }
  }

  const deleteAccount = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    const form = event.currentTarget
    try {
      await showModal({
        type: 'danger',
        text: zh
          ? '删除账户后无法恢复。确定要继续吗？'
          : 'Account deletion cannot be undone. Continue?',
      })
    } catch {
      return
    }
    const data = new FormData(form)
    const password = String(data.get('password') ?? '')
    const { code, message } = await fetch.post<fetch.ResponseBody>(
      '/user/profile',
      { action: 'delete', password },
    )
    await showModal({ mode: 'alert', text: message })
    if (code === 0) {
      window.location.href = blessing.base_url
    }
  }

  const nicknameWidget = (
    <section>
      <h2>{zh ? '修改昵称' : 'Change nickname'}</h2>
      <form id="profile-change-nickname" onSubmit={saveNickname}>
        <label htmlFor="profile-nickname">
          {zh ? '新昵称' : 'New nickname'}
        </label>
        <input
          id="profile-nickname"
          name="new_nickname"
          required
          maxLength={100}
          value={newNickname}
          onChange={(event) => setNewNickname(event.target.value)}
        />
        <button type="submit">{zh ? '保存昵称' : 'Save nickname'}</button>
      </form>
    </section>
  )
  const avatarWidget = (
    <section>
      <h2>{zh ? '修改头像' : 'Change avatar'}</h2>
      <img
        src={`${blessing.base_url}/avatar/${avatar}`}
        alt="User Image"
        width={64}
        height={64}
      />
      <form id="profile-change-avatar" onSubmit={saveAvatar}>
        <label htmlFor="profile-avatar">
          {zh
            ? '材质编号（0 恢复默认头像）'
            : 'Texture ID (0 resets the avatar)'}
        </label>
        <input
          id="profile-avatar"
          name="avatar"
          type="number"
          min={0}
          required
          defaultValue={avatar}
        />
        <button type="submit">{zh ? '设置头像' : 'Set avatar'}</button>
      </form>
      <a href={`${blessing.base_url}/user/closet`}>
        {zh ? '打开衣柜' : 'Open closet'}
      </a>
    </section>
  )
  const emailWidget = (
    <section>
      <h2>{zh ? '修改邮箱' : 'Change email'}</h2>
      <form id="profile-change-email" onSubmit={saveEmail}>
        <label htmlFor="profile-email">{t('auth.email')}</label>
        <input
          id="profile-email"
          name="email"
          type="email"
          maxLength={100}
          required
          defaultValue={initial.email}
        />
        <label htmlFor="profile-email-password">
          {zh ? '当前密码' : 'Current password'}
        </label>
        <input
          id="profile-email-password"
          name="password"
          type="password"
          minLength={6}
          maxLength={32}
          autoComplete="current-password"
          required
        />
        <button type="submit">{zh ? '更新邮箱' : 'Update email'}</button>
      </form>
    </section>
  )
  const passwordWidget = (
    <section>
      <h2>{zh ? '修改密码' : 'Change password'}</h2>
      <form id="profile-change-password" onSubmit={savePassword}>
        <label htmlFor="profile-current-password">
          {zh ? '当前密码' : 'Current password'}
        </label>
        <input
          id="profile-current-password"
          name="current_password"
          type="password"
          minLength={6}
          maxLength={32}
          autoComplete="current-password"
          required
        />
        <label htmlFor="profile-new-password">
          {zh ? '新密码' : 'New password'}
        </label>
        <input
          id="profile-new-password"
          name="new_password"
          type="password"
          minLength={8}
          maxLength={32}
          autoComplete="new-password"
          required
        />
        <label htmlFor="profile-confirm-password">
          {zh ? '确认新密码' : 'Confirm new password'}
        </label>
        <input
          id="profile-confirm-password"
          name="confirmation"
          type="password"
          minLength={8}
          maxLength={32}
          autoComplete="new-password"
          required
        />
        <button type="submit">{zh ? '更新密码' : 'Update password'}</button>
      </form>
    </section>
  )
  const delete_accountWidget = (
    <section>
      <h2>{zh ? '删除账户' : 'Delete account'}</h2>
      {initial.allow_delete ? (
        <>
          <p>
            {zh ? '删除账户后无法恢复。' : 'Account deletion cannot be undone.'}
          </p>
          <form id="profile-delete-account" onSubmit={deleteAccount}>
            <label htmlFor="profile-delete-password">
              {zh ? '当前密码' : 'Current password'}
            </label>
            <input
              id="profile-delete-password"
              name="password"
              type="password"
              minLength={6}
              maxLength={32}
              autoComplete="current-password"
              required
            />
            <button type="submit" className="danger">
              {zh ? '删除账户' : 'Delete account'}
            </button>
          </form>
        </>
      ) : (
        <p>
          {zh
            ? '管理员账户不能删除。'
            : 'Administrator accounts cannot be deleted.'}
        </p>
      )}
    </section>
  )
  const profileWidgets: Record<ProfileWidget, React.ReactNode> = {
    avatar: avatarWidget,
    password: passwordWidget,
    nickname: nicknameWidget,
    email: emailWidget,
    delete_account: delete_accountWidget,
  }

  return (
    <>
      <p>
        {nickname} · {initial.email}
      </p>
      <div className="grid">
        {page_widgets.map((widget) => (
          <React.Fragment key={widget}>{profileWidgets[widget]}</React.Fragment>
        ))}
      </div>
    </>
  )
}

export default hot(Profile)
