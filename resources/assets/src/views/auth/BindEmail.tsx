import React, { useState } from 'react'
import { hot } from 'react-hot-loader/root'
import * as fetch from '@/scripts/net'
import urls from '@/scripts/urls'
import Alert from '@/components/Alert'
import EmailSuggestion from '@/components/EmailSuggestion'

const BindEmail: React.FC = () => {
  const chinese = blessing.locale.startsWith('zh')
  const [email, setEmail] = useState('')
  const [message, setMessage] = useState('')
  const [isPending, setIsPending] = useState(false)

  const handleSubmit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    setMessage('')
    setIsPending(true)

    try {
      const result = await fetch.post<
        fetch.ResponseBody<{ redirectTo?: string }>
      >(urls.auth.bind(), { email })
      if (result.code === 0) {
        window.location.href =
          blessing.base_url + (result.data?.redirectTo ?? '/user')
      } else {
        setMessage(result.message)
      }
    } catch (error) {
      setMessage(
        error instanceof Error
          ? error.message
          : chinese
            ? '无法连接到服务器。'
            : 'Unable to connect to the server.',
      )
    } finally {
      setIsPending(false)
    }
  }

  return (
    <form onSubmit={handleSubmit}>
      <EmailSuggestion
        type="email"
        placeholder={chinese ? '邮箱地址' : 'Email address'}
        required
        autoFocus
        value={email}
        onChange={setEmail}
      />
      <Alert type="warning">{message}</Alert>
      <button
        className="btn btn-primary"
        type="submit"
        disabled={isPending}
      >
        {isPending
          ? chinese
            ? '正在绑定…'
            : 'Binding…'
          : chinese
            ? '绑定并继续'
            : 'Bind and continue'}
      </button>
    </form>
  )
}

export default hot(BindEmail)
