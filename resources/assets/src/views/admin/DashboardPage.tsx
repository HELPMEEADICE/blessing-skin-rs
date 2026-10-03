import React, { useEffect, useRef, useState } from 'react'
import { hot } from 'react-hot-loader/root'
import * as fetch from '@/scripts/net'
import Loading from '@/components/Loading'
import { createDashboardChart } from './createDashboardChart'

type DashboardStats = {
  users: number
  players: number
  textures: number
  storage: number
}

type ChartData = {
  labels: string[]
  xAxis: string[]
  data: number[][]
}

const Chart: React.FC<{
  data: ChartData
  index: number
  color: string
}> = ({ data, index, color }) => {
  const element = useRef<HTMLDivElement>(null)
  const isDarkMode = document.body.classList.contains('dark-mode')

  useEffect(() => {
    if (!element.current || !data.labels[index] || !data.data[index]) return
    const chart = createDashboardChart(
      element.current,
      isDarkMode ? '#3498db' : color,
      isDarkMode ? '#fff' : '#000',
      {
        label: data.labels[index]!,
        xAxis: data.xAxis,
        data: data.data[index]!,
      },
    )
    return () => chart.dispose()
  }, [color, data, index, isDarkMode])

  return (
    <article className="chart">
      <h2>{data.labels[index]}</h2>
      <div
        ref={element}
        role="img"
        aria-label={data.labels[index]}
        style={{ minHeight: 260 }}
      />
    </article>
  )
}

const DashboardPage: React.FC = () => {
  const zh = blessing.locale.startsWith('zh')
  const stats = blessing.extra.dashboard_stats as DashboardStats
  const [chartData, setChartData] = useState<ChartData | null>(null)
  const [chartError, setChartError] = useState('')
  const [receiver, setReceiver] = useState('all')
  const [uid, setUid] = useState('')
  const [email, setEmail] = useState('')
  const [title, setTitle] = useState('')
  const [content, setContent] = useState('')
  const [notice, setNotice] = useState('')
  const [isSending, setIsSending] = useState(false)

  useEffect(() => {
    let active = true
    fetch
      .get<ChartData>('/admin/chart')
      .then((result) => {
        if (!active) return
        if (
          !Array.isArray(result.labels) ||
          !Array.isArray(result.xAxis) ||
          !Array.isArray(result.data)
        ) {
          throw new Error(zh ? '无法加载活动图表。' : 'Unable to load activity charts.')
        }
        setChartData(result)
      })
      .catch((error: unknown) => {
        if (active) {
          setChartError(
            error instanceof Error
              ? error.message
              : zh
                ? '无法加载活动图表。'
                : 'Unable to load activity charts.',
          )
        }
      })
    return () => {
      active = false
    }
  }, [zh])

  const sendNotification = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    setNotice('')
    setIsSending(true)
    const result = await fetch.post<fetch.ResponseBody>(
      '/admin/notifications/send',
      { receiver, uid, email, title, content },
    )
    setIsSending(false)
    setNotice(result.message)
    if (result.code === 0) {
      setTitle('')
      setContent('')
      setUid('')
      setEmail('')
      setReceiver('all')
    }
  }

  return (
    <main className="admin-dashboard">
      <header>
        <h1>{blessing.site_name}</h1>
        <a href={`${blessing.base_url}/user`}>
          {zh ? '返回用户中心' : 'User dashboard'}
        </a>
      </header>
      <h2>{zh ? '管理后台概览' : 'Admin overview'}</h2>
      <nav aria-label={zh ? '管理导航' : 'Admin navigation'}>
        <a href={`${blessing.base_url}/admin/users`}>{zh ? '用户' : 'Users'}</a>
        <a href={`${blessing.base_url}/admin/players`}>
          {zh ? '角色' : 'Players'}
        </a>
        <a href={`${blessing.base_url}/admin/reports`}>
          {zh ? '举报' : 'Reports'}
        </a>
        <a href={`${blessing.base_url}/admin/i18n`}>
          {zh ? '多语言' : 'Internationalization'}
        </a>
        <a href={`${blessing.base_url}/admin/options`}>
          {zh ? '站点设置' : 'Site settings'}
        </a>
        <a href={`${blessing.base_url}/admin/status`}>
          {zh ? '系统状态' : 'System status'}
        </a>
        <a href={`${blessing.base_url}/admin/plugins/manage`}>
          {zh ? '插件' : 'Plugins'}
        </a>
      </nav>
      <section className="notice">
        <h2>{zh ? '发送站内通知' : 'Send a site notification'}</h2>
        <form id="notification-form" onSubmit={sendNotification}>
          <label htmlFor="notification-receiver">
            {zh ? '接收对象' : 'Recipients'}
          </label>
          <select
            id="notification-receiver"
            name="receiver"
            required
            value={receiver}
            onChange={(event) => setReceiver(event.target.value)}
          >
            <option value="all">{zh ? '所有用户' : 'All users'}</option>
            <option value="normal">{zh ? '普通用户' : 'Regular users'}</option>
            <option value="uid">{zh ? '指定用户编号' : 'User ID'}</option>
            <option value="email">{zh ? '指定邮箱' : 'Email address'}</option>
          </select>
          {receiver === 'uid' && (
            <>
              <label htmlFor="notification-uid">UID</label>
              <input
                id="notification-uid"
                name="uid"
                type="number"
                min={1}
                required
                value={uid}
                onChange={(event) => setUid(event.target.value)}
              />
            </>
          )}
          {receiver === 'email' && (
            <>
              <label htmlFor="notification-email">
                {zh ? '邮箱地址' : 'Email address'}
              </label>
              <input
                id="notification-email"
                name="email"
                type="email"
                maxLength={100}
                required
                value={email}
                onChange={(event) => setEmail(event.target.value)}
              />
            </>
          )}
          <label htmlFor="notification-title">
            {zh ? '标题（最多 20 字）' : 'Title (up to 20 characters)'}
          </label>
          <input
            id="notification-title"
            name="title"
            maxLength={20}
            required
            value={title}
            onChange={(event) => setTitle(event.target.value)}
          />
          <label htmlFor="notification-content">
            {zh ? '内容' : 'Content'}
          </label>
          <textarea
            id="notification-content"
            name="content"
            rows={3}
            value={content}
            onChange={(event) => setContent(event.target.value)}
          />
          <button type="submit" disabled={isSending}>
            {isSending
              ? zh
                ? '正在发送…'
                : 'Sending…'
              : zh
                ? '发送'
                : 'Send'}
          </button>
          <p id="notification-status" role="status">
            {notice}
          </p>
        </form>
      </section>
      <section className="stats" aria-label={zh ? '站点统计' : 'Site statistics'}>
        <article className="stat">
          <h2>{zh ? '用户' : 'Users'}</h2>
          <p>{stats.users}</p>
        </article>
        <article className="stat">
          <h2>{zh ? '角色' : 'Players'}</h2>
          <p>{stats.players}</p>
        </article>
        <article className="stat">
          <h2>{zh ? '纹理' : 'Textures'}</h2>
          <p>{stats.textures}</p>
        </article>
        <article className="stat">
          <h2>{zh ? '存储用量（字节）' : 'Storage (bytes)'}</h2>
          <p>{stats.storage}</p>
        </article>
      </section>
      <section
        className="charts"
        aria-label={zh ? '近一个月活动' : 'Recent activity'}
      >
        {chartError ? (
          <p role="alert">{chartError}</p>
        ) : chartData ? (
          <>
            <Chart data={chartData} index={0} color="#17a2b8" />
            <Chart data={chartData} index={1} color="#6f42c1" />
          </>
        ) : (
          <div className="chart"><Loading /></div>
        )}
      </section>
    </main>
  )
}

export default hot(DashboardPage)
