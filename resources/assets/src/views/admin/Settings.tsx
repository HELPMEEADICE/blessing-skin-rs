import React, { useState } from 'react'
import { hot } from 'react-hot-loader/root'
import * as fetch from '@/scripts/net'

type SettingChoice = {
  value: string
  label: string
  selected: boolean
}

type SettingField = {
  key: string
  label: string
  kind: string
  value: string
  checked: boolean
  choices: SettingChoice[]
}

type SettingsData = {
  section: 'general' | 'score' | 'customize' | 'resource'
  title: string
  fields: SettingField[]
}

type SettingValue = string | boolean

type SettingValues = Record<string, SettingValue>

const Settings: React.FC = () => {
  const zh = blessing.locale.startsWith('zh')
  const settings = blessing.extra.settings as SettingsData
  const initialValues = settings.fields.reduce<SettingValues>(
    (values, field) => {
      values[field.key] =
        field.kind === 'checkbox' ? field.checked : field.value
      return values
    },
    {},
  )
  const [values, setValues] = useState(initialValues)
  const [status, setStatus] = useState('')
  const [isSaving, setIsSaving] = useState(false)

  const submit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    setStatus('')
    setIsSaving(true)
    try {
      const endpoint =
        settings.section === 'general'
          ? '/admin/options'
          : `/admin/${settings.section}`
      const result = await fetch.post<fetch.ResponseBody>(endpoint, { values })
      setStatus(result.message)
    } catch (error: unknown) {
      setStatus(
        error instanceof Error
          ? error.message
          : zh
          ? '无法连接到服务器。'
          : 'Unable to connect to the server.',
      )
    } finally {
      setIsSaving(false)
    }
  }

  const update = (key: string, value: SettingValue) => {
    setValues((current) => ({ ...current, [key]: value }))
  }

  return (
    <>
      <a href={`${blessing.base_url}/user`}>
        {zh ? '返回用户面板' : 'Back to account'}
      </a>
      <h1>{settings.title}</h1>
      <nav>
        <a href={`${blessing.base_url}/admin/options`}>
          {zh ? '站点选项' : 'Options'}
        </a>
        <a href={`${blessing.base_url}/admin/score`}>
          {zh ? '积分设置' : 'Score'}
        </a>
        <a href={`${blessing.base_url}/admin/customize`}>
          {zh ? '外观自定义' : 'Customize'}
        </a>
        <a href={`${blessing.base_url}/admin/resource`}>
          {zh ? '资源与缓存' : 'Resources'}
        </a>
      </nav>
      <form id="settings" onSubmit={submit}>
        {settings.fields.map((field) => (
          <fieldset key={field.key}>
            <label htmlFor={`setting-${field.key}`}>{field.label}</label>
            <div>
              {field.kind === 'checkbox' ? (
                <input
                  id={`setting-${field.key}`}
                  data-setting={field.key}
                  data-kind="checkbox"
                  type="checkbox"
                  checked={Boolean(values[field.key])}
                  onChange={(event) => update(field.key, event.target.checked)}
                />
              ) : field.kind === 'select' ? (
                <select
                  id={`setting-${field.key}`}
                  data-setting={field.key}
                  data-kind="select"
                  value={String(values[field.key] ?? '')}
                  onChange={(event) => update(field.key, event.target.value)}
                >
                  {field.choices.map((choice) => (
                    <option key={choice.value} value={choice.value}>
                      {choice.label}
                    </option>
                  ))}
                </select>
              ) : field.kind === 'textarea' ? (
                <textarea
                  id={`setting-${field.key}`}
                  data-setting={field.key}
                  data-kind="textarea"
                  value={String(values[field.key] ?? '')}
                  onChange={(event) => update(field.key, event.target.value)}
                />
              ) : (
                <input
                  id={`setting-${field.key}`}
                  data-setting={field.key}
                  data-kind={field.kind}
                  type={field.kind === 'number' ? 'number' : 'text'}
                  value={String(values[field.key] ?? '')}
                  onChange={(event) => update(field.key, event.target.value)}
                />
              )}
            </div>
          </fieldset>
        ))}
        <p>
          <button type="submit" disabled={isSaving}>
            {isSaving
              ? zh
                ? '正在保存…'
                : 'Saving…'
              : zh
              ? '保存设置'
              : 'Save settings'}
          </button>{' '}
          <span role="status">{status}</span>
        </p>
      </form>
    </>
  )
}

export default hot(Settings)
