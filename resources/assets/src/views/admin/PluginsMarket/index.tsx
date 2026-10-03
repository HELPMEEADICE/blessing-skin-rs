import React, { useState, useEffect, useMemo } from 'react'
import { hot } from 'react-hot-loader/root'
import { enableMapSet } from 'immer'
import { useImmer } from 'use-immer'
import { t } from '@/scripts/i18n'
import * as fetch from '@/scripts/net'
import { toast, showModal } from '@/scripts/notify'
import Loading from '@/components/Loading'
import Pagination from '@/components/Pagination'
import type { Plugin, PluginMarketResponse } from './types'
import Row from './Row'

enableMapSet()

const PluginsMarket: React.FC = () => {
  const chinese = blessing.locale.startsWith('zh')
  const [plugins, setPlugins] = useImmer<Plugin[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [isConfigured, setIsConfigured] = useState(false)
  const [search, setSearch] = useState('')
  const [page, setPage] = useState(1)
  const [installings, setInstallings] = useImmer<Set<string>>(() => new Set())

  const searchedPlugins = useMemo(
    () =>
      plugins.filter(
        (plugin) =>
          plugin.name.toLowerCase().includes(search.toLowerCase()) ||
          plugin.title.toLowerCase().includes(search.toLowerCase()),
      ),
    [plugins, search],
  )
  const totalPages = Math.max(1, Math.ceil(searchedPlugins.length / 10))

  useEffect(() => {
    const getPlugins = async () => {
      try {
        const response = await fetch.get<PluginMarketResponse>(
          '/admin/plugins/market/list',
        )
        setIsConfigured(response.configured)
        setPlugins(() => response.plugins)
      } catch {
        setPlugins(() => [])
      } finally {
        setIsLoading(false)
      }
    }
    void getPlugins()
  }, [])

  const handleInstall = async (plugin: Plugin) => {
    setInstallings((installings) => {
      installings.add(plugin.name)
    })

    try {
      const { code, message } = await fetch.post<fetch.ResponseBody>(
        '/admin/plugins/market/download',
        { name: plugin.name },
      )
      if (code === 0) {
        toast.success(message)
        setPlugins((plugins) => {
          const record = plugins.find((item) => item.name === plugin.name)
          if (record) {
            record.installed = true
            record.installed_version = record.version
            record.can_update = false
          }
        })
      } else {
        showModal({ mode: 'alert', text: message })
      }
    } finally {
      setInstallings((installings) => {
        installings.delete(plugin.name)
      })
    }
  }

  const handleUpdate = async (plugin: Plugin) => {
    try {
      await showModal({
        text: t('admin.confirmUpdate', {
          plugin: plugin.title,
          old: plugin.installed_version || '?',
          new: plugin.version,
        }),
      })
    } catch {
      return
    }

    await handleInstall(plugin)
  }

  const pagedPlugins = searchedPlugins.slice((page - 1) * 10, page * 10)

  return (
    <div className="card">
      <div className="card-header">
        <input
          type="text"
          className="form-control"
          placeholder={t('vendor.datatable.search')}
          value={search}
          onChange={(event) => {
            setSearch(event.target.value)
            setPage(1)
          }}
        />
      </div>
      {!isLoading && !isConfigured ? (
        <div className="card-body">
          {chinese ? (
            <>
              <p>Rust 插件市场尚未配置。</p>
              <p>
                管理员可在服务环境中设置 <code>WASM_PLUGIN_REGISTRY_URL</code>{' '}
                指向版本 1 的 JSON 清单。PHP 插件 ZIP
                不兼容；也可在插件管理页上传 WASM 组件。
              </p>
            </>
          ) : (
            <>
              <p>The Rust plugin market is not configured.</p>
              <p>
                Set <code>WASM_PLUGIN_REGISTRY_URL</code> in the service
                environment to a version 1 JSON manifest. PHP plugin ZIP files
                are incompatible; WASM components can also be uploaded on the
                plugin management page.
              </p>
            </>
          )}
        </div>
      ) : isLoading ? (
        <div className="card-body">
          <Loading />
        </div>
      ) : searchedPlugins.length === 0 ? (
        <div className="card-body text-center">{t('general.noResult')}</div>
      ) : (
        <div className="card-body table-responsive p-0">
          <table className="table table-striped">
            <thead>
              <tr>
                <th>{t('admin.pluginTitle')}</th>
                <th>{t('admin.pluginDescription')}</th>
                <th>
                  {t('admin.pluginAuthor')} / {t('admin.pluginVersion')}
                </th>
                <th>{t('admin.operationsTitle')}</th>
              </tr>
            </thead>
            <tbody>
              {pagedPlugins.map((plugin) => (
                <Row
                  key={plugin.name}
                  plugin={plugin}
                  isInstalling={installings.has(plugin.name)}
                  onInstall={() => void handleInstall(plugin)}
                  onUpdate={() => void handleUpdate(plugin)}
                />
              ))}
            </tbody>
          </table>
        </div>
      )}
      {isConfigured && !isLoading && (
        <div className="card-footer">
          <div className="float-right">
            <Pagination
              page={page}
              totalPages={totalPages}
              onChange={setPage}
            />
          </div>
        </div>
      )}
    </div>
  )
}

export default hot(PluginsMarket)
