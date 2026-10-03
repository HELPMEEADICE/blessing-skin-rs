import React, { useCallback, useEffect, useRef, useState } from 'react'
import { hot } from 'react-hot-loader/root'
import * as fetch from '@/scripts/net'
import Loading from '@/components/Loading'

type WasmPlugin = {
  name: string
  title: string
  description: string
  version: string
  enabled: boolean
  loaded: boolean
  on_disk: boolean
}

const WasmPlugins: React.FC = () => {
  const chinese = blessing.locale.startsWith('zh')
  const canUpload = Boolean(blessing.extra?.can_upload)
  const [plugins, setPlugins] = useState<WasmPlugin[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [file, setFile] = useState<File | null>(null)
  const [isUploading, setIsUploading] = useState(false)
  const [workingPlugin, setWorkingPlugin] = useState<string | null>(null)
  const [status, setStatus] = useState('')
  const [hasError, setHasError] = useState(false)
  const uploadForm = useRef<HTMLFormElement>(null)

  const say = useCallback(
    (english: string, chineseText: string) => (chinese ? chineseText : english),
    [chinese],
  )

  useEffect(() => {
    const loadPlugins = async () => {
      setIsLoading(true)
      try {
        const inventory = await fetch.get<WasmPlugin[]>('/admin/plugins/data')
        if (!Array.isArray(inventory)) {
          throw new Error(
            say('Could not load WASM components.', '无法加载 WASM 组件。'),
          )
        }
        setPlugins(inventory)
      } catch (error) {
        setHasError(true)
        setStatus(
          error instanceof Error
            ? error.message
            : say('Could not load WASM components.', '无法加载 WASM 组件。'),
        )
      } finally {
        setIsLoading(false)
      }
    }

    void loadPlugins()
  }, [say])

  const reloadPlugins = async () => {
    const inventory = await fetch.get<WasmPlugin[]>('/admin/plugins/data')
    if (!Array.isArray(inventory)) {
      throw new Error(
        say('Could not load WASM components.', '无法加载 WASM 组件。'),
      )
    }
    setPlugins(inventory)
  }

  const managePlugin = async (plugin: WasmPlugin, action: string) => {
    if (
      action === 'delete' &&
      !window.confirm(
        say('Delete this component file?', '确定删除此组件文件吗？'),
      )
    ) {
      return
    }

    setWorkingPlugin(plugin.name)
    setStatus('')
    setHasError(false)
    try {
      const result = await fetch.post<fetch.ResponseBody>(
        '/admin/plugins/manage',
        { action, name: plugin.name },
      )
      if (result.code !== 0) {
        setHasError(true)
        setStatus(result.message)
        return
      }
      await reloadPlugins()
      setStatus(result.message)
    } catch (error) {
      setHasError(true)
      setStatus(
        error instanceof Error
          ? error.message
          : say('Could not update the component.', '无法更新组件状态。'),
      )
    } finally {
      setWorkingPlugin(null)
    }
  }

  const uploadPlugin = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (!file) {
      return
    }

    setIsUploading(true)
    setStatus('')
    setHasError(false)
    const formData = new FormData()
    formData.append('file', file, file.name)
    try {
      const result = await fetch.post<fetch.ResponseBody>(
        '/admin/plugins/upload',
        formData,
      )
      if (result.code !== 0) {
        setHasError(true)
        setStatus(result.message)
        return
      }
      setFile(null)
      uploadForm.current?.reset()
      await reloadPlugins()
      setStatus(result.message)
    } catch (error) {
      setHasError(true)
      setStatus(
        error instanceof Error
          ? error.message
          : say('Could not upload the component.', '无法上传组件。'),
      )
    } finally {
      setIsUploading(false)
    }
  }

  return (
    <div className="row">
      <div className={canUpload ? 'col-lg-8' : 'col-12'}>
        <div className="card card-primary card-outline">
          <div className="card-header">
            <h3 className="card-title">
              {say('WASM components', 'WASM 组件')}
            </h3>
            <button
              className="btn btn-default btn-sm float-right"
              type="button"
              disabled={isLoading}
              onClick={() => {
                setIsLoading(true)
                void reloadPlugins()
                  .catch((error: unknown) => {
                    setHasError(true)
                    setStatus(
                      error instanceof Error
                        ? error.message
                        : say(
                            'Could not load WASM components.',
                            '无法加载 WASM 组件。',
                          ),
                    )
                  })
                  .finally(() => setIsLoading(false))
              }}
            >
              {say('Refresh', '刷新')}
            </button>
          </div>
          <div className="card-body">
            <p>
              {say(
                'Components implementing lifecycle API 1.0.0 run in a sandbox without filesystem, network, database, or WASI access. Changes require a service restart.',
                '服务只加载通过 lifecycle API 1.0.0 校验的组件。组件在无文件、网络、数据库和 WASI 权限的沙箱中运行；状态变更需重启服务。',
              )}
            </p>
            <p
              className={hasError ? 'text-danger' : 'text-muted'}
              role="status"
              aria-live="polite"
            >
              {isLoading ? say('Loading components…', '正在加载组件…') : status}
            </p>
            {isLoading ? (
              <Loading />
            ) : plugins.length === 0 ? (
              <p className="text-muted">
                {say('No WASM components found.', '没有找到 WASM 组件。')}
              </p>
            ) : (
              plugins.map((plugin) => (
                <div
                  className="border-bottom py-3 d-flex justify-content-between align-items-center"
                  key={plugin.name}
                >
                  <div className="mr-3">
                    <strong className="d-block">{plugin.title}</strong>
                    <span className="text-muted">
                      {plugin.version} · {plugin.description}
                    </span>
                  </div>
                  <div className="d-flex flex-wrap">
                    {plugin.on_disk && (
                      <>
                        <button
                          className="btn btn-secondary btn-sm mr-2 mb-1"
                          type="button"
                          disabled={workingPlugin !== null}
                          onClick={() =>
                            void managePlugin(
                              plugin,
                              plugin.enabled ? 'disable' : 'enable',
                            )
                          }
                        >
                          {workingPlugin === plugin.name
                            ? say('Working…', '处理中…')
                            : plugin.enabled
                            ? say('Disable', '停用')
                            : say('Enable', '启用')}
                        </button>
                        <button
                          className="btn btn-danger btn-sm mb-1"
                          type="button"
                          disabled={workingPlugin !== null}
                          onClick={() => void managePlugin(plugin, 'delete')}
                        >
                          {say('Delete', '删除')}
                        </button>
                      </>
                    )}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
      <div className={canUpload ? 'col-lg-4' : 'col-12'}>
        {canUpload ? (
          <>
            <div className="card card-primary card-outline">
              <div className="card-header">
                <h3 className="card-title">
                  {say('Install a WASM component', '安装 WASM 组件')}
                </h3>
              </div>
              <form ref={uploadForm} onSubmit={uploadPlugin}>
                <div className="card-body">
                  <p>
                    {say(
                      'Upload one valid component file up to 32 MiB. ZIP archives, PHP files, and remote URL downloads are not supported.',
                      '只接受单个有效组件文件，最大 32 MiB。不支持 ZIP、PHP 文件或远程 URL 下载。',
                    )}
                  </p>
                  <label htmlFor="wasm-plugin-file">
                    {say('Component file', '组件文件')}
                  </label>
                  <input
                    className="form-control-file"
                    id="wasm-plugin-file"
                    type="file"
                    accept=".wasm,application/wasm"
                    required
                    onChange={(event) =>
                      setFile(event.currentTarget.files?.[0] ?? null)
                    }
                  />
                </div>
                <div className="card-footer clearfix">
                  <button
                    className="btn btn-primary float-right"
                    type="submit"
                    disabled={!file || isUploading}
                  >
                    {isUploading
                      ? say('Uploading…', '正在上传…')
                      : say('Upload component', '上传组件')}
                  </button>
                </div>
              </form>
            </div>
            <div className="card card-default">
              <div className="card-header">
                <h3 className="card-title">
                  {say('Port legacy PHP plugins', '移植旧 PHP 插件')}
                </h3>
              </div>
              <div className="card-body">
                <p>{say('Run this on the server:', '在服务器终端运行：')}</p>
                <pre>
                  <code>
                    blessing-skin-rs plugin-migrate &lt;legacy-plugin-dir&gt;
                    {' --output <scaffold-dir>'}
                  </code>
                </pre>
                <p>
                  {say(
                    'The tool reports PHP dependencies and hooks and creates a Rust/WASM scaffold. It does not execute or translate PHP code.',
                    '迁移工具会报告 PHP 依赖和钩子并生成 Rust/WASM 脚手架；不会执行或自动翻译 PHP 代码。',
                  )}
                </p>
              </div>
            </div>
          </>
        ) : (
          <div className="callout callout-info">
            {say(
              'Only super administrators can upload components.',
              '只有超级管理员可以上传组件。',
            )}
          </div>
        )}
      </div>
    </div>
  )
}

export default hot(WasmPlugins)
