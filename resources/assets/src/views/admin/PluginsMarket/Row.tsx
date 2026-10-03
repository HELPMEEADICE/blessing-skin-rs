import React from 'react'
import { t } from '@/scripts/i18n'
import type { Plugin } from './types'

interface Props {
  plugin: Plugin
  isInstalling: boolean
  onInstall(): void
  onUpdate(): void
}

const Row: React.FC<Props> = ({
  plugin,
  isInstalling,
  onInstall,
  onUpdate,
}) => {
  const chinese = blessing.locale.startsWith('zh')

  return (
    <tr>
      <td style={{ width: '18%' }}>
        <div>
          <b>{plugin.title}</b>
        </div>
        <div>{plugin.name}</div>
      </td>
      <td style={{ width: '42%' }}>{plugin.description}</td>
      <td>
        <div>{plugin.author}</div>
        <small>{plugin.version}</small>
      </td>
      <td style={{ width: '14%' }}>
        {plugin.can_update ? (
          <button
            className="btn btn-success"
            disabled={isInstalling}
            onClick={onUpdate}
          >
            {isInstalling ? (
              <>
                <i className="fas fa-spinner fa-spin mr-1"></i>
                {t('admin.pluginUpdating')}
              </>
            ) : (
              <>
                <i className="fas fa-sync-alt mr-1"></i>
                {t('admin.updatePlugin')}
              </>
            )}
          </button>
        ) : plugin.installed ? (
          <span className="badge bg-green">
            {chinese ? '已安装' : 'Installed'}
          </span>
        ) : (
          <button
            className="btn btn-success"
            disabled={isInstalling}
            onClick={onInstall}
          >
            {isInstalling ? (
              <>
                <i className="fas fa-spinner fa-spin mr-1"></i>
                {t('admin.pluginInstalling')}
              </>
            ) : (
              <>
                <i className="fas fa-download mr-1"></i>
                {t('admin.installPlugin')}
              </>
            )}
          </button>
        )}
      </td>
    </tr>
  )
}

export default Row
