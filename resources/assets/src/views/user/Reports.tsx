import React, { useEffect, useState } from 'react'
import { hot } from 'react-hot-loader/root'
import { t } from '@/scripts/i18n'
import * as fetch from '@/scripts/net'
import type { Paginator } from '@/scripts/types'
import Loading from '@/components/Loading'
import Pagination from '@/components/Pagination'

type Report = {
  id: number
  tid: number
  texture_name: string | null
  reason: string
  status: 0 | 1 | 2
  report_at: string
}

const Reports: React.FC = () => {
  const [reports, setReports] = useState<Report[]>([])
  const [page, setPage] = useState(1)
  const [lastPage, setLastPage] = useState(1)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    let active = true
    setIsLoading(true)
    setError('')
    fetch
      .get<Paginator<Report>>('/user/reports/list', { page })
      .then((result) => {
        if (!active) return
        setReports(result.data)
        setLastPage(result.last_page)
      })
      .catch((reason: unknown) => {
        if (!active) return
        setError(
          reason instanceof Error ? reason.message : t('general.fatalError'),
        )
      })
      .finally(() => {
        if (active) setIsLoading(false)
      })
    return () => {
      active = false
    }
  }, [page])

  const statusText = (status: Report['status']) => {
    switch (status) {
      case 0:
        return t('report.status.0')
      case 1:
        return t('report.status.1')
      default:
        return t('report.status.2')
    }
  }

  return (
    <div className="card">
      {error && (
        <div className="card-body text-danger" role="alert">
          {error}
        </div>
      )}
      {isLoading ? (
        <div className="card-body">
          <Loading />
        </div>
      ) : (
        <div className="card-body p-0 table-responsive">
          <table className="table table-striped">
            <thead>
              <tr>
                <th>{t('report.tid')}</th>
                <th>{t('report.reason')}</th>
                <th>{t('report.status-title')}</th>
                <th>{t('report.time')}</th>
              </tr>
            </thead>
            <tbody>
              {reports.length === 0 ? (
                <tr>
                  <td className="text-center" colSpan={4}>
                    {t('general.noResult')}
                  </td>
                </tr>
              ) : (
                reports.map((report) => (
                  <tr key={report.id}>
                    <td>
                      {report.tid}{' '}
                      <a
                        href={`${blessing.base_url}/skinlib/show/${report.tid}`}
                        target="_blank"
                        rel="noreferrer"
                      >
                        <i
                          className="fas fa-share"
                          aria-label={t('user.viewInSkinlib')}
                        />
                      </a>
                    </td>
                    <td>{report.reason}</td>
                    <td>{statusText(report.status)}</td>
                    <td>{report.report_at}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      )}
      <div className="card-footer d-flex flex-row-reverse">
        <Pagination page={page} totalPages={lastPage} onChange={setPage} />
      </div>
    </div>
  )
}

export default hot(Reports)
