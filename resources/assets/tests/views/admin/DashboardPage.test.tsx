import React from 'react'
import { fireEvent, render, waitFor } from '@testing-library/react'
import * as fetch from '@/scripts/net'
import DashboardPage from '@/views/admin/DashboardPage'

jest.mock('@/scripts/net')
jest.mock('@/views/admin/createDashboardChart', () => ({
  createDashboardChart: jest.fn(() => ({ dispose: jest.fn() })),
}))

beforeEach(() => {
  window.blessing.extra = {
    dashboard_stats: { users: 4, players: 2, textures: 1, storage: 8 },
    page_widgets: ['usage', 'notification', 'chart'],
    side_menu: [
      { label: 'Users', link: '/admin/users' },
      { label: 'Players', link: '/admin/players' },
      { label: 'Reports', link: '/admin/reports' },
      { label: 'Internationalization', link: '/admin/i18n' },
      { label: 'Site settings', link: '/admin/options' },
      { label: 'System status', link: '/admin/status' },
      { label: 'Plugins', link: '/admin/plugins/manage' },
      { label: 'Updates', link: '/admin/update' },
    ],
  }
  fetch.get.mockResolvedValue({
    labels: ['User Registration', 'Texture Uploads'],
    xAxis: ['2026-10-01', '2026-10-02'],
    data: [
      [1, 2],
      [0, 1],
    ],
  })
})

test('links administrators to standalone Rust releases', () => {
  const { getByRole } = render(<DashboardPage />)

  expect(getByRole('link', { name: 'Updates' })).toHaveAttribute(
    'href',
    '/admin/update',
  )
})

test('renders the filtered navigation in the configured order', () => {
  window.blessing.extra.side_menu = [
    { label: 'Plugins', link: '/admin/plugins/manage' },
    { label: 'Updates', link: '/admin/update' },
  ]
  const { getByRole, queryByRole } = render(<DashboardPage />)

  expect(getByRole('navigation').querySelectorAll('a')).toHaveLength(2)
  expect(getByRole('link', { name: 'Plugins' })).toHaveAttribute(
    'href',
    '/admin/plugins/manage',
  )
  expect(getByRole('link', { name: 'Updates' })).toHaveAttribute(
    'href',
    '/admin/update',
  )
  expect(queryByRole('link', { name: 'Users' })).not.toBeInTheDocument()
})

test('renders dashboard regions in the configured order', () => {
  window.blessing.extra.page_widgets = ['chart', 'notification', 'usage']
  const { container } = render(<DashboardPage />)

  expect(
    Array.from(container.querySelectorAll('.notice, .stats, .charts')).map(
      (region) => region.className,
    ),
  ).toEqual(['charts', 'notice', 'stats'])
})

test('omits filtered regions and does not load hidden charts', () => {
  window.blessing.extra.page_widgets = ['notification']
  const { container } = render(<DashboardPage />)

  expect(container.querySelectorAll('.notice, .stats, .charts')).toHaveLength(1)
  expect(container.querySelector('.notice')).toBeInTheDocument()
  expect(fetch.get).not.toBeCalled()
})

test('sends a notification to the selected user', async () => {
  fetch.post.mockResolvedValue({ code: 0, message: 'Notification sent' })
  const { getByLabelText, getByRole, getByText } = render(<DashboardPage />)

  fireEvent.change(getByLabelText('Recipients'), {
    target: { value: 'uid' },
  })
  fireEvent.change(getByLabelText('UID'), { target: { value: '7' } })
  fireEvent.change(getByLabelText('Title (up to 20 characters)'), {
    target: { value: 'Maintenance' },
  })
  fireEvent.change(getByLabelText('Content'), {
    target: { value: 'The server restarts tonight.' },
  })
  fireEvent.submit(getByRole('button', { name: 'Send' }).closest('form')!)

  await waitFor(() =>
    expect(fetch.post).toBeCalledWith('/admin/notifications/send', {
      receiver: 'uid',
      uid: '7',
      email: '',
      title: 'Maintenance',
      content: 'The server restarts tonight.',
    }),
  )
  expect(getByText('Notification sent')).toBeInTheDocument()
})
