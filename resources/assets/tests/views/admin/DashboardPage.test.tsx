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
  }
  fetch.get.mockResolvedValue({
    labels: ['User Registration', 'Texture Uploads'],
    xAxis: ['2026-10-01', '2026-10-02'],
    data: [[1, 2], [0, 1]],
  })
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
