import React from 'react'
import { fireEvent, render, waitFor } from '@testing-library/react'
import * as fetch from '@/scripts/net'
import Settings from '@/views/admin/Settings'

jest.mock('@/scripts/net')

beforeEach(() => {
  window.blessing.extra = {
    settings: {
      section: 'resource',
      title: 'Resources and cache',
      fields: [
        {
          key: 'force_ssl',
          label: 'Force HTTPS',
          kind: 'checkbox',
          value: 'false',
          checked: false,
          choices: [],
        },
        {
          key: 'cache_expire_time',
          label: 'Cache expiration (seconds)',
          kind: 'number',
          value: '3600',
          checked: false,
          choices: [],
        },
      ],
    },
  }
})

test('submits typed settings to the matching Rust settings route', async () => {
  fetch.post.mockResolvedValue({ code: 0, message: 'Settings saved.' })
  const { getByLabelText, getByRole, getByText } = render(<Settings />)

  fireEvent.click(getByLabelText('Force HTTPS'))
  fireEvent.change(getByLabelText('Cache expiration (seconds)'), {
    target: { value: '7200' },
  })
  fireEvent.submit(
    getByRole('button', { name: 'Save settings' }).closest('form')!,
  )

  await waitFor(() =>
    expect(fetch.post).toBeCalledWith('/admin/resource', {
      values: { force_ssl: true, cache_expire_time: '7200' },
    }),
  )
  expect(getByText('Settings saved.')).toBeInTheDocument()
})
