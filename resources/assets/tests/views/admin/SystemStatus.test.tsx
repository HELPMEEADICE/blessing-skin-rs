import React from 'react'
import { render } from '@testing-library/react'
import SystemStatus from '@/views/admin/SystemStatus'

beforeEach(() => {
  blessing.locale = 'en'
  blessing.site_name = 'Example Skin'
  blessing.extra = {
    admin_status: {
      groups: [
        {
          title: 'Database',
          fields: [{ label: 'Type', value: 'SQLite' }],
        },
      ],
      wasm_plugins: ['sample-plugin'],
      page_widgets: ['system_info', 'plugins'],
    },
  }
})

test('renders system status fields and loaded WASM plugins', () => {
  const { getByText, getByRole } = render(<SystemStatus />)

  expect(getByText('System status - Example Skin')).toBeInTheDocument()
  expect(getByText('SQLite')).toBeInTheDocument()
  expect(getByText('Loaded WASM plugins (1)')).toBeInTheDocument()
  expect(getByText('sample-plugin')).toBeInTheDocument()
  expect(getByRole('link', { name: 'Admin dashboard' })).toHaveAttribute(
    'href',
    '/admin',
  )
})

test('renders status regions in the configured order', () => {
  blessing.extra.admin_status.page_widgets = ['plugins', 'system_info']

  const { getAllByRole } = render(<SystemStatus />)

  expect(getAllByRole('heading').map((heading) => heading.textContent)).toEqual(
    ['System status - Example Skin', 'Loaded WASM plugins (1)', 'Database'],
  )
})
