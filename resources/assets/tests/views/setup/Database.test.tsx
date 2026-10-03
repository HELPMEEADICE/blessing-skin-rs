import React from 'react'
import { render } from '@testing-library/react'
import Database from '@/views/setup/Database'

beforeEach(() => {
  blessing.locale = 'en'
  blessing.extra = {
    setup_database: {
      csrf: 'csrf-token',
      driver: 'sqlite',
      host: '',
      port: '',
      username: '',
      database: '/var/lib/blessing/database.sqlite',
      prefix: 'skin_',
      error: '',
      saved: false,
    },
  }
})

test('preserves the native setup form fields and CSRF token', () => {
  const { getByLabelText, getByRole, getByDisplayValue } = render(<Database />)

  expect(getByLabelText('Database type')).toHaveValue('sqlite')
  expect(getByLabelText('Database name or SQLite file path')).toHaveValue(
    '/var/lib/blessing/database.sqlite',
  )
  expect(getByDisplayValue('csrf-token')).toHaveAttribute('name', 'csrf')
  expect(getByLabelText('Table prefix (optional)')).toHaveValue('skin_')
  expect(getByRole('button', { name: 'Test and save' })).toBeInTheDocument()
})

test('shows the saved configuration restart notice', () => {
  blessing.extra.setup_database.saved = true
  const { getByText, queryByLabelText } = render(<Database />)

  expect(getByText(/The connection succeeded/)).toBeInTheDocument()
  expect(queryByLabelText('Database type')).not.toBeInTheDocument()
})
