import React from 'react'
import { render } from '@testing-library/react'
import Info from '@/views/setup/Info'

beforeEach(() => {
  blessing.locale = 'en'
  blessing.extra = {
    setup_info: {
      csrf: 'csrf-token',
      site_name: 'Example Skin',
      error: '',
    },
  }
})

test('renders the native administrator setup form with CSRF', () => {
  const { getByLabelText, getByRole, getByDisplayValue } = render(<Info />)

  expect(getByLabelText('Administrator email')).toHaveAttribute('type', 'email')
  expect(getByLabelText('Password (8 to 32 characters)')).toHaveAttribute(
    'minLength',
    '8',
  )
  expect(getByLabelText('Confirm password')).toHaveAttribute(
    'name',
    'password_confirmation',
  )
  expect(getByDisplayValue('csrf-token')).toHaveAttribute('name', 'csrf')
  expect(getByLabelText('Site name')).toHaveValue('Example Skin')
  expect(getByRole('button', { name: 'Install' })).toBeInTheDocument()
})

test('shows installer validation errors', () => {
  blessing.extra.setup_info.error = 'Enter a valid administrator email address.'
  const { getByRole } = render(<Info />)

  expect(getByRole('alert')).toHaveTextContent(
    'Enter a valid administrator email address.',
  )
})
