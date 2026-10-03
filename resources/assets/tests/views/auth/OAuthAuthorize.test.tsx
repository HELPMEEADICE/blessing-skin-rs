import React from 'react'
import { render } from '@testing-library/react'
import OAuthAuthorize from '@/views/auth/OAuthAuthorize'

beforeEach(() => {
  blessing.locale = 'en'
  blessing.extra = {
    oauth: {
      auth_token: 'signed-token',
      client_id: 42,
      client_name: 'Third-party app',
      scopes: ['User.Read', 'Plugin.Custom'],
    },
  }
})

test('renders consent details and native approve and deny forms', () => {
  const { getByText, getAllByRole, getAllByDisplayValue, getByDisplayValue } =
    render(<OAuthAuthorize />)

  expect(getByText('Third-party app')).toBeInTheDocument()
  expect(getByText('Approve')).toBeInTheDocument()
  expect(getByText('Deny')).toBeInTheDocument()
  expect(getByText('Plugin.Custom')).toBeInTheDocument()
  expect(getAllByRole('button')).toHaveLength(2)
  expect(getAllByDisplayValue('signed-token')).toHaveLength(2)
  expect(getByDisplayValue('42')).toBeInTheDocument()
  expect(getByDisplayValue('DELETE')).toBeInTheDocument()
})
