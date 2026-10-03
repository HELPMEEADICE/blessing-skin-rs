import React from 'react'
import { render } from '@testing-library/react'
import Welcome from '@/views/setup/Welcome'

beforeEach(() => {
  blessing.locale = 'en'
  blessing.extra = { setup_welcome: { version: 'test-version' } }
})

test('shows setup prerequisites and links to database configuration', () => {
  const { getByText, getByRole } = render(<Welcome />)

  expect(getByText('Welcome')).toBeInTheDocument()
  expect(getByText(/test-version/)).toBeInTheDocument()
  expect(getByRole('link', { name: 'Start setup' })).toHaveAttribute(
    'href',
    '/setup/database',
  )
})
