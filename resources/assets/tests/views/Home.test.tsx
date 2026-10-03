import React from 'react'
import { render } from '@testing-library/react'
import Home from '@/views/Home'

beforeEach(() => {
  blessing.site_name = 'Example Skin'
  blessing.extra = {
    home: {
      title: 'Skin Server',
      login: 'Log in',
      browse_skinlib: 'Browse skin library',
    },
  }
})

test('renders the site title and public navigation links', () => {
  const { getByText } = render(<Home />)

  expect(getByText('Example Skin')).toBeInTheDocument()
  expect(getByText('Skin Server')).toBeInTheDocument()
  expect(getByText('Log in').closest('a')).toHaveAttribute(
    'href',
    '/auth/login',
  )
  expect(getByText('Browse skin library').closest('a')).toHaveAttribute(
    'href',
    '/skinlib',
  )
})
