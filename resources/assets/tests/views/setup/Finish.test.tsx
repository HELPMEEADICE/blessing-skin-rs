import React from 'react'
import { render } from '@testing-library/react'
import Finish from '@/views/setup/Finish'

beforeEach(() => {
  blessing.locale = 'en'
})

test('explains the service restart and links back to the home page', () => {
  const { getByText, getByRole } = render(<Finish />)

  expect(getByText(/Restart the Rust service/)).toBeInTheDocument()
  expect(getByRole('link', { name: 'Home' })).toHaveAttribute('href', '/')
})
