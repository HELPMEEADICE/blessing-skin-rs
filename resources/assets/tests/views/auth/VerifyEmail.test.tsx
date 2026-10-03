import React from 'react'
import { fireEvent, render, waitFor } from '@testing-library/react'
import * as fetch from '@/scripts/net'
import VerifyEmail from '@/views/auth/VerifyEmail'

jest.mock('@/scripts/net')

test('posts the email to the signed verification URL', async () => {
  blessing.base_url = window.location.origin
  window.history.pushState({}, '', '/auth/verify/7?signature=abc')
  fetch.post.mockResolvedValue({
    code: 1,
    message: 'Email does not match this account.',
  })

  const { getByPlaceholderText, getByRole, getByText } = render(
    <VerifyEmail />,
  )
  fireEvent.change(getByPlaceholderText('Email address'), {
    target: { value: 'wrong@example.test' },
  })
  fireEvent.click(getByRole('button', { name: 'Verify email' }))

  await waitFor(() =>
    expect(fetch.post).toBeCalledWith(
      '/auth/verify/7?signature=abc',
      { email: 'wrong@example.test' },
    ),
  )
  expect(getByText('Email does not match this account.')).toBeInTheDocument()
})
