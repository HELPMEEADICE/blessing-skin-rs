import React from 'react'
import { fireEvent, render, waitFor } from '@testing-library/react'
import * as fetch from '@/scripts/net'
import BindEmail from '@/views/auth/BindEmail'

jest.mock('@/scripts/net')

test('submits a new account email and shows validation errors', async () => {
  fetch.post.mockResolvedValue({
    code: 1,
    message: 'This email address is already in use.',
  })

  const { getByPlaceholderText, getByRole, getByText } = render(
    <BindEmail />,
  )
  fireEvent.change(getByPlaceholderText('Email address'), {
    target: { value: 'taken@example.test' },
  })
  fireEvent.click(getByRole('button', { name: 'Bind and continue' }))

  await waitFor(() =>
    expect(fetch.post).toBeCalledWith('/auth/bind', {
      email: 'taken@example.test',
    }),
  )
  expect(
    getByText('This email address is already in use.'),
  ).toBeInTheDocument()
})
