import React from 'react'
import { fireEvent, render, waitFor } from '@testing-library/react'
import * as fetch from '@/scripts/net'
import { t } from '@/scripts/i18n'
import Profile from '@/views/user/Profile'

jest.mock('@/scripts/net')

const profile = {
  nickname: 'Existing Name',
  email: 'user@example.test',
  avatar: 0,
  allow_delete: true,
}

const defaultWidgets = [
  'avatar',
  'password',
  'nickname',
  'email',
  'delete_account',
]

beforeEach(() => {
  window.blessing.extra = { profile, page_widgets: defaultWidgets }
})

test('renders profile regions in the configured order', () => {
  window.blessing.extra.page_widgets = ['email', 'nickname', 'avatar']
  const { container } = render(<Profile />)

  expect(
    Array.from(container.querySelectorAll('.grid section h2')).map(
      (heading) => heading.textContent,
    ),
  ).toEqual(['Change email', 'Change nickname', 'Change avatar'])
})

test('omits profile regions filtered out by plugins', () => {
  window.blessing.extra.page_widgets = ['avatar', 'nickname']
  const { container, queryByRole } = render(<Profile />)

  expect(container.querySelectorAll('.grid section')).toHaveLength(2)
  expect(
    queryByRole('heading', { name: 'Delete account' }),
  ).not.toBeInTheDocument()
})

test('updates the nickname through the legacy profile action', async () => {
  fetch.post.mockResolvedValue({ code: 0, message: 'Nickname updated' })
  const { getByLabelText, getByRole, getByText } = render(<Profile />)
  const input = getByLabelText('New nickname')
  fireEvent.change(input, { target: { value: 'Updated Name' } })
  fireEvent.submit(
    getByRole('button', { name: 'Save nickname' }).closest('form')!,
  )

  await waitFor(() =>
    expect(fetch.post).toBeCalledWith('/user/profile', {
      action: 'nickname',
      new_nickname: 'Updated Name',
    }),
  )
  expect(getByText('Updated Name · user@example.test')).toBeInTheDocument()
})

test('rejects a mismatched password confirmation before sending', () => {
  const { getByLabelText, getByRole, getByText } = render(<Profile />)
  fireEvent.change(getByLabelText('New password'), {
    target: { value: 'password123' },
  })
  fireEvent.change(getByLabelText('Confirm new password'), {
    target: { value: 'password456' },
  })
  fireEvent.submit(
    getByRole('button', { name: 'Update password' }).closest('form')!,
  )

  expect(fetch.post).not.toBeCalled()
  expect(getByText(t('auth.invalidConfirmPwd'))).toBeInTheDocument()
})

test('hides account deletion for an administrator profile', () => {
  window.blessing.extra = {
    profile: { ...profile, allow_delete: false },
    page_widgets: defaultWidgets,
  }
  const { getByText, queryByRole } = render(<Profile />)

  expect(
    getByText('Administrator accounts cannot be deleted.'),
  ).toBeInTheDocument()
  expect(
    queryByRole('button', { name: 'Delete account' }),
  ).not.toBeInTheDocument()
})
