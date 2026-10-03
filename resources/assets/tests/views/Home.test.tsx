import React from 'react'

import { render } from '@testing-library/react'

import Home from '@/views/Home'

beforeEach(() => {
  blessing.site_name = 'Example Skin'

  blessing.extra = {
    transparent_navbar: false,

    home: {
      title: 'Skin Server',

      login: 'Log in',

      register: 'Register',

      browse_skinlib: 'Browse skin library',

      user_center: 'User Center',

      admin_panel: 'Admin Panel',

      logout: 'Log Out',

      description: 'A skin hosting service',

      background: '/app/bg.webp',

      fixed_bg: false,

      hide_intro: false,

      navbar_color: 'cyan',

      authenticated: false,

      copyright_prefer: 0,

      copyright_text: '',
    },
  }

  blessing.i18n = {
    general: {
      skinlib: 'Skin Library',
    },

    index: {
      features: {
        title: 'Features',

        first: { icon: 'fa-users', name: 'Players', desc: 'Many players' },

        second: { icon: 'fa-share-alt', name: 'Sharing', desc: 'Share skins' },

        third: { icon: 'fa-cloud', name: 'Free', desc: 'Always free' },
      },

      introduction: ':sitename hosts Minecraft skins.',

      start: 'Join us',
    },
  }
})

test('renders the localized landing page and public navigation links', () => {
  const { getAllByText, getByText } = render(<Home />)

  expect(getAllByText('Example Skin')).toHaveLength(2)

  expect(getByText('A skin hosting service')).toBeInTheDocument()

  expect(getByText('Features')).toBeInTheDocument()

  expect(getByText('Players')).toBeInTheDocument()

  expect(getByText('Example Skin hosts Minecraft skins.')).toBeInTheDocument()

  expect(getByText('Log in').closest('a')).toHaveAttribute(
    'href',

    '/auth/login',
  )

  expect(getByText('Browse skin library').closest('a')).toHaveAttribute(
    'href',

    '/skinlib',
  )
})

test('uses customization and signed-in navigation settings', () => {
  blessing.extra.transparent_navbar = true

  blessing.extra.home = {
    ...blessing.extra.home,

    background: '/uploads/home.webp',

    fixed_bg: true,

    hide_intro: true,

    authenticated: true,

    user_id: 7,

    user_label: 'Player Seven',
  }

  const { container, getAllByText, getByText, queryByText } = render(<Home />)

  expect(container.querySelector('.home-background')).toHaveClass('fixed')

  expect(container.querySelector('.navbar')).toHaveClass('transparent')

  expect(getByText('Player Seven').closest('a')).toHaveAttribute(
    'href',
    '/user',
  )

  getAllByText('User Center').forEach((node) => {
    expect(node.closest('a')).toHaveAttribute('href', '/user')
  })

  expect(queryByText('Features')).not.toBeInTheDocument()
})
