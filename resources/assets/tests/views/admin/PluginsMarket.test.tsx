import React from 'react'
import { render, waitFor, fireEvent } from '@testing-library/react'
import { t } from '@/scripts/i18n'
import * as fetch from '@/scripts/net'
import PluginsMarket from '@/views/admin/PluginsMarket'
import type {
  Plugin,
  PluginMarketResponse,
} from '@/views/admin/PluginsMarket/types'

jest.mock('@/scripts/net')

const fixture: Readonly<Plugin> = Object.freeze<Readonly<Plugin>>({
  name: 'yggdrasil-api',
  title: 'Yggdrasil API',
  description: 'Yggdrasil authentication provider',
  version: '1.0.0',
  author: 'Blessing Skin',
  installed: false,
})
const configuredRegistry: Readonly<PluginMarketResponse> = Object.freeze({
  configured: true,
  plugins: [fixture],
})

beforeEach(() => {
  fetch.get.mockResolvedValue(configuredRegistry)
})

test('search plugins by name or title', async () => {
  const { getByPlaceholderText, queryByText } = render(<PluginsMarket />)
  await waitFor(() => expect(fetch.get).toBeCalled())

  fireEvent.input(getByPlaceholderText(t('vendor.datatable.search')), {
    target: { value: 'missing' },
  })
  expect(queryByText('yggdrasil-api')).not.toBeInTheDocument()
})

test('shows setup guidance when no Rust registry is configured', async () => {
  fetch.get.mockResolvedValue({ configured: false, plugins: [] })
  const { findByText } = render(<PluginsMarket />)
  expect(await findByText(/WASM_PLUGIN_REGISTRY_URL/)).toBeInTheDocument()
})

test('installs a registry component and marks it installed', async () => {
  fetch.post.mockResolvedValue({
    code: 0,
    message: 'Installed. Restart the service.',
  })
  const { findByText, getByText, queryByText } = render(<PluginsMarket />)
  await findByText('yggdrasil-api')

  fireEvent.click(getByText(t('admin.installPlugin')))
  await waitFor(() =>
    expect(fetch.post).toBeCalledWith('/admin/plugins/market/download', {
      name: fixture.name,
    }),
  )
  expect(
    await findByText('Installed. Restart the service.'),
  ).toBeInTheDocument()
  expect(queryByText(t('admin.installPlugin'))).not.toBeInTheDocument()
})

test('does not offer an install action for installed components', async () => {
  fetch.get.mockResolvedValue({
    configured: true,
    plugins: [{ ...fixture, installed: true }],
  })
  const { findByText, queryByText } = render(<PluginsMarket />)
  expect(await findByText('Installed')).toBeInTheDocument()
  expect(queryByText(t('admin.installPlugin'))).not.toBeInTheDocument()
})

test('confirms and applies available updates', async () => {
  fetch.get.mockResolvedValue({
    configured: true,
    plugins: [
      {
        ...fixture,
        installed: true,
        installed_version: '0.5.0',
        can_update: true,
      },
    ],
  })
  fetch.post.mockResolvedValue({
    code: 0,
    message: 'Updated. Restart the service.',
  })
  const { findByText, getByText, queryByText } = render(<PluginsMarket />)
  await findByText('yggdrasil-api')

  fireEvent.click(getByText(t('admin.updatePlugin')))
  expect(
    await findByText(
      t('admin.confirmUpdate', {
        plugin: fixture.title,
        old: '0.5.0',
        new: fixture.version,
      }),
    ),
  ).toBeInTheDocument()
  fireEvent.click(getByText(t('general.confirm')))

  await waitFor(() =>
    expect(fetch.post).toBeCalledWith('/admin/plugins/market/download', {
      name: fixture.name,
    }),
  )
  expect(await findByText('Updated. Restart the service.')).toBeInTheDocument()
  expect(queryByText(t('admin.updatePlugin'))).not.toBeInTheDocument()
})
