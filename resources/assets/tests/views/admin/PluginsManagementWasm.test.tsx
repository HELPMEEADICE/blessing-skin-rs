import React from 'react'
import { fireEvent, render, waitFor } from '@testing-library/react'
import * as fetch from '@/scripts/net'
import PluginsManagement from '@/views/admin/PluginsManagement'

jest.mock('@/scripts/net')

const originalExtra = blessing.extra

afterEach(() => {
  blessing.extra = originalExtra
  jest.clearAllMocks()
})

test('renders and manages Rust WASM components', async () => {
  blessing.extra = { wasm_plugins: true, can_upload: false }
  fetch.get.mockResolvedValue([
    {
      name: 'sample',
      title: 'sample',
      description: 'Enabled; will load on next startup',
      version: 'WASM lifecycle API 1.0.0',
      enabled: true,
      loaded: false,
      on_disk: true,
    },
  ])
  fetch.post.mockResolvedValue({
    code: 0,
    message:
      'Plugin file updated. Restart the service for the change to take effect.',
  })

  const { getByRole, getByText } = render(<PluginsManagement />)
  await waitFor(() => expect(getByText('sample')).toBeInTheDocument())

  fireEvent.click(getByRole('button', { name: 'Disable' }))
  await waitFor(() =>
    expect(fetch.post).toBeCalledWith('/admin/plugins/manage', {
      action: 'disable',
      name: 'sample',
    }),
  )
  expect(
    await getByText(
      'Plugin file updated. Restart the service for the change to take effect.',
    ),
  ).toBeInTheDocument()
})

test('uploads one WASM component for super administrators', async () => {
  blessing.extra = { wasm_plugins: true, can_upload: true }
  fetch.get.mockResolvedValue([])
  fetch.post.mockResolvedValue({
    code: 0,
    message: 'WASM component installed. Restart the service to load it.',
  })

  const { getByLabelText, getByRole, getByText } = render(<PluginsManagement />)
  const componentFile = new File(['component'], 'sample.wasm', {
    type: 'application/wasm',
  })
  fireEvent.change(getByLabelText('Component file'), {
    target: { files: [componentFile] },
  })
  fireEvent.click(getByRole('button', { name: 'Upload component' }))

  await waitFor(() =>
    expect(fetch.post).toBeCalledWith(
      '/admin/plugins/upload',
      expect.any(FormData),
    ),
  )
  expect(
    await getByText(
      'WASM component installed. Restart the service to load it.',
    ),
  ).toBeInTheDocument()
})
