export type Plugin = {
  name: string
  version: string
  title: string
  description: string
  author: string
  installed: boolean
  installed_version?: string
  can_update?: boolean
}

export type PluginMarketResponse = {
  configured: boolean
  plugins: Plugin[]
}
