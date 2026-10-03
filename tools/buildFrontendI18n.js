const fs = require('fs')
const path = require('path')
const yaml = require('js-yaml')

const languageRoot = path.resolve(__dirname, '../resources/lang')
const outputRoot = path.resolve(__dirname, '../public/app/i18n')

fs.mkdirSync(outputRoot, { recursive: true })

for (const locale of fs.readdirSync(languageRoot).sort()) {
  if (!/^[a-zA-Z0-9_-]+$/.test(locale)) {
    continue
  }

  const input = path.join(languageRoot, locale, 'front-end.yml')
  if (!fs.existsSync(input)) {
    continue
  }

  const translations = yaml.safeLoad(fs.readFileSync(input, 'utf8'))
  if (
    !translations ||
    typeof translations !== 'object' ||
    Array.isArray(translations)
  ) {
    throw new Error(`Expected a translation mapping in ${input}`)
  }

  const indexPath = path.join(languageRoot, locale, 'index.yml')
  if (fs.existsSync(indexPath)) {
    const index = yaml.safeLoad(fs.readFileSync(indexPath, 'utf8'))
    if (index && typeof index === 'object' && !Array.isArray(index)) {
      translations.index = index
    }
  }

  fs.writeFileSync(
    path.join(outputRoot, `${locale}.json`),
    `${JSON.stringify(translations)}\n`,
  )
}
