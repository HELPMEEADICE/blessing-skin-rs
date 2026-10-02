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

  fs.writeFileSync(
    path.join(outputRoot, `${locale}.json`),
    `${JSON.stringify(translations)}\n`,
  )
}
