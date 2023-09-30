import { setFailed, getMultilineInput, getInput, warning, info } from '@actions/core'
import { Table } from 'console-table-printer'
import { action } from './action'


// const allowed_licenses = new Set([
//   'MIT',
//   'ISC',
//   'BSD-2-Clause',
//   'BSD-3-Clause',
//   'Apache-2.0',
//   'MIT OR Apache-2.0',
//   'Python-2.0',
//   'public domain',
//   '(MIT OR WTFPL)',
//   'Unlicense',
//   'BlueOak-1.0.0',
//   'Public Domain',
//   '(BSD-3-Clause OR GPL-2.0)',
//   '(BSD-2-Clause OR MIT OR Apache-2.0)',
//   '(MIT OR CC0-1.0)',
//   '0BSD',
//   'CC0-1.0',
//   'MPL-2.0'
// ])

// const ignored_packages = [
//   { name: 'filter-iterator', version: '0.0.1' },
//   { name: 'do-taskmanager', version: '2.0.0-rc.0' },
//   { name: 'flareutils', version: '0.3.4' },
//   { name: 'spdx-exceptions', version: '2.3.0' }
// ]

try {
  const directory = (getInput('directory', { required: false, trimWhitespace: true }) || '.').replaceAll('\'', '')
  const allowed_licenses = new Set(getMultilineInput('allowed', { required: false }) ?? [])
  const ignored_packages = new Set(getMultilineInput('ignored', { required: false }).map(pkg => {
    if (!pkg.startsWith('@')) {
      const [ _, name, version ] = pkg.split('@')
      return { name: `@${name}`, version }
    }
    const [ name, version ] = pkg.split('@')
    return { name, version }
  }))

  const result = await action(directory, allowed_licenses, ignored_packages)

  if (result.success === true) {
    info('All licenses are valid')
    const table = new Table({
      columns: [
        { alignment: 'left', name: 'license', title: 'License' },
        { alignment: 'right', name: 'packages', title: 'Count' }
      ]
    })
    table.addRows(result.licensesUsed)
    info(table.render())
  } else {
    setFailed('Invalid licenses found')
    for (const license of result.invalidLicenses) {
      warning(`Invalid license ${license}`)
      const table = new Table({
        columns: [
          { alignment: 'left', name: 'name', title: 'Name' },
          { alignment: 'left', name: 'version', title: 'Version' },
          { alignment: 'left', name: 'license', title: 'License' },
          { alignment: 'left', name: 'homepage', title: 'Homepage' }
        ]
      })
      table.addRows([ ...result.licensesUsed[license] ].map(pkg => ({
        name: pkg.name,
        version: pkg.version,
        license: pkg.license,
        homepage: pkg.homepage
        // todo include chain `pnpm why <package> --json`
      })))
      info(table.render())
    }
  }

} catch (error) {
  setFailed(error.message)
}
