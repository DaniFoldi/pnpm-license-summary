import { setFailed, getMultilineInput, getInput, warning, info } from '@actions/core'
import { Table } from 'console-table-printer'
import { action } from './action'


try {
  const directory = (getInput('directory', { required: false, trimWhitespace: true }) || '.').replaceAll('\'', '')
  const allowedLicenses = new Set(getMultilineInput('allowed', { required: false }) ?? [])
  const ignoredPackages = new Set(getMultilineInput('ignored', { required: false }).map(pkg => {
    if (pkg.startsWith('@')) {
      const [ _, name = '', version = '' ] = pkg.split('@')
      return { name: `@${name}`, version }
    }
    const [ name = '', version = '' ] = pkg.split('@')
    return { name, version }
  }))

  const result = await action(directory, allowedLicenses, ignoredPackages)

  if (result.success) {
    info('All licenses are valid')
    const table = new Table({
      columns: [
        { alignment: 'left', name: 'license', title: 'License' },
        { alignment: 'right', name: 'count', title: 'Count' }
      ]
    })
    table.addRows(Object.entries(result.licensesUsed).map(pkg => ({
      license: pkg[0],
      count: pkg[1].size
    })))
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
      const packages = result.licensesUsed[license]
      if (!packages) {
        continue
      }
      table.addRows([ ...packages ].map(pkg => ({
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
  if (error instanceof Error) {
    setFailed(error.message)
  } else {
    setFailed(error ? error.toString() : 'Unknown error')
  }
}
