import { spawn } from 'node:child_process'
import { resolve } from 'node:path'
import { cwd } from 'node:process'
import type { PackageDetails } from './types'
import { getPnpmVersion } from './get-pnpm-version'


async function runPnpmLicenses(directory: string): Promise<string> {
  const proc = spawn('pnpm', [ 'licenses', 'ls', '--json' ], {
    cwd: resolve(cwd(), directory)
  })

  let stdout = ''
  proc.stdout.on('data', data => stdout += data.toString())

  // eslint-disable-next-line promise/avoid-new
  await new Promise((resolve, reject) => {
    proc.on('close', resolve)
    proc.on('error', reject)
  })

  return stdout
}


/**
 *
 * @param {string} directory The directory to get licenses for, needs to contain package.json
 * @returns {Promise<Record<string, Array<PackageDetails>>>} A map of licenses to list of packages
 */
export async function getLicenses(directory: string): Promise<Record<string, Array<PackageDetails>>> {

  const major = (await getPnpmVersion()).split('.', 1).join('')

  switch (major) {
    case '10':
    case '9': {
      const result = await runPnpmLicenses(directory)
      const parsedResult = result.startsWith('{') ? JSON.parse(result) : {}
      return Object
        .entries(parsedResult)
        .map(([ license, packages ]) => {
          return (packages as Array<Omit<PackageDetails, 'version' | 'path'> & { versions: string[]; paths: string[] }>).map(pkg => {
            const { paths, versions, ...rest } = pkg
            return versions.map((version, i) => [license, { version, path: paths[i], ...rest }])
          }).flat()
        })
        .flat()
        .reduce(function(acc, [license, pkg]) {
          // @ts-expect-error shut up
          acc[license] = acc[license] || []
          // @ts-expect-error shut up
          acc[license].push(pkg)
          return acc
          }, {}
        );
    }
    case '8': {
      const result = await runPnpmLicenses(directory)
      return result.startsWith('{') ? JSON.parse(result) : {}
    }
    default:
      throw new Error('Unsupported pnpm version, please use pnpm 8 or 9.')
  }
}
