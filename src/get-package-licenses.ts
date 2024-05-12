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
    case '9': {
      const result = await runPnpmLicenses(directory)
      const parsedResult = result.startsWith('{') ? JSON.parse(result) : {}
      return Object.fromEntries(Object
        .entries(parsedResult)
        // for each package entry with "versions", return "version" one at a time
        .map(([license, packages]) => {
          const { paths, versions, ...rest } = packages as Omit<PackageDetails, 'version' | 'path'> & { versions: string[]; paths: string[] }
          return [license, versions.map((version, i) => ({ version, path: paths[i], ...rest }))]
        }))
    }
    case '8': {
      const result = await runPnpmLicenses(directory)
      return result.startsWith('{') ? JSON.parse(result) : {}
    }
    default:
      throw new Error('Unsupported pnpm version, please use pnpm 8 or 9.')
  }
}
