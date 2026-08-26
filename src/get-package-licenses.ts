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

  await new Promise((resolve, reject) => {
    proc.on('close', resolve)
    proc.on('error', reject)
  })

  return stdout
}


export function parseLicensesJson(result: string): Record<string, Array<PackageDetails>> {
  const parsedResult = result.startsWith('{') ? JSON.parse(result) : {}

  if (parsedResult && typeof parsedResult === 'object' && 'error' in parsedResult && parsedResult.error && typeof parsedResult.error === 'object') {
    const { code, message } = parsedResult.error as { code?: string; message?: string }

    throw new Error(`pnpm licenses ls failed${code ? ` (${code})` : ''}: ${message ?? 'unknown error'}`)
  }

  return Object
    .entries(parsedResult)
    .flatMap(([ license, packages ]) => {
      if (!Array.isArray(packages)) {
        return []
      }

      return packages.flatMap(pkg => {
        const { paths, versions, ...rest } = pkg

        if (!Array.isArray(versions) || !Array.isArray(paths)) {
          return []
        }

        return versions.map((version, i) => [ license, { version, path: paths[i], ...rest }])
      })
    })
    .reduce((acc: Record<string, Array<PackageDetails>>, [ license, pkg ]) => {
      acc[license] = acc[license] ?? []
      acc[license].push(pkg as PackageDetails)

      return acc
    }, {})
}


/**
 *
 * @param {string} directory The directory to get licenses for, needs to contain package.json
 * @returns {Promise<Record<string, Array<PackageDetails>>>} A map of licenses to list of packages
 */
export async function getLicenses(directory: string): Promise<Record<string, Array<PackageDetails>>> {

  const major = (await getPnpmVersion()).split('.', 1).join('')

  switch (major) {
    case '11':
    case '10':
    case '9':
      return parseLicensesJson(await runPnpmLicenses(directory))

    case '8': {
      const result = await runPnpmLicenses(directory)

      return result.startsWith('{') ? JSON.parse(result) : {}
    }

    default:
      throw new Error('Unsupported pnpm version, please use pnpm 8 or 9.')
  }
}
