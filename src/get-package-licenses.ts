import { spawn } from 'node:child_process'
import { resolve } from 'node:path'
import { cwd } from 'node:process'
import { debug, isDebug } from '@actions/core'
import { PackageDetails } from './types'

/**
 *
 * @param {string} directory The directory to get licenses for, needs to contain package.json
 * @returns {Promise<Record<string, Array<PackageDetails>>>} A map of licenses to list of packages
 */
export async function getLicenses(directory: string): Promise<Record<string, Array<PackageDetails>>> {
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

  if (isDebug()) {
    debug('Licenses JSON')
    debug(stdout)
  }

  return stdout.startsWith('{') ? JSON.parse(stdout) : {}
}
