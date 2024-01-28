import { debug } from '@actions/core'
import { getLicenses } from './get-package-licenses'
import { matchesIgnore } from './ignore'
import type { AllowedLicenses, IgnoredPackages, Result } from './types'

/**
 *
 * @param {string} directory The directory to get licenses for, needs to contain package.json
 * @param {AllowedLicenses} allowedLicenses Set of allowed licenses
 * @param {IgnoredPackages} ignoredPackages Set of 'package @ version' to ignore
 * @returns {Promise<Result>} The result of the action
 */
export async function action(
  directory: string,
  allowedLicenses: AllowedLicenses,
  ignoredPackages: IgnoredPackages
): Promise<Result> {
  let result: Result = {
    success: true,
    unusedIgnores: [],
    licensesUsed: {}
  }

  const licenses = await getLicenses(directory)

  ignores: for (const ignored of ignoredPackages) {
    for (const [ _, packages ] of Object.entries(licenses)) {
      if (!packages || !Array.isArray(packages)) {
        debug(`Something went wrong with ${ignored.name}@${ignored.version}`)
        debug(`Licenses: ${JSON.stringify(licenses, null, 2)}`)
        continue
      }
      if (packages.some(pkg => matchesIgnore(pkg.name, ignored.name) && matchesIgnore(pkg.version, ignored.version))) {
        continue ignores
      }
    }
    result.unusedIgnores.push(`${ignored.name}@${ignored.version}`)
  }

  for (const [ license, packages ] of Object.entries(licenses)) {
    if (!Array.isArray(packages)) {
      debug(`No packages found using ${license}`)
      continue
    }
    licenses[license] = packages
      .filter(pkg => {
        for (const { name, version } of ignoredPackages) {
          if (matchesIgnore(pkg.name, name) && matchesIgnore(pkg.version, version)) {
            return false
          }
        }
        return true
      })
  }

  result.licensesUsed = Object.fromEntries(Object.entries(licenses)
    .filter(([ _, packages ]) => Array.isArray(packages))
    .map(([ license, packages ]) => ([ license, new Set(packages) ] as const))
    .sort((a, b) => b[1].size - a[1].size))

  const invalidLicenses = new Set(Object.entries(licenses)
    .filter(([ license ]) => !allowedLicenses.has(license))
    .filter(([ _, packages ]) => packages.length > 0)
    .map(([ license ]) => license))

  if (invalidLicenses.size > 0) {
    result = {
      ...result,
      invalidLicenses,
      success: false
    }
  }

  return result
}
