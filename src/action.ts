import { getLicenses } from './get-package-licenses'
import { AllowedLicenses, IgnoredPackages, Result } from './types'

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
    for (const license of Object.keys(licenses)) {
      if (packages.some(pkg => pkg.name === ignored.name && matchesIgnore(pkg.version, ignored.version))) {
        continue ignores
      }
    }
    result.unusedIgnores.push(`${ignored.name}@${ignored.version}`)
  }

  for (const license of Object.keys(licenses)) {
    licenses[license] = licenses[license]
      .filter(pkg => {
        for (const { name, version } of ignoredPackages) {
          if (pkg.name === name && matchesIgnore(pkg.version, version)) {
            return false
          }
        }
        return true
      })
  }

  result.licensesUsed = Object.fromEntries(Object.entries(licenses)
    .map(([ license, packages ]) => ([ license, new Set(packages) ] as const))
    .sort((a, b) => b[1].size - a[1].size))

  const invalidLicenses = new Set(Object.keys(licenses)
    .filter(license => !allowedLicenses.has(license))
    .filter(license => licenses[license].length > 0))

  if (invalidLicenses.size > 0) {
    result = {
      ...result,
      invalidLicenses,
      success: false
    }
  }

  return result
}
