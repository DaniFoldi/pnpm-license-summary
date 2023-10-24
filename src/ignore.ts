export function matchesIgnore(packageVersion: string, ignoredVersion: string): boolean {
  if (ignoredVersion === '*') return true
  if (ignoredVersion === packageVersion) return true
  if (ignoredVersion.endsWith('*')) {
    const prefix = ignoredVersion.slice(0, -1)
    return packageVersion.startsWith(prefix)
  }
  return false
}
