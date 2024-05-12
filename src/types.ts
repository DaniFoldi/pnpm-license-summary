export type Package = { name: string; version: string  }
export type PackageDetails = Package & { license: string; homepage: string }

export type AllowedLicenses = Set<string>
export type IgnoredPackages = Set<Package>

export type Result = { unusedIgnores: Array<string>; licensesUsed: Record<string, Set<PackageDetails>> }
  & ({ success: true } | { success: false; invalidLicenses: Set<string> })
