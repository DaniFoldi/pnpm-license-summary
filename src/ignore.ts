export function matchesIgnore(target: string, template: string): boolean {
  if (template === '*') return true
  if (template === target) return true
  if (template.endsWith('*')) {
    const prefix = template.slice(0, -1)
    return target.startsWith(prefix)
  }
  return false
}
