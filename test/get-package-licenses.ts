import { expect, it } from 'vitest'
import { getLicenses } from '../src/get-package-licenses'


it('returns an empty object on empty', async () => {
  const licenses = await getLicenses('fixtures/empty')
  expect(Object.entries(licenses)).toHaveLength(0)
})

it('returns correct object of packages', async () => {
  const licenses = await getLicenses('.')
  expect(licenses).matchSnapshot()
})
