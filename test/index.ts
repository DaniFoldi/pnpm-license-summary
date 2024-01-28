import { expect, it } from 'vitest'
import { action } from '../src/action'
import type { Package } from '../src/types'


it('succeeds on an empty package', async () => {
  const result = await action('fixtures/empty', new Set(), new Set())
  expect(result.success).toBeTruthy()
  expect(result).matchSnapshot()
})

it('warns on unused ignores', async () => {
  const result = await action('fixtures/empty', new Set(), new Set([{ name: 'foo', version: '1.0.0' }]))
  expect(result.success).toBeTruthy()
  expect(result.unusedIgnores).toHaveLength(1)
  expect(result).matchSnapshot()
})

it('succeeds when all licenses are valid', async () => {
  const licenses = [ 'MIT', '0BSD' ]
  const ignores: Package[] = []
  const result = await action('fixtures/empty', new Set(licenses), new Set(ignores))
  expect(result.success).toBeTruthy()
  expect(result).matchSnapshot()
})

it('succeeds when all packages are ignored', async () => {
  const licenses = [ 'MIT', '0BSD' ]
  const ignores: Package[] = []
  const result = await action('fixtures/empty', new Set(licenses), new Set(ignores))
  expect(result.success).toBeTruthy()
  expect(result).matchSnapshot()
})

it('succeeds when licenses are valid or packages are ignored', async () => {
  const licenses = [ 'MIT', '0BSD' ]
  const ignores: Package[] = []
  const result = await action('fixtures/empty', new Set(licenses), new Set(ignores))
  expect(result.success).toBeTruthy()
  expect(result).matchSnapshot()
})
