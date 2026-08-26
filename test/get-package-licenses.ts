import { expect, it } from 'vitest'
import { getLicenses, parseLicensesJson } from '../src/get-package-licenses'


it('parses empty response', () => {
  const licenses = parseLicensesJson('')
  expect(Object.entries(licenses)).toHaveLength(0)
})

it('parses non-json response', () => {
  const licenses = parseLicensesJson('No licenses in packages found')
  expect(Object.entries(licenses)).toHaveLength(0)
})

it('parses pnpm 9/10/11 json response', () => {
  const licenses = parseLicensesJson(JSON.stringify({
    MIT: [
      {
        name: 'is-odd',
        versions: [ '3.0.1' ],
        paths: [ '/path/to/is-odd' ],
        license: 'MIT',
        homepage: 'https://example.com/is-odd'
      }
    ]
  }))

  expect(licenses).toStrictEqual({
    MIT: [
      {
        name: 'is-odd',
        version: '3.0.1',
        path: '/path/to/is-odd',
        license: 'MIT',
        homepage: 'https://example.com/is-odd'
      }
    ]
  })
})

it('parses pnpm 9/10/11 json response with multiple versions', () => {
  const licenses = parseLicensesJson(JSON.stringify({
    MIT: [
      {
        name: 'is-number',
        versions: [ '6.0.0', '7.0.0' ],
        paths: [ '/path/to/is-number@6', '/path/to/is-number@7' ],
        license: 'MIT',
        homepage: 'https://example.com/is-number'
      }
    ]
  }))

  expect(licenses).toStrictEqual({
    MIT: [
      {
        name: 'is-number',
        version: '6.0.0',
        path: '/path/to/is-number@6',
        license: 'MIT',
        homepage: 'https://example.com/is-number'
      },
      {
        name: 'is-number',
        version: '7.0.0',
        path: '/path/to/is-number@7',
        license: 'MIT',
        homepage: 'https://example.com/is-number'
      }
    ]
  })
})

it('throws on pnpm error response', () => {
  expect(() => parseLicensesJson(JSON.stringify({
    error: {
      code: 'ERR_PNPM_MISSING_PACKAGE_INDEX_FILE',
      message: 'Failed to find package index file for /@actions/core/1.10.1, please consider running \'pnpm install\''
    }
  }))).toThrow(/Failed to find package index file/)
})

it('returns an empty object on empty', async () => {
  const licenses = await getLicenses('fixtures/empty')
  expect(Object.entries(licenses)).toHaveLength(0)
})
