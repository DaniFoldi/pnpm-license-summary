# pnpm-license-summary action

> Generate a summary of licenses for a pnpm project

## Usage

```yaml
- uses: DaniFoldi/pnpm-license-summary
  with:
    # The path to the pnpm project (default: .)
    path: .
    # allowed licenses (default: [])
    allowed: |
      MIT
      ISC
    # ignored packages (default: [])
    ignored: |
      foo@1.0.0
```

## License

MIT
