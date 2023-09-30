# pnpm-license-summary action

> Generate a summary of licenses for a pnpm project

## Usage

```yaml
- uses: pnpm/action-license-summary@v1
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
