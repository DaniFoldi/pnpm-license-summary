import { spawn } from 'node:child_process'


export async function getPnpmVersion(): Promise<string> {
  const proc = spawn('pnpm', [ '--version' ])

  let stdout = ''
  proc.stdout.on('data', data => stdout += data.toString())

  // eslint-disable-next-line promise/avoid-new
  await new Promise((resolve, reject) => {
    proc.on('close', resolve)
    proc.on('error', reject)
  })

  return stdout.trim()
}
