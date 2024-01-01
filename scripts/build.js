import { build, formatMessages } from 'esbuild'


const { errors, warnings } = await build({
  entryPoints: [ 'src/index.ts' ],
  bundle: true,
  outfile: 'dist/index.js',
  format: 'esm',
  target: 'esnext',
  platform: 'node',
  banner: {
    js: `
        import { fileURLToPath } from 'url';
        import { createRequire as topLevelCreateRequire } from 'module';
        import { dirname as pathDirname } from 'path';
        const require = topLevelCreateRequire(import.meta.url);
        const __filename = fileURLToPath(import.meta.url);
        const __dirname = pathDirname(__filename);
        `.trimStart().replaceAll(/\n\s+/g, '\n')
  },
  metafile: true
})

console.log(await formatMessages([ ...errors, ...warnings ], { color: true, kind: 'error' }))
