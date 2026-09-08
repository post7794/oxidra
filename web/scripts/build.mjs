import { mkdir, copyFile } from 'node:fs/promises';
import { resolve, dirname } from 'node:path';
import { pathToFileURL } from 'node:url';
import { webRoot, publicFiles, referenceFiles } from '../server.mjs';

export async function buildSite() {
  const output = resolve(webRoot, 'dist');
  const files = [
    ...publicFiles.map(file => ({ source: resolve(webRoot, file), name: file })),
    ...referenceFiles.map(file => ({ source: resolve(webRoot, '..', file), name: `reference/${file}` })),
  ];
  for (const file of files) {
    const destination = resolve(output, file.name);
    await mkdir(dirname(destination), { recursive: true });
    await copyFile(file.source, destination);
  }
  return { output, files: files.map(file => file.name) };
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  const result = await buildSite();
  console.log(`Built ${result.files.length} static files → ${result.output}`);
  console.log('Deploy dist/ to a static host. All asset paths are relative; subdirectory hosting is supported.');
}
