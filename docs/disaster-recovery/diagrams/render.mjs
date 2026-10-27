// Documentation-only renderer. Run from an isolated approved tooling directory;
// no production endpoints or application dependencies are involved.
import { instance } from '@viz-js/viz';
import { parseArgs } from 'node:util';
import fs from 'node:fs';
import path from 'node:path';

const { values } = parseArgs({ options: {
  input: { type: 'string' }, output: { type: 'string' },
} });
if (!values.input || !values.output) {
  throw new Error('Usage: node render.mjs --input <diagram-source-dir> --output <new-output-dir>');
}
const input = fs.realpathSync(values.input);
const output = path.resolve(values.output);
if (fs.existsSync(output)) throw new Error('Output must be a NEW directory; source assets are never overwritten.');
if (output === input || output.startsWith(input + path.sep)) throw new Error('Output must be outside diagram sources.');
const catalog = JSON.parse(fs.readFileSync(path.join(input, 'catalog.json'), 'utf8'));
const viz = await instance();
const escape = text => text.replaceAll('&', '&amp;').replaceAll('<', '&lt;')
  .replaceAll('>', '&gt;').replaceAll('"', '&quot;');
fs.mkdirSync(output, { recursive: true });
for (const item of catalog) {
  if (!/^[0-9]{2}-[a-z0-9-]+$/.test(item.name)) throw new Error('Unexpected diagram filename');
  const dot = fs.readFileSync(path.join(input, item.name + '.dot'), 'utf8');
  const rendered = viz.render(dot, { engine: 'dot', format: 'svg' });
  if (rendered.status !== 'success') throw new Error(JSON.stringify(rendered.errors));
  let svg = rendered.output.replace(/<\?xml[\s\S]*?\?>\s*/, '')
    .replace(/<!DOCTYPE[\s\S]*?>\s*/, '');
  svg = svg.replace(/<svg\b/, '<svg role="img" aria-labelledby="diagram-title diagram-description"');
  svg = svg.replace(/(<svg[\s\S]*?>)/, `$1\n<title id="diagram-title">${escape(item.title)}</title>`
    + `<desc id="diagram-description">${escape(item.description)}</desc>`);
  fs.writeFileSync(path.join(output, item.name + '.svg'), svg);
  console.log(`${item.name}: ${item.nodes} nodes / ${item.edges} edges rendered`);
}
