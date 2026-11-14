import { readFile } from 'node:fs/promises';
import openapiTS, { astToString, COMMENT_HEADER } from 'openapi-typescript';
const ast = await openapiTS(new URL('../../../docs/admin-openapi.json', import.meta.url));
const expected = COMMENT_HEADER + astToString(ast);
const actual = await readFile(new URL('../src/api/generated.ts', import.meta.url), 'utf8');
if (actual.replaceAll('\r\n', '\n') !== expected.replaceAll('\r\n', '\n')) {
  throw new Error('Frontend types have drifted from OpenAPI. Run npm run api:generate.');
}
console.log('Frontend types match the backend OpenAPI contract.');
