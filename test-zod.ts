import { CallToolResultSchema } from '@modelcontextprotocol/sdk/types.js';

const result = CallToolResultSchema.parse({
  content: [{ type: 'text', text: 'hello' }],
  structuredContent: { foo: 'bar' }
});
console.log(JSON.stringify(result));
