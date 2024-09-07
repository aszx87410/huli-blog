const path = require('path')

const config = {
  basePath: path.join(__dirname, '../../'),
  sourceFolder: './source/_posts',
  translateTargetFolder: './source/_posts/en',
  debug: false,
  apiKey: process.env.OPENAI_API_KEY,
  promptFile: path.resolve(__dirname, "prompt.md"),
  model: 'gpt-4o-mini',
  temperature: 0.1,
  fragmentSize: 2048,
  apiCallInterval: 5,
}

module.exports = config