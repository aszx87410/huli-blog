const fs = require('fs');
const path = require('path');
const readline = require('readline');
const { translate } = require('./translator.js')
const config = require('./config.js')

const { basePath, sourceFolder, translateTargetFolder, debug} = config

const sleep = ms => new Promise(r => setTimeout(r, ms))

function promptToContinue(prompt) {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });

  return new Promise((resolve, reject) => {
    rl.question(prompt + '([Y]es/[n]o/[e]xit) ', (answer) => {
      rl.close();
      if (answer.toLowerCase() === 'y' || answer === '') {
        resolve(true);
      } else if (answer.toLowerCase() === 'n') {
        resolve(false)
      } else {
        reject(new Error('Abort'));
      }
    });
  });
}

function checkFileExists(filePath) {
  return new Promise((resolve, reject) => {
    fs.access(filePath, fs.constants.F_OK, (err) => {
      if (err) {
        resolve(false);
      } else {
        resolve(true);
      }
    });
  });
}

async function main() {
  const files = await fs.promises.readdir(sourceFolder);

  console.log('Total(appx.):', files.length)
  let count = 0
  for (const file of files) {
    const filePath = path.join(basePath, sourceFolder, file);
    const stats = await fs.promises.stat(filePath);

    if (!stats.isFile() || !filePath.endsWith('.md')) {
      continue
    }

    // check if translation is already there
    const targetPath = path.join(basePath, translateTargetFolder, file)
    if (await checkFileExists(targetPath)) {
      console.log('Translation exists for file:', file)
      continue
    }

    console.log(file);
    if (debug && !await promptToContinue('Do you want to translate this file?')) {
      continue
    }

    // start translate
    let startTime = +new Date()
    await translate({
      filename: file,
      filePath: filePath,
      outputPath: targetPath
    })
    let endTime = +new Date()
    console.log(`Time for the translation: ${endTime - startTime}ms`)
    console.log('Count:', ++count)
    await sleep(10000)
  }
}

main().catch(err => {
  console.error('Fatal error', err)
  throw new Error(err)
});