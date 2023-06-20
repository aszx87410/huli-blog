const fs = require('node:fs/promises')
const path = require('node:path')
const configureApiCaller = require('./api.js')
const {
  replaceCodeBlocks,
  restoreCodeBlocks,
  splitStringAtBlankLines
} = require("./md-utils.js")
const { statusToText } = require('./status.js')
const config = require('./config.js')

const { apiKey, promptFile, model, temperature, fragmentSize, apiCallInterval} = config

const translateMultiple = async (
  callApi,
  fragments,
  instruction,
  apiOptions,
  onStatus
) => {
  const statuses = new Array(fragments.length).fill(0).map(() => ({
    status: "waiting"
  }))
  onStatus({ status: "pending", lastToken: "" })
  const handleNewStatus = index => {
    return status => {
      statuses[index] = status
      onStatus({
        status: "pending",
        lastToken: `[${statuses.map(statusToText).join(", ")}]`
      })
    }
  }
  const results = await Promise.all(
    fragments.map((fragment, index) =>
      translateOne(
        callApi,
        fragment,
        instruction,
        apiOptions,
        handleNewStatus(index)
      )
    )
  )
  const finalResult = results.join("\n\n")
  onStatus({ status: "done", translation: finalResult })
  return finalResult
}

const translateOne = async (
  callApi,
  text,
  instruction,
  apiOptions,
  onStatus
) => {
  onStatus({ status: "waiting" })
  const res = await callApi(text, instruction, apiOptions, onStatus)

  if (
    res.status === "error" &&
    res.message.match(/reduce the length|stream read error/i)
  ) {
    // Looks like the input was too long, so split the text in half and retry
    const splitResult = splitStringAtBlankLines(text, 0)
    if (splitResult === null) return text // perhaps code blocks only
    return await translateMultiple(
      callApi,
      splitResult,
      instruction,
      apiOptions,
      onStatus
    )
  }

  if (res.status === "error") throw new Error(res.message)
  return res.translation
}

const readTextFile = async filePath => {
  try {
    return await fs.readFile(filePath, "utf-8")
  } catch (e) {
    if (e.code === "ENOENT") {
      console.error(`File not found: ${filePath}`)
      process.exit(1)
    } else {
      throw e
    }
  }
}

const translate = async ({
  filename,
  filePath,
  outputPath
}) => {

  const markdown = await readTextFile(filePath)
  const instruction = await readTextFile(promptFile)

  const { output: replacedMd, codeBlocks } = replaceCodeBlocks(markdown)
  const fragments = splitStringAtBlankLines(replacedMd, fragmentSize)

  let status = { status: "pending", lastToken: "" }

  console.log('')
  console.log(`Translating ${filename}...`)
  console.log(`Model: ${model}, Temperature: ${temperature}`)
  console.log(`Fragments: ${fragments.length}`)
  for(let i=0; i<fragments.length; i++) {
    console.log(`${i}. ${fragments[i].slice(0, 30)}...`)
  }
  console.log('\n')

  const printStatus = () => {
    process.stdout.write("\x1b[1A\x1b[2K") // clear previous line
    console.log(statusToText(status))
  }
  printStatus()

  const callApi = configureApiCaller({
    apiKey: apiKey,
    rateLimit: apiCallInterval
  })

  const translatedText = await translateMultiple(
    callApi,
    fragments,
    instruction,
    { model, temperature },
    newStatus => {
      status = newStatus
      printStatus()
    }
  )

  const finalResult = restoreCodeBlocks(translatedText, codeBlocks) + "\n"

  await fs.writeFile(outputPath, finalResult, "utf-8")
  console.log(`\nTranslation done! Saved to ${outputPath}.`)
}

exports.translate = translate
