const readline = require('readline');

const sleep = ms => new Promise(r => setTimeout(r, ms))
/**
 * Takes an async function and returns a new function
 * that can only be started once per interval
 */
const limitCallRate = (func, interval) => {
  const queue = []
  let processing = false

  if (interval <= 0) return func

  const processQueue = () => {
    if (queue.length === 0) {
      processing = false
      return
    }
    processing = true
    const item = queue.shift()
    func(...item.args).then(item.resolve, item.reject)
    setTimeout(processQueue, interval * 1000)
  }

  return (...args) => {
    return new Promise((resolve, reject) => {
      queue.push({ args, resolve, reject })
      if (!processing) processQueue()
    })
  }
}

function safeParseJSON(input) {
  try {
    return JSON.parse(input)
  } catch(err) {
    console.log('JSON parse error:', input)
    return null
  }
}

const configureApiCaller = options => {
  const { apiKey, rateLimit = 0, httpsProxy } = options

  const callApi = async (
    text,
    instruction,
    apiOptions,
    onStatus,
    maxRetry = 5
  ) => {
    let {default: fetch} = await import('node-fetch')
    const { model, temperature } = apiOptions

    onStatus({ status: "pending", lastToken: "" })
    const response = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${apiKey}`
      },
      body: JSON.stringify({
        model,
        temperature,
        messages: [
          {
            role: "system",
            content: "You are a translator for Markdown documents."
          },
          { role: "user", content: instruction },
          {
            role: "assistant",
            content:
              "Okay, input the Markdown.\n" +
              "I will only return the translated text."
          },
          { role: "user", content: text }
        ],
        stream: true
      })
    })

    if (response.status >= 400) {
      const resText = await response.text()
      const res = safeParseJSON(resText)
      if ((!res || res.error.message.match(/You can retry/)) && maxRetry > 0) {
        // Sometimes the API returns an error saying 'You can retry'. So we retry.
        onStatus({ status: "retrying", lastToken: `(Retrying ${maxRetry})` })
        await sleep(rateLimit * 1000)
        return await callApi(
          text,
          instruction,
          apiOptions,
          onStatus,
          maxRetry - 1
        )
      }
      onStatus({ status: "error", message: res.error.message })
      return { status: "error", message: res.error.message }
    }

    const stream = response.body
    let resultText = ""
    const reader = readline.createInterface(stream)
    try {
      for await (const line of reader) {
        if (line.trim().length === 0) continue
        if (line.includes("[DONE]")) break
        const res = safeParseJSON(line.split(": ", 2)[1])
        if (res.choices[0]?.finish_reason === "length") {
          onStatus({ status: "error", message: "reduce the length." })
          return { status: "error", message: "reduce the length." }
        }
        const content = res.choices[0].delta.content ?? ""
        if (content.length)
          onStatus({ status: "pending", lastToken: content })
        resultText += content
      }
    } catch (err) {
      onStatus({ status: "error", message: "stream read error" })
      return { status: "error", message: "stream read error" }
    }
    onStatus({ status: "done", translation: resultText })
    return { status: "done", translation: resultText }
    
  }
  return limitCallRate(callApi, rateLimit)
}

module.exports = configureApiCaller
