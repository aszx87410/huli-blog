---
title: Chrome's Built-in Translation and Prompt API
date: 2025-09-27 06:50:00
catalog: true
tags: [Web]
categories: [Web]
photos: /img/chrome-built-in-prompt-api/cover-en.png
---

Recently, a reader shared with me a Chrome extension he created: [JP NEWS Helper](https://github.com/Stevetanus/JPNEWS-helper/tree/main), which can summarize and translate articles from NHK News Easy, helping to learn Japanese.

Since this extension is open source, my first curiosity was: "Which AI service does it use, and how is the key handled?" After looking at the source code, I found out that it actually uses Chrome's built-in Web API, not the HTTP API I had assumed.

It was a bit of a late realization for me to discover that there are built-in Web APIs available, so I decided to write a short article to document it.

<!-- more -->

## Chrome's Built-in AI Related APIs

If you want to watch the official Google video directly, you can refer to this: [The future of Chrome Extensions with Gemini in your browser](https://www.youtube.com/watch?v=8iIvAMZ-XYU). For a text version, you can check this article: [Built-in AI API](https://developer.chrome.com/docs/ai/built-in-apis).

Starting from version 138 (as of writing this article, the latest stable version is 140), Chrome provides three built-in Web APIs:

1. Translator API, for translation
2. Language Detector API, for detecting languages
3. Summarizer API, for summarizing articles

These three APIs require downloading some small models before use, and the overall usage is super simple. Below is an example using the translation feature.

First, you need to check if it's available and whether you need to download:

``` js
const translator = await Translator.create({
  sourceLanguage: 'en',
  targetLanguage: 'zh-TW',
  monitor(m) {
    m.addEventListener('downloadprogress', (e) => {
      console.log(`Downloaded ${e.loaded * 100}%`);
    });
  },
});
```

That monitor is used to track the download progress, and for translation, it can be downloaded quite quickly.

Once downloaded, you can translate with just one line of code:

``` js
await translator.translate('How are you?');
```

That's it, super simple.

However, I tried it out, and the quality of the translation wasn't very good; it still can't compare to using a real large LLM model. But having this feature built directly into the Web API is already a significant improvement.

## Prompt API

In addition to the three mentioned at the beginning, there are also a few other APIs still in testing, such as the prompt API, which allows you to directly input prompts, similar to using ChatGPT and other APIs. Currently, to use it, you need to apply for an origin trial to get a key. I previously wrote about how to apply: [Try New Features Early Through Chrome Origin Trials](https://blog.huli.tw/2022/02/02/en/origin-trials-try-new-feature/).

I created a demo website; feel free to check it out. Since the prompt API model is quite large, it's recommended to download it in a non-mobile network environment, otherwise, the data usage might spike.

Additionally, since this API is still in the testing phase, there may be some issues. At first, I had no problems playing around with it, but later it seemed I hit some bug, and every time I asked the AI, it would cause a system-level panic, causing my entire Mac to crash and restart.

https://aszx87410.github.io/demo/ai/prompt-api.html

The usage of this API is also super simple. The first step is to check availability and download:

``` js
await LanguageModel.create({
  monitor(m) {
    m.addEventListener('downloadprogress', (e) => {
      updateProgress(e.loaded);
      if (e.loaded >= 1) {
        updateStatus('✅ ready', 'available');
      }
    });
  }
});
```

Once downloaded, you can use it:

``` js
const session = await LanguageModel.create();
const response = await session.prompt('What can you do?');
console.log(response)
```

There are more parameters you can adjust, and it can support more complex conversations; the above is just a very basic example.

Although the model isn't large and the capabilities are not as extensive as other large models, having a small model that can run locally in the browser can already offload some tasks that would otherwise require an API key.

Now Chrome is also increasingly proactive in packaging small models directly within, providing more native AI features, and in the future, developers can use these Web APIs to develop products without needing to prepare their own backend.

## What about other browsers?

The Translation API was officially released with Chrome 138, and Google has set related standards. However, Firefox and Safari are still in very early stages.

Firefox is currently [not very satisfied](https://github.com/mozilla/standards-positions/issues/1015) with the API design and has proposed another [version](https://github.com/mozilla/explainers/blob/main/translation.md). Safari also has some privacy and security [considerations](https://github.com/WebKit/standards-positions/issues/339) regarding the current approach, and it seems there hasn't been much progress.

As for other more powerful APIs like the Prompt API, Firefox has given a [negative](https://github.com/mozilla/standards-positions/issues/1213#issuecomment-2950074313) response to the current proposal, while there seems to be no news from Safari [on that front](https://github.com/WebKit/standards-positions/issues/495).

Therefore, the things mentioned in this article are currently only available in Chromium-based browsers like Chrome and Edge. Whether other browsers will catch up in the future remains uncertain.

## Conclusion

The integration of various AI with existing products is imperative, and browsers, being applications that users heavily rely on, are a battleground for competition.

For example, Perplexity has launched a [Comet Browser](https://www.perplexity.ai/comet), and Chrome is increasingly incorporating built-in AI features.

If AI is not misleading me, the current Prompt API in Chrome uses [Gemma](https://ai.google.dev/gemma/docs), while Edge uses [Phi](https://azure.microsoft.com/en-us/products/phi).

As the AI models built into browsers evolve, the capabilities will expand. However, given the current situation, the models that can run locally are definitely very limited, as the available resources are constrained, and their performance is not as good as those large models. But it is worth keeping an eye on the future, as they should continue to evolve.
