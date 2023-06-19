# 文章翻譯器

翻譯的主要程式碼是從這邊改的：https://github.com/smikitky/markdown-gpt-translator

改的東西包括：

1. 把 TypeScript 換成 JavaScript
2. 拿掉一些多餘的套件，只留 node-fetch（因為原生的 stream 用法不同）
3. 把 retry 機制改的更好一點
4. 結合原本部落格文章的部分
5. 把設定檔機制換掉

## 設定檔

請看 config.js

另外 API key 請放在環境變數 `process.env.OPENAI_API_KEY`

prompt 在 `prompt.md`，可以自行更改。

## 翻譯機制

建議先到 config.js 把 DEBUG 設成 true，就會有互動模式問你要不要翻譯

會先把 sourceFolder 裡面的 .md 檔案列舉出來，然後一個一個問你要不要翻譯

翻譯的時候會先按照長度去切成幾個 fragments，個別翻完再合起來

## 使用方式

1. 改設定檔
2. 設置 API key 環境變數
3. `node index.js`

確認過在 Node.js v20 可以跑，套件只需要安裝 `node-fetch` 即可，其他都是原生的
