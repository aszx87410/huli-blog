---
layout: note
title: "AI駭客攻防報告"
date: 2025-11-18 20:08:20
---
話說 Anthropic 前幾天發佈了個報告：《[Disrupting](https://www.anthropic.com/news/disrupting-AI-espionage) the first reported AI-orchestrated cyber espionage campaign》，主要在講他們偵測到中國國家級駭客組織發起的網路攻擊，其中大量使用了 AI，並且用 jailbreak 繞過了 Claude 模型的限制來讓他做一些壞壞的事。

攻擊主要分幾個階段，第一階段由人選出 target，第二階段由 AI 負責去做偵查（俗稱的 recon），搜集各種目標的資訊，接著由人去 review 結果之後，再由 AI 去發起攻擊。

從頭到尾真人都只負責監督，剩下的事情都由 AI 來幹，並且整合了各種 MCP tool，讓 AI 可以去做一堆事情甚至開瀏覽器自動化之類的，從偵察到寫 exploit 到橫向移動全部給 AI 自己做。

我自己看到這報告並不太意外就是了，我們現在寫 code 不就是這樣嗎，讓 AI 自己看 Figma 設計稿然後寫 code，寫完自己呼叫 Browser / DevTools MCP 看畫面然後自己改，改完給我 review，review 完自動產生 summary 跟 PR。

既然寫 code 都可以這樣了，攻擊也能如此也不太意外。而且前一兩年就有些公司開始做全 AI pentester 了，CTF 也開始用 AI 輔助甚至全自動，儘管還是有些細節會出錯（如幻覺），但技術面怎麼想都是有可能的。

不過現階段可能僅限於比較簡單且單點的漏洞？就像寫 code 一開始也只能改改單個檔案或是新專案，後來才進化成可以看整個 codebase 並融入現有風格。比起寫 code，感覺 AI security 還在相對偏早的階段，我能想像簡單的可以都交給 AI 打，困難的可能還需要點時間。

也就是說，看到 AI 在寫 code 上的進化，應該不會讓人懷疑他在資安這塊的潛力，只是現階段到底可以全自動化到什麼程度，這個就滿值得討論的。而這篇 Anthropic 的報告基本上是在講說自動化程度已經比很多人想像中的高了。

看了看推特上跟 hackernews 上的討論，有些人看到這報告則是覺得比較偏行銷用途，畢竟報告裡其實沒太多技術細節，就算有，也都是偏工程的細節，例如 AI 駭客的流程或是架構，但絲毫沒有提到任何資安面的東西，像是他們到底實際給什麼任務，產生了什麼結果。

相比之下，[OpenAI](https://cdn.openai.com/threat-intelligence-reports/7d662b68-952f-4dfd-a2f2-fe55b041cc4a/disrupting-malicious-uses-of-ai-october-2025.pdf) 上個月出的報告就《Disrupting malicious uses of AI: an update》就專業多了，裡面就詳細寫到每一個駭客組織都拿他們的模型幹了些什麼，內容滿詳細的。

說不定在不遠的未來，主流就變成機器人對決了，攻擊方寫一個 AI 駭客組成 AI 紅隊 24 小時不間斷攻擊，防守方寫出一個 AI 藍隊不斷防守，碰到可疑流量就自行阻斷，24 小時監督，看誰的機器人比較厲害。

那要怎麼讓機器人變得更厲害呢？當然還是需要真人來教他了，就像目前的 AI coding 一樣，原本就沒料的人用了之後也還是沒料；本來就強的人，用了之後強強聯手，強強強強。

參考資料：<https://cybermap.kaspersky.com/>
