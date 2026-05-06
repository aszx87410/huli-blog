---
layout: note
title: "CodeRabbit供應鏈漏洞"
date: 2025-10-16 07:22:54
---
來清一下存很久但還沒有寫的舊聞，在幾個月前被資安公司 Kudelski Security 公佈細節的 CodeRabbit 漏洞。

隨著 AI 越來越進步，除了幫你寫 code 以外，現在連 review 都是 AI 幫你做了。例如說 Cursor 有提供 bugbot，GitHub 有提供 copilot，各家都有自己的 Ai reviewer。有一間叫 CodeRabbit 的公司也是專門做這個的，GitHub app 裝上去之後就會有機器人幫你 review 你的 PR。

而這個 CodeRabbit 有個設定檔，可以自訂你要用什麼靜態分析的工具去跑，例如說 ESLint 啦，Pylint 啦等等。因為是靜態分析工具嘛，所以就算跑了 ESLint 通常也只是對程式碼做靜態分析，應該不會特別執行其他操作才對。

但其中一個給 ruby 用的工具 Rubocop 可以設置 extension，指定一個 ruby 檔案來執行。因此透過配置 extension，就能在跑靜態分析工具時執行程式碼（等於是在幫你跑工具的機器上執行任意程式碼），於是他們就塞了一些 code 把 env dump 出來，得到一大堆 key，AI 的，GitHub 的，DB 的，你想到的都有。

由於 GitHub App 的 key 也在裡面，等於是你直接掌控了 CodeRabbit 的 GitHub App，因此所有有安裝他們工具的 GitHub repo，你都可以讀寫，這就是為什麼揭露細節的文章標題為：「How We Exploited CodeRabbit: From a Simple PR to RCE and Write Access on 1M [Repositories](https://kudelskisecurity.com/research/how-we-exploited-coderabbit-from-a-simple-pr-to-rce-and-write-access-on-1m-repositories)」，直接擁有了 100 萬個倉庫的讀寫權限。

這個漏洞在今年一月被回報，過了一週後就修掉了。

我感覺 CodeRabbit 可能打從一開始就沒想到這個攻擊面，不覺得執行靜態分析工具，可以讓人執行任意程式碼，所以不覺得有人可以打進去這個環境。但大家都看到了，一旦被打進去就直接 game over。

其中最需要改善的當然是修正一下 threat model，要先假設攻擊者可以在這個環境執行任意程式碼，就能設計出更安全的框架，跑在一個 sandbox 裡面。

另外，也可以看出為什麼我們總是需要多層防護。

當你心中想的是「這個環境他們進不來啦，沒關係」，就算你 100% 相信這個前提，萬一最差狀況還是發生了（如同這個故事一樣），就等於直接投降，資料都給你。

但若你想的是「雖然我覺得不會被打進來，但如果真的發生了該怎麼防？」，你可能就會把一些敏感資料放在其他地方，雖然不一定能完全防禦，但至少能增加攻擊的難度，並且爭取更多時間讓你發現有人打進來了。
