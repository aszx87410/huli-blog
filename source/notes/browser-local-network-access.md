---
layout: note
title: "瀏覽器防護本機請求"
date: 2025-06-16 19:40:28
---
昨天聊到了 Windsurf Editor 的漏洞，一句話解釋就是 Windsurf 在你 local 起的 server 有問題，收到請求就能打出 RCE（Remote Code Execution，遠端程式碼執行）。

其實仔細想想，要打到 local server 不是件容易的事情，大多數人會覺得你要先跟被害者在同個內網才能攻擊，否則是沒辦法直接連到他的機器的。

但我上一篇也提到了，透過瀏覽器可以讓這件事變得非常容易，因為瀏覽器就是把網頁在你電腦打開，所以當我在網頁上去 fetch localhost 的時候，這個 localhost 是指你的電腦，也就是誰打開網頁，就是誰的電腦。

透過瀏覽器，讓我們對 local 發送請求變得非常容易，而瀏覽器當然也注意到了這點。

早在 2014 年就有人提出瀏覽器應該要阻擋從 public 到 private 的請求，例如說我一個 huli .tw 的網頁，不應該讓我發請求到 localhost，這就是阻擋 public 到 private。

因此後來 Google 就提了個 Private Network Access 的 spec，規定如果從 public 要發請求到 private network，那必須要有一個新的 CORS header：Access-Control-Request-Private-Network: true

若是 private network 沒有這個 header，瀏覽器就不讓它存取。

我大概三四年前注意到這東西的，但今天再回去看了一下，發現好像不推了，改推另一種更簡單的形式「當網頁需要發請求給 local network 時，跳出請求授權按鈕要你同意」，把是否開放的權力交還給使用者。

然後在設計時也有考慮到昨天講的 DNS rebinding，每次只要新建 connection 就要重新檢查，就不能像昨天那樣繞過了。

所以，在不久的將來，當瀏覽器跳出視窗問你要不要授權某個網站訪問 localhost 的時候，或許你會想起這篇文章，然後按下 No。

補充文章：

- <https://issues.chromium.org/issues/40083783>
- <https://issues.chromium.org/issues/40079641>
- <https://chromestatus.com/feature/5152728072060928>
