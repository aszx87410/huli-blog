---
layout: note
title: "MCP Inspector本機漏洞"
date: 2025-07-02 20:31:09
---
Anthropic 有開源一個 [MCP Inspector](https://www.oligo.security/blog/critical-rce-vulnerability-in-anthropic-mcp-inspector-cve-2025-49596)，專門拿來 debug MCP servers，具體使用方式是跑個指令以後，就會在 local 跑一個 server，給你一個 web UI 去戳 MCP servers，可以查看有哪些工具可以用，以及實際呼叫看結果。

因為 MCP 這東西就是 Anthropic 推的，所以理所當然一堆在開發 MCP server 的都會用這工具來 debug。但是呢，這工具近期被 Oligo Security 發現一個嚴重的漏洞 CVE-2025-49596，成因與我們之前聊過的 Windsurf Editor 漏洞相當類似。

先來複習一下 Windsurf Editor 之前出了什麼事，簡單講就是一個 localhost 的服務沒有做任何驗證，因此透過瀏覽器可以在網頁上把請求發到這個 server 上，執行任意功能。

而這次 MCP Inspector 出的包也是一樣的，有一個 /sse 的 API 不但沒有任何驗證，還可以直接執行程式碼 😂

所以寫一個網頁發送請求到 localhost 的 /sse?transportType=stdio&command=ls，若是這人有開啟 MCP Inspector，就會執行你發送給他的指令，直接達成最嚴重的 RCE 遠端程式碼執行。

至於修復方式呢，就是多加一個 token 的驗證，以及檢查請求中的 origin header，來防止 DNS rebinding（雖然我看了看那 patch 好像有機會繞 🤔️）。

除了 server 本身需要修復以外，瀏覽器看到類似案例越來越多之後，應該會加緊腳步了，上次有聊過 Chrome 的最新進度是有請求要發送到本地時會跳一個要你同意的視窗，其他瀏覽器倒是還沒看到類似的做法。

總之呢，這個故事告訴我們，不要以為 server 跑在 localhost 就沒人會打你，從瀏覽器打進來是一條輕鬆方便又可行的道路
