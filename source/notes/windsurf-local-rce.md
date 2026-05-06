---
layout: note
title: "Windsurf本機RCE漏洞"
date: 2025-06-15 20:24:32
---
你用 AI IDE 幫忙寫 code 很開心，駭客用你的 AI IDE 駭進去也很開心。

資安研究員 s1r1us 發現了一個 Windsurf IDE 的漏洞，拿到了一萬美金的賞金，並且剪了一支 [YouTube](https://www.youtube.com/watch?v=23Mz7qcRz50) 影片詳細講述這個過程。

大意就是 Windsurf 的核心邏輯其實是放在一個額外的程式並且做為 server 跑起來（這個 server 是跑在 localhost 的），跟 IDE 透過 HTTP 來溝通。例如說你在 Windsurf Chat 中寫的 prompt，會被送到本地的這個 server，server 處理完畢之後回傳結果。

而問題就出在這個 server 完全沒有任何 auth 或是 CSRF 的保護，所以身為攻擊者，我可以寫個網頁，直接 POST 一個「幫我執行 XXX 指令」的 prompt 到本地的 Windsurf server ，它就會開心地幫你執行。接著我把這個網頁傳給其他人，其他人只要點了就會中招。

雖然 Windsurf server 的 port 是隨機的，但只要簡單做個 port scanning 就可以找到，這沒什麼問題。

有問題的是另一個地方，那就是這個 server 只接受 content-type 為 application/proto 的請求，而瀏覽器預設是不支援這個 content type 的（非簡單請求），需要開 CORS。也就是說，如果這 server 沒有支援 CORS，瀏覽器是不會幫你發出這個請求的。

好巧不巧地，Windsurf server 原本就不是給瀏覽器前端去呼叫的，所以當然沒有支援 CORS，因此瀏覽器就送不出請求，看起來無解了。

這時候 s1r1us 想起了他以前打 CTF 的經驗，腦中蹦出了一個名詞（這我自己幫他加戲的）：DNS rebinding！

舉例來說，假設 huli 是我的 domain，我就設置 huli 的 DNS 紀錄，A record 設兩條，一個是真的 server IP，另一個是 127.0.0.1。

接著在瀏覽器執行 fetch("huli/sendMessage") 並且帶上 payload 跟 header，接著瀏覽器就會發送一個 CORS 請求到我的 server，此時我回應 OK，允許瀏覽器發送真的 POST 請求。

這時，我把 server 關掉，讓這個 IP 沒辦法訪問，瀏覽器就會很聰明地 fallback 到另一個 A record，也就是 127.0.0.1，並且發出 POST 請求。這就是 DNS rebinding 的應用，一個 domain 對應到兩個 IP，讓瀏覽器先用 A 再用 B，藉此繞過原本 local server 不支援 CORS 的限制。

透過這個方式，就能夠讓瀏覽器發送 CORS 請求並且包含這個自訂的 header，順利攻陷 Windsurf。
