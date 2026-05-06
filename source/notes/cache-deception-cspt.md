---
layout: note
title: "快取欺騙到帳號接管"
date: 2025-08-19 19:43:28
---
今天看到有人把一個簡單但實用的小技巧寫成了文章分享，快速幾句話來簡單聊聊

原文是 Jorge Cerezo Dacosta 寫的 [Cache Deception](https://zere.es/posts/cache-deception-cspt-account-takeover/) + CSPT: Turning Non Impactful Findings into Account Takeover

有些網站的 CDN 快取策略是針對某個 suffix，如 *.css 或 *.js 全部都開啟快取。

雖然看起來沒什麼問題，但如果你的 header 沒配好就很有可能出事，例如說沒有把 token 放到 cache key 裡面或是忽略，導致帶著 token 的 response 會快取住以後，下一個沒帶 token 的請求也會拿到這個 response。

舉個例子， 一般正常請求可能是 GET /api/me，有些後端只看 prefix，GET /api/me.css 也會 work，此時這個 response 就被快取住了（這叫做 Cache Deception）。

於是下一個人 GET /api/me.css，就拿到上一個人的 response，資料就外洩了。

但問題是，api/me.css 這個不正常的 URL 不會有人訪問，就算你直接把這 URL 貼給其他人，其他人點開時如果網站不是用 cookie 來做 auth，而是放在 Authorization header 之類的，那也不會帶上，根本沒用。

因此，需要搭配另一個稱作 CSPT（Client side path traversal）的小技巧，這個漏洞歸功於偷懶的工程師們。

例如，有個頁面可能會從 query string 拿 id 然後發送請求，如：fetch(`/api/bookings/${query.id}`, { headers: {...} })，此時我們如果傳一個 ?id=../me.css，就可以操控送出的 URL，成功讓使用者造訪 /api/me.css，所以被稱為前端的 path traversal。

這個小漏洞超常超常看到，但因為需要結合其他漏洞一起攻擊，所以會注意的人不多，會修的人也不多（工程師：這不能攻擊啊，幹嘛修）。

總之呢，結合起來就是：
1. 把會觸發 CSPT 的 URL 如 example/pages/user?id=../me.css 丟給受害者
2. 受害者點開，發送請求到 /api/me.css，被 CDN 快取住
3. 攻擊者發送請求到 /api/me.css，得到受害者的資料

話說，如果網站是用 cookie 做身份驗證，那 CSPT 就不用了，可以直接攻擊，如 [ChatGPT](https://nokline.github.io/bugbounty/2024/02/04/ChatGPT-ATO.html) 去年年初的一個漏洞就是這樣，CDN 會快取所有 /share/* 的 response，因此只要讓受害者訪問一個 URL：/share/%2F..%2Fapi/auth/session?cachebuster=123

這個 response 在 CDN 就會被快取起來，但對 server 來說會回傳 /api/auth/session 的 response，因此直接拿到其他人的 token，是個價值 6500 美元的漏洞。
