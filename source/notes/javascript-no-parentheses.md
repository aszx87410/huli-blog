---
layout: note
title: "不用括號執行函式"
date: 2025-09-18 07:18:23
---
有種討人厭的東西叫 WAF，全名為 Web Application Firewall，給網站用的防火牆。儘管你找到了可以插入 HTML 的地方，但只要符合 WAF 的判定規則就會直接把你擋掉，讓你沒辦法攻擊。

因此呢，想攻擊的話就要試著繞過 WAF，在各種限制下組出不會被偵測到的 payload。

這次介紹的是「不用  也能執行函式的 JavaScript」

在一般開發者的眼中，執行函式一定會用到 ，不用  怎麼執行？但是有了 template string 以後，可以用一種叫做 tagged template string 的方法去執行，像這樣：alert`1`

這個實際的應用其實滿廣的，例如說現在有些 library 的用法會是：sql`select * from users where username=${name}` ，看起來是個漏洞，但其實不是， 因為這不只是單純的字串取代，而是會去執行 sql 這個函式，裡面可以做 escape。

除此之外，還有另一種奇技淫巧，那就是把錯誤訊息當成程式碼來執行。

在網頁上，所有沒被捕捉的同步錯誤都會被 window.onerror 接收到，如 Sentry 背後就有用這個。那只要用 onerror=eval，再搭配把錯誤訊息構造成合法的 JavaScript，一樣可以執行任意程式碼。

例如說這樣：onerror=alert;throw 'hello'; 最後會跳出 Uncaugh hello，那只要改一下把 hello 變成 =alert(1)，錯誤訊息就會是「Uncaugh=alert(1)」，把前面的 Uncaugh 當成 global variable 來用。

接著，因為 '=alert(1)' 是個 JavaScript 的字串了，可以改成 '=alert\u00281\u0029'，把括號換成 unicode，這樣就能在 payload 中把括號藏起來了，達成我們的目的。

以上是簡單的基本概念，更詳細的解說與更進階的 payload 都在[這篇文章](https://blog.huli.tw/2025/09/15/xss-without-semicolon-and-parentheses/)裡了，或許可以稱它為花式 JavaScript 吧（還有很多更花的就是了）。
