---
layout: note
title: "Self-XSS變身術"
date: 2025-06-22 20:29:03
---
Self-XSS，之前在我的書中有提過，通常有兩個定義，一個定義是「讓使用者主動攻擊自己」，例如說你在臉書打開 DevTools console，就會看到上面有個警告，寫著大大的紅字：「住手！」，就是怕有人自己在這邊貼一串 JavaScript 執行，自己攻擊自己。

而另一種定義則是「只能攻擊自己的 XSS」，假設 profile 頁面只有自己能看到，而姓名允許 HTML 所以能拿到 XSS。但因為只有自己能看到，所以沒辦法傳給其他人，只能攻擊自己。

因此在許多 bug bounty program 中，self-XSS 是不算數的，找到也沒用。

而 Slonser 近期發表了一篇 [Make Self](https://blog.slonser.info/posts/make-self-xss-great-again/)-XSS Great Again 的文章，談到幾種把 Self-XSS 變成 XSS 的做法。

Self-XSS 之所以難以造成 impact，是因為「只能攻擊自己」與「我要攻擊別人」是兩件矛盾的事情，就算被害者用你的帳號登入，執行了 XSS，你也沒辦法拿到被害者的資料。而 iframe 的一個屬性 credentialless 解決了這個問題。

加上 credentialless 之後，你可以讓同一個網頁用另外一套 storage，跟原本的隔絕開來。因此，我們可以用兩個 iframe，一個是被害者本來的頁面，另一個是加了 credentialless 的頁面，接著在後面這個執行攻擊的 payload，利用這兩個 iframe 是 same-origin 的特性，偷到被害者的資料。

講白話一點就是原本同一個網站同時間只能登入一個帳號，現在可以登入兩個而且互不干擾了，就帳號多開那樣啦！

而另一個我書中有談過的方法是 CSRF，例如說用 CSRF 把受害者的姓名改成 XSS payload，這樣就成功把 self-XSS 變成 XSS 了，是滿經典的做法。

最後還提到一個我覺得最有趣的新 API：fetchLater，這個 API 可以指定某個請求要在一段時間後發送，所以當你用 self-XSS 之後，可以安排某個請求在 1 天後發送，而 1 天過後受害者已經登入回自己的帳號，當請求發送時就是用自己的身份！

這 API 滿有趣的，值得多花點時間研究，畢竟原本是為了解決 sendBeacon 這種 tracking 的需求而出現的，沒想過還可以拿來做攻擊。
