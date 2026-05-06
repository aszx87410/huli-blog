---
layout: note
title: "localhost繞過權限"
date: 2025-11-12 07:22:49
---
「（叩叩叩）你好」 『你是誰？』 「我是 localhost」 『請進』

今天早上看到了做檔案共享的系統 [Triofox](https://cloud.google.com/blog/topics/threat-intelligence/triofox-vulnerability-cve-2025-12480/) 的漏洞 CVE-2025-12480 的細節，差不多就是上面這樣 😆

有個 AdminDatabase.aspx 的頁面是拿來設置 DB 用的，有擋權限所以直接訪問會給你一個 access denied，但如果你把 Host header 改成 localhost，就可以直接繞過權限檢查。

設定完 DB 之後下一步是設定 admin account，於是用同樣方法就能繞過檢查，新增一個 admin account，有了 admin account 之後再透過其他功能就能在 server 上執行腳本，拿到 RCE，剩下想幹什麼就幹什麼了。

Google 發的技術細節文章裡面有給一些程式碼，有個叫做 CanRunCriticalPage 的函式，開頭就先檢查 base.Request.Url.Host 是不是 localhost，是的話就回傳 true，這就是漏洞的 root cause。

雖然看起來滿誇張的，但我自己還真的看過類似的系統，當偵測到來源是 localhost 或是內網時直接通過，就不檢查權限了。會有這種設計通常是懶得實作內網的驗證機制，覺得內網很安全，或者是讓工程師方便測試之類的。

但問題往往是這類的檢查很多都沒做好，導致外部可以竄改這些 header，讓外網偽裝成內網，就直接進來了。再者，若是系統本身被找到一個 SSRF 的話也直接沒救。總之，不管怎麼看都是個危險的機制。

Google 的，裡面有更多細節。
