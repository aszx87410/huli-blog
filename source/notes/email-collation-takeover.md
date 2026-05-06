---
layout: note
title: "Email 比對與帳號接管"
date: 2025-12-22 20:33:13
---
之前在 conf 講過的案例中，有一個滿值得特別拿出來講。

假設有個忘記密碼的功能，使用者輸入了 email，接著你拿去 DB 查，用了 select * from users where email = ?，去查有沒有這個 user，查到了之後直接拿使用者輸入的 email 寄重設密碼信給他，會有什麼問題？

答案是使用者輸入的 email 跟 DB 裡存的 email 不一定是相等的。

舉個最簡單的例子是大小寫，MySQL 有些 collation 是不區分大小寫的，所以 gmail 跟 GMAIL 相等，這倒是問題不大。

但在有些 collation 中，gmail 跟 gmaîĺ 是相等的，也就是說使用者輸入的是 huli@gmaîĺ，DB 查到了 huli@gmail 這個 user，但最後寄信給huli@gmaîĺ，而 gmaîĺ 這個網域是買得到也寄得到的，於是你的系統就把重設密碼信寄給了錯的人，出了一個 account takeover 的漏洞。

最早看到這個是在今年 6 月份 Voorivex 發的文章：Puny-Code, 0-Click Account [Takeover](https://blog.voorivex.team/puny-code-0-click-account-takeover)，不確定更早有沒有人提過。

目前看來 PostgreSQL 基本上沒這問題，但 MySQL 的話你選常用的  utf8mb4_unicode_ci 或是 utf8mb4_general_ci 都有這問題。與其說是問題，不如說是 feature 就是這樣，只是很多人不知道有這 feature 而已 😅

至於修法的話，就是不要相信 user input 就對了，要寄信的時候拿 DB 查出來的 email 寄信，就不會有這問題。在實作上應該大部分都是拿 DB 內的 email 寄信啦，不過拿 user input 寄的其實也不少，畢竟你會覺得他們相等嘛，用哪個都一樣（並沒有）。

補充文章：<https://dev.mysql.com/doc/refman/8.4/en/charset-collation-implementations.html>
