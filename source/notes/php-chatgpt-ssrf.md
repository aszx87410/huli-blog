---
layout: note
title: "另一個ChatGPT漏洞"
date: 2025-04-08 20:54:54
---
「ChatGPT」有漏洞，但不是那個 ChatGPT 😆

剛剛看到有人轉 TWCERT/CC 的一篇文章，標題為「ChatGPT 漏洞遭大規模濫用，美國為主要攻擊目標」，內容寫說：

> 資安業者Veriti的研究員發現一個正被積極利用的伺服器端請求偽造（SSRF）漏洞，編號為CVE-2024-27564（CVSS：6.5）。此漏洞允許攻擊者利用ChatGPT的pictureproxy.php元件（commit ID為f9f4bbc），通過「url」參數發起任意請求，繞過安全控制，控制ChatGPT請求指定資源，從而可能導致敏感資訊洩漏。

我想到之前在講 Material theme 的事件時，也有人回說 ChatGPT 被爆了一個漏洞，但人家根本沒用 PHP，看來就是這個了。

我去找了一下 CVE 紀錄裡面附的參考資料，發現這個漏洞指的是 dirk1983/chatgpt 這個 [GitHub](https://github.com/dirk1983/chatgpt/issues/114) repo，只是簡單用 PHP 做的一個 ChatGPT wrapper，README 裡面寫說：

> 本项目完全开源，是PHP版调用OpenAI的API接口进行问答的Demo（中間省略）本项目定位是个人或朋友之间分享使用，轻量设计，不计划引入数据库等复杂功能。有需要的用户可以自行拿去修改，版权没有，改动不究。

所以呢，就是這個叫做 ChatGPT 的 PHP 專案有一個 SSRF 的漏洞，跟我們平時在用的 ChatGPT 基本上一點關係都沒有 😅

而且會架這種服務放在公網的，應該大多數也都是個人，我想不到有公司會這樣搞 😂

補充文章：<https://www.twcert.org.tw/tw/cp-104-10060-5d64a-1.html>
