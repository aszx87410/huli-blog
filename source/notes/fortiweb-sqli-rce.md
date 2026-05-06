---
layout: note
title: "FortiWeb注入漏洞"
date: 2025-07-13 20:23:05
---
知名的 WAF [FortiWeb](https://pwner.gg/blog/2025-07-10-fortiweb-fabric-rce) 前幾天爆出一個 [SQL](https://labs.watchtowr.com/pre-auth-sql-injection-to-rce-fortinet-fortiweb-fabric-connector-cve-2025-25257/) injection 漏洞 CVE-2025-25257，技術細節滿有趣的，一起來看一下。

WAF 的全名是 Web Application Firewall，防火牆有很多種，WAF 是專門給 Web 的防火牆，例如說你在 query string 隨便放個單引號或是 eval 之類的，可能就會被 WAF 擋住，不讓你的請求送到後面。有了 WAF 之後，就算後面的程式有漏洞，也不一定打得進去，可能會先被 WAF 攔住（大多數時候是駭客技高一籌，還是能繞過）。

但也是有原本沒事，結果用了 WAF 反而出事的案例 😓

FortiWeb 有個 /api/fabric/device/status 的 endpoint 會從 Authorization header 裡面拿東西出來，然後呼叫 select id from fabric_user.user_table where token = '%s'，直接用 %s 把字串放進去，一個樸實無華的 SQL injection 就這樣出現了，而且這個 API 原本就是給外部用的，所以不需要任何驗證，誰都可以呼叫。

拿到 SQL injection 之後可以幹嘛呢？試著把 impact 變得更大，看能不能變成 RCE！

一個常用的技巧是，如果權限夠的話，是可以用 SQL 寫檔案的，如 SELECT 'huli' INTO OUTFILE '/tmp/huli.txt'，就可以寫檔案到指定位置。而 FortiWeb 是用 root 在跑 MySQL 的，所以有足夠的權限，但是要把檔案寫到哪裡呢？

在原本的應用中，有個 cgi-bin 的資料夾底下放著一個 ml-draw.py，因為 server 有設置放在這底下的東西都會被執行，所以可以透過發請求的方式把這個 Python 檔案跑起來（GET /cgi-bin/ml-draw.py）。

而 Python 在 import module 時會根據順序尋找 module 在哪裏，例如說會先找當前的資料夾，找不到再跑去找 /usr/lib/python3.10/，然後再找 /usr/lib/python3.10/site-packages/ 之類的。

因此，我們只要把檔案寫到順序在前面的資料夾，就可以覆蓋這個 Python 腳本會引用的模組，裡面放我們自己寫的 Python 檔案，就串成 RCE 了！
（有人可能會問為什麼不直接寫到 cgi-bin 底下，直接跑起來就好，原因是要跑起來的前提是檔案要是 executable，但是寫入檔案後就只是個普通檔案，沒有可執行權限）

還有另一個小細節是 Authorization header 必須在 128 個字元以內，而且不能有空格，所以需要稍微繞一下（用 /**/ 就行了），也因為字元限制需要分多個 query 執行來保存 payload。

像這種 WAF 直接被打穿的案例好像層出不窮，每過一陣子就會看到類似的新聞，某某 WAF 又被找到一個 pre-auth RCE 之類的 😂
