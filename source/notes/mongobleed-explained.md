---
layout: note
title: "MongoBleed 漏洞解析"
date: 2026-01-02 18:57:11
---
有讀者私訊想看我寫上周爆的 MongoDB 漏洞 [MongoBleed](https://bigdata.2minutestreaming.com/p/mongobleed-explained-simply)（正式編號為 CVE-2025-14847），之前其實就有關注到只是沒仔細看，看了一下發現這個名字取得不錯。

取 MongoBleed 這名字的人，參考的是 2014 年的 TLS 大漏洞 Heartbleed，這兩個漏洞的成因都滿類似的。Heartbeat 俗稱為心跳，是一個常見的網路機制，通常用於確認跟你連線的對象是不是還活著，常常都是固定每幾秒發一個封包過去，有東西回來就代表對方活著，形象一點可以想成心電圖那樣，每幾秒就一個波峰，就像心跳那樣，每幾秒跳一下。

而 Heartbleed 這漏洞是 TLS 中對於心跳機制的實作有問題，在心跳的封包裡面可以傳 payload 跟 payload 的 length，server 端應該要把 payload 原封不動回傳。

在正常狀況下，假設 payload 是 hello，payload length 是 5，server 就回傳 hello。但如果 payload 不變，payload length 改成 1005 呢？server 就會回傳 hello 外加 1000 個在記憶體裡面的隨機字元！

由於 server 直接相信了 payload length，因此多出來的這些地方都會是 server 記憶體的其他內容，有可能是剛解密的 request，或甚至是 server 使用的 private key 等等，每傳一個封包就洩漏出隨機的字串，資料像是流血那樣一點一點不斷流出，就成了 heartbleed。

這次的 MongoBleed 也很像，是 zlib 的壓縮功能有問題，一樣可以傳 payload 跟 length，而且 length 同樣沒檢查。於是我宣稱自己的 payload 有 1005 個字但實際只有 5 個，後面 1000 個字元就會是 memory 的隨機內容，再搭配 MongoDB 在解析 JSON 時的報錯，就可以從 response 的錯誤訊息中得到 memory 的內容。

雖然每次拿到的內容都是隨機的，但只要一直發請求就會一直拿到新的東西，如同我前面提的，像是出血那樣，一點一點流血，資料也一點一滴流出。

再者，MongoBleed 之所以嚴重，是因為這個功能是在 auth 之前的，根本不用登入就能打。所以只要你的 MongoDB 開放在外網就會被打，就算你帳號密碼強度超強也一樣，只要外網連得到就是被打。

下次有人跟你說：「資料庫直接對外沒差啦，我們有設帳號密碼啊而且強度很強」，你就丟 MongoBleed 這個漏洞到他臉上，讓他看看資料庫 public 的下場。

參考資料：

- <https://www.ox.security/blog/attackers-could-exploit-zlib-to-exfiltrate-data-cve-2025-14847/>
- <https://github.com/joe-desimone/mongobleed/tree/main>
