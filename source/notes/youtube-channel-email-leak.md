---
layout: note
title: "YouTube頻道Email外洩"
date: 2025-05-26 20:25:36
---
今天來分享個洩漏 YouTube 頻道 email 得到 2 萬美金賞金的故事，有些細節滿有趣的

YouTube 後台有個 API: /youtubei/v1/creator/get_creator_channels 可以拿到一些頻道營收相關的資訊，其中有個叫做 channelIds 的參數，如果填入了別人的，一樣可以拿到結果，但問題是拿到的都是一些公開資訊，沒什麼用。

一般來講差不多到這邊就是死路了，但作者 [brutecat](https://brutecat.com/articles/youtube-creator-emails) 之前在研究 Google API 時，發現了一條新的路。當你傳送的 request body 的值有錯誤的時候，server 會回傳錯誤資訊，舉例來說，你傳 browserId: 1，server 會跟你說：「browse_id 應該是字串」。

而 Google API 除了支援一般 JSON 以外，也支援 JSON + protobuf 的形式，在這個前提之下 request body 會進行序列化，然後直接用 array 傳進去，如：[1,2,3,4,5,6] 這樣，不會有欄位名稱。

因此只要傳入這樣一個陣列，就會得到一段錯誤訊息跟你說每個欄位叫什麼名稱，型態又是什麼，間接還原出來這整個 API 能夠接收的參數。

因為這個發現，作者找到了一個 includeSuspended 的隱藏參數，加上去之後 response 會多一個 externalContentOwnerId，拿這個 ID 去打別的 API，就能拿到這個 owner 背後所關聯的 email。

故事大概是這樣啦，原文有更多細節，例如說會解釋什麼是 content ID 等等，但核心大概就是「找到原本沒公開的參數」這一點，從這邊突破進去，這點滿有趣的。

，這位 brutecat 之前也找了另一個也是洩漏 email 的拿到一萬美金，太神啦。
