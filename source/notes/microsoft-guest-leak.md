---
layout: note
title: "微軟訪客系統漏洞"
date: 2025-07-28 19:47:37
---
一個 15 歲的小朋友 Faav 在找尋微軟有哪些值得注意的 subdomain 時，發現了一個 guest點microsoft點com，是一個給訪客使用的系統。

但註冊登入之後，裡面一片空白什麼都沒有，於是他看了一下請求，有個 API 的參數是 {"buildingIds":[]}，往裡面放入一個 1 之後，就跑出東西來了，就是某間辦公室的資訊，如經緯度、地址等等。

接著他找到了另一個 /api/v1/host 的 API，可以用 email 透露出姓名、電話以及員工 ID 等等，還有另一個給訪客用的 /api/v1/guest/ 也是，同樣可以用 email 就拿到姓名、電話、拜訪時間等等個資。

在這個 API 中會回傳一個 visitId，經過一番摸索之後發現了 /api/visits/visit/:visitId，可以回傳這整個 visit 的資料，response 裡面有 invite id, group id, batch id 等等，繼續找下去會發現 /api/group/:groupId，可以拿到整個 group 的資料。

從這篇文章往回推，看起來每次預約可能都是一次 visit，然後拜訪的人是一個 group，group 裡面包含邀約人跟被邀約的人之類的，拿到這些 id 之後就可以拿到裡面的資料。

要大規模利用的話，感覺就是去搜集所有 microsoft 員工的 email 丟到上面，應該就可以撈出一大堆資料。

最後他向微軟回報了這個漏洞，拿到 0 塊錢，文中沒有寫詳細原因，只說：「MSRC ignored all my messages and paid me $0」，我猜有可能是 out of scope，不在賞金的 scope 之中？

補充文章：<https://blog.faav.top/break-into-any-microsoft-building>
