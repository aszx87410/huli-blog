---
layout: note
title: "別把密鑰貼上工具"
date: 2025-11-27 08:02:02
---
你各位阿，不要輕易把敏感資料貼在網路上啊
有很多很方便的小工具網站如 json beautifer 或是 json formatter 之類的，可以美化你的 json，這些我自己也偶爾會用

昨天看了資安公司 watchTowr 的一份報告之後才發現，原來這些工具有個分享功能，會產生一個 URL 讓你可以分享你的 json 給別人
但是這個分享功能其實有個 public page 會直接顯示整個網站最近分享過的東西（這功能就是這樣設計的）

因此如果你把 key 貼在上面之後分享出去，就等於直接分享給整個網際網路了

那真的有人會這樣做嗎？有，而且還不少

文章中指出他們在歷史紀錄裡找到不少公司的敏感資料，各種 secret 跟 key 都在裡面😅

話說哪天如果幫你解析 JWT 的網頁被駭了，應該可以蒐集到一大堆的 token 😆

補充文章：<https://labs.watchtowr.com/stop-putting-your-passwords-into-random-websites-yes-seriously-you-are-the-problem/>
