---
layout: note
title: "useEffect造成事故"
date: 2025-09-15 10:42:58
---
[Cloudflare](https://blog.cloudflare.com/deep-dive-into-cloudflares-sept-12-dashboard-and-api-outage/) 前幾天出了個事故， dashboard 跟部分 API 都掛了，事故報告出來之後，兇手之一是寫 React 時一定都碰過的 useEffect 😅

在 React 中你可以監聽一些 state 的變化並執行相對應的動作，但有個常見的錯誤是，如果你在裡面又改了監聽的 state ，就會有類似無窮迴圈的效果，一直不斷重複執行

而這次的兇手之一就是這個，dashboard 的前端沒寫好導致 useEffect 一直狂發請求，自己對自己 DDoS，造成後端負荷過大進而影響服務

剛好掛掉的這個 API 又是負責 auth，於是連帶影響其他原本正常的 API

文章裡面其實沒有寫的太詳細，根據 reddit 的討論，看起來像是有問題的前端先發版，而這個 bug 只會出現在 API 有錯誤並且重試的時候，接著再過幾分鐘有問題的後端也發版了，兩個加在一起就形成這個結果了，過多請求導致服務不可用

而 cloudflare 加資源以後暫時恢復，但修復問題時沒修好，上了一版 patch 後又掛了第二次，只好趕緊 rollback 😅

多看幾次[故障報告](https://blog.cloudflare.com/deep-dive-into-cloudflares-sept-12-dashboard-and-api-outage/)跟討論之後，看起來是現在這樣。稍早之前其實也有 po 但事故原因寫得不太對，有錯的話再來修一下🙇
