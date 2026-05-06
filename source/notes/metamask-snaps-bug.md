---
layout: note
title: "Snaps 簽交易漏洞"
date: 2026-03-13 18:52:25
---
在加密貨幣的世界中，MetaMask 大概是最知名的軟體錢包了。而 MetaMask 除了本身提供的那些功能以外，還提供了叫做 Snaps 的 plugin 系統，可以讓開發者在 MetaMask 上面新增功能。

MetaMask 是瀏覽器的 plugin，然後本身又提供了 plugin，一層疊一層，厲害吧。

那有什麼功能會需要往 MetaMask 上面加呢？

舉例來說，有些 blockchain 用的技術沒有被 MetaMask 原生支援，因此這些鏈如果想做錢包的話，要嘛自己再做一個新的擴充套件，要嘛用 Snaps 加到 MetaMask 上。

由於 MetaMask 實在是太多人用了，因此大多數人都選擇後者，做一個 plugin 來幫它加功能，讓它支援更多種不同的 chain，例如說 MetaMask 背後的公司 Consensys，就做了個給 Starknet 用的 Snaps 錢包，讓大家可以在這上面使用 Starknet。

今天有份漏洞[報告](https://hackerone.com/reports/3507241)被揭露，有人發現這個 Starknet Snaps 在發起交易時，支援一個叫做 enableAuthorize 的參數，正常狀況下是 true，MetaMask UI 就會顯示確認視窗。

但如果這個參數傳 false，就不會顯示確認視窗而是直接 sign transaction。換句話說，如果有人不小心在某個網站上連接了 Starknet Snaps，在連接之後攻擊者就可以直接用這個參數繞過確認，在使用者不知道的狀況下發起交易，進而把裡面的錢偷走。

而這個「連接」就像是你在網站上要使用 MetaMask 錢包會跳出的視窗一樣，不是個太敏感的操作（我認為啦），網站要拿錢包地址也需要先連接，否則什麼都拿不到。這個連接跟授權交易完全是兩回事，前者雖然要使用者點擊，但門檻低。

總之呢，假設我做了一個 Dapp 跟大家說來連接 Starknet Snaps 就送獎金，只要連接拿地址登記就好，散佈出去，若是有人裝了這個 Snaps，在點擊連接後就能自動幫他簽交易把錢偷走。

問題來了，這樣的漏洞嚴重程度是多少，賞金又是多少呢？

答案是 medium 以及 350 塊美金 😆

原本 Hackerone 的人員還評估成 low，之後是 Consensys 的人改成 medium，但我怎麼看至少都應該是 high 才對。

官方給的理由是：
1. 使用者必須有裝Starknet Snap
2. 使用者要 connect
3. downstream dApp behavior for financial impact

第一點簡直是聽君一席話如聽一席話的典範，我不就是回報這個程式的漏洞嗎。

第二點我上面講過了，我覺得門檻沒這麼高。

第三點我就沒有看懂了，不知道是不是我對 Starknet 了解有誤？在我的認知中，只要能簽交易就能偷錢了，我自己做個惡意 dApp 不就好了嗎？難道不是？

總之，在我反駁之後官方沒有繼續給回覆，我就請求公開漏洞了，官方還是沒回覆，因此現在一個月後自動公開。他們很多漏洞都沒公開的，我猜他們可能連看都不看根本不 follow 了，也沒有管後續 😂

喔，對啦，那個回報的人就是我，碰巧看到的洞而已。，歡迎一起來看看報告。

然後另一個我覺得滿值得聊的是 CVSS 對於 Web3 的適用程度，我都可以偷錢了，結果拿 CVSS 給我評個不影響 confidentiality 跟 availability，然後 integrity low。

你要這樣講不是不行啦，我只能簽交易確實可能不影響那些，但這個洞怎麼看都不會是 low。這代表在 Web3 相關的情境下，針對傳統漏洞的 CVSS 沒辦法很好的判斷嚴重程度，沒有把資產損失這點考慮進去。

而大多數時候我也不會看到有人硬要把 CVSS 拿去套那些加密貨幣的漏洞，至於 hackerone 為什麼堅持這樣，我也不知道 😑
