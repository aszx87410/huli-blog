---
layout: note
title: "Messenger高額漏洞"
date: 2025-09-04 07:29:36
---
之前介紹過的 bug 中，最高賞金的大概是兩三萬美金左右，昨天看到一個突破天際的 11 萬美金，靠著一個 bug 從 Meta 那邊拿到了約 350 萬台幣。

一名資安研究員 Dzmitry Lukyanenka 發現 Windows 版本的 Facebook Messenger 在接收檔案時有個 path traversal 的漏洞，直接把檔名跟寫入的位置拼在一起，傳個 %2e%2e%5c（..\ 編碼過的結果），寫入時就能寫到上層的資料夾。

但由於 Windows 上的檔案路徑有長度限制，原本的路徑已經很長了，因此就算有這漏洞，也沒辦法把檔案寫到任意位置，光是寫到 C:\Users\vulna\AppData\Local\ 去，就已經只剩下 12 個字元了。

那這個寫入檔案的漏洞可以怎麼利用呢？

有一個叫做 DLL Hijacking 的技巧，原理是 Windows app 在載入 DLL 時是有順序的，所以如果你拿到寫入檔案的權限，往優先的地方寫入 DLL，就會讓某個 app 先載入你寫入的 DLL，載入後就能執行任意程式碼（前提是該 app 載入時沒有把路徑寫死）。

而這次拿來 PoC 的是一個叫 Viber 的 app，會載入 C:\Users\vulna\AppData\Local\Viber\qwave.dll

因此透過 path traversal 的漏洞，把 DLL 寫入到 ..\..\..\..\Viber\qwave.dll，在 Viber 開啟時就會載入這個 DLL，最後達成 RCE。

攻擊方法很簡單，就是傳一個檔案給目標，然後等目標打開 Viber 就會中招。

回報之後一開始拿到 34500 美金，但作者覺得這金額太少（在 mobile 上打出 RCE 最高賞金是 30 萬，官網有寫），反映之後 Meta 再加碼 75000，總額就是 111750 美金，折合台幣 343 萬。

就算是在看完攻擊原理跟 PoC 影片之後，這賞金也比我預期中的多滿多的。到寫入檔案都還在理解範圍，但是 DLL Hijacking 那裡，我以為 Meta 會給出「這個需要受害者有裝 Viber app 才能成立，攻擊前提比較困難」之類的理由來降低 impact，沒想到最後給了這麼多錢。

不過有這個前例出現，代表未來只要能拿到 Windows 上的任意檔案寫入，就能搭配 DLL Hijacking 回報成 RCE，放大 impact 也放大賞金，對賞金獵人們是個利多。

影片：<https://www.vulnano.com/2025/09/remote-code-execution-though.html>
