---
layout: note
title: "Linux 提權漏洞解析"
date: 2026-04-30 21:21:26
---
今天剛看到 Linux 最新被爆出來的提權漏洞 CVE-2026-31431，又稱作 [Copy Fail](https://xint.io/blog/copy-fail-linux-distributions)，利用方式簡單容易。

用白話文講的話，你原本把重要文件放左邊，白紙放右邊，讀完左邊文件之後，在右邊白紙寫下筆記。

但你有天突然覺得這樣很不方便，比起左右放，還是上下放更好，於是上面放白紙，下面放文件，結果白紙寫著寫著寫滿了，不小心多寫了一些字在重要文件上面，文件的內容就被修改了。就因為這個不小心，重要文件的內容被改動，就成了一個漏洞。

修法很簡單，不要把兩張紙上下放在一起就好，讀就是讀，寫就是寫，要寫就寫白紙上，不讓你寫到重要文件去。

技術細節的話，這個 bug 出在 Linux kernel 的 authencesn 功能，是拿來做加解密的。正常狀況下，你丟給他一段密文跟 key，他就會把解密的結果寫到 buffer 後還給你。

正常來講讀寫是分開的兩塊 buffer，但由於 2017 年的一個改動，讀跟寫的 buffer 指到了同一塊記憶體，然後 authencesn 的實作又被發現了一個 4 bytes 的 overwrite。

所以你先用 splice 拿到 /usr/bin/su 的 page cache reference，當成 input 丟給 authencesn，接著再利用那個 overwrite，就可以蓋掉 su 在 page cache 中的內容，等於是修改 su 的程式碼。

蓋完之後再執行 /usr/bin/su，就順利 root 了。

整個 exploit 的重點在於可以寫到任意的 page cache，所以把你想改的 program 用 splice 拿到 page cache reference 後，就可以丟給 authencesn 用 bug 去覆蓋 page cache。

最後修法是把那個 in-place 的改動拿掉，不讓你寫 page cache。

（我完全不懂 Linux kernel，技術細節是反覆看 writeup 以及與 AI 討論得出來的，細節必有不精確之處，有錯的地方歡迎留言指正，讓我多學習一些 Linux 知識）
