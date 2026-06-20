---
layout: note
title: "GitHub RCE 與 AI 逆向"
date: 2026-06-14 22:46:32
---
四月底的時候 GitHub 有爆出一個嚴重的 RCE 漏洞 CVE-2026-3854，只要有 push 權限就可以拿到 RCE，是由資安公司 Wiz 回報的。

總之就是 GitHub 裡面有一個 X-Stat 的 header 會在內部傳遞，是用分號 ; 來分割 key 跟 value，然後在 push 時帶上的 option 會被放在裡面，而這邊的編碼沒做好，導致你可以在 option 傳 abc; test=pwn; 去影響到 X-Stat 最後解析出來的值。

而這個 X-Stat 有幾個有趣的值如 rails_env、custom_hooks_dir、repo_pre_receive_hooks 這些看起來就可以利用的東西，最後只要把這些覆蓋掉，就可以用 GitHub 本來就有的 pre hook 機制去執行任意指令，串成 RCE。

那這 X-Stat 的 header 是怎麼被發現的呢，GitHub 本身可不是個開源軟體。

雖然沒開源，但是 GitHub 有提供你可以部署在自己主機上的企業版，給你一個 VM 跑起來，而這個 VM 裡自然也會有 GitHub server 的 binary，你把這個 binary 逆向就行了。

在 [Wiz 的文章](https://www.wiz.io/blog/github-rce-vulnerability-cve-2026-3854)裡面有特別提到，AI 在這部分幫了很大的忙，他們以前就想做類似的研究但成本太高，現在靠 AI + IDA MCP 加速很多也降低成本，才發現這條路徑。

感覺這種事會越來越常發生，對那些編譯過的 binary，要做白箱的話需要先逆向解開才能挖洞，需要一定成本跟前置知識，像我這種幾乎不會逆向的就玩不了。

但現在有 AI 幫我逆向了，想研究的東西丟給 AI 幫我逆一逆，我也是可以看到 source code 了，就不會受到原本的限制。不過對我這種外行人來說，AI 解不開的 binary 照樣沒輒就是了。

之前解一個手機上 .so 檔，類似 VMProtect 那樣的東西 AI 就沒完全解開，還一直跟我說什麼「這個需要資深工程師花兩週，成本太高」，我只能一直安撫他：「你可以的，你很厲害，加油」，但解了兩三天燒了一堆 token 沒解開我就先放棄了。也不是完全沒有進度，有在推進了但沒完全還原。
