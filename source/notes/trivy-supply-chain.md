---
layout: note
title: "Trivy 供應鏈攻擊"
date: 2026-03-25 21:04:07
---
剛好整起事件都有跟到，來聊一下 Trivy 跟最近的大規模供應鏈攻擊事件。

Trivy 是個資安公司 Aqua Security 出的開源掃描工具，最常用的是拿來掃 IaC 的程式碼或是 image 之類的，我自己就用過不少次。

在 2 月底的時候 Trivy 的 GitHub 被攻擊，因為 CI 流程有漏洞，所以發個 PR 就可以偷到 token，這類攻擊通常被叫做 Pwn Request，以前也出現過不少次，而這次的攻擊其實不只有 Trivy 受害，一堆 repo 也被攻擊了。

攻擊的帳號叫做 hackerbot-claw，跟上了前陣子正熱的小龍蝦熱潮，我那時看到消息還想說是不是哪個資安研究員在做研究 😆

過了幾週，到了 3/19 左右，駭客正式發起攻擊，透過 2 月底偷到的 token 直接幫 Trivy 發個含有惡意程式碼的新版本，甚至更狠地還把舊的 tag 全部都 push 一遍。

有些人已經有意識到這類型的供應鏈攻擊風險，在使用一些套件時會寫死版本號如 trivy@1.2.3，這個通常是沒問題的，因為許多 package manager 會保證版本不可篡改，例如說 NPM。

但是 GitHub [Actions](https://docs.github.com/en/actions/reference/security/secure-use) 沒這功能，他的版本只是一個 tag，背後東西是可以換的。所以你在使用 action 時寫死 tag 也沒用，要寫死 commit hash，這我也是今天才知道的，之前沒注意到這個差異。

看到這邊我相信大家都有個疑惑的點，那就是為什麼二月底被駭，理論上已經清理過一輪了，怎麼 3 月底又來一次，而且還是用二月就被偷的 token。

官方聲明是這樣寫的：We rotated secrets and tokens, but the process wasn't atomic and attackers may have been privy to refreshed tokens

具體是什麼狀況沒講，但總之應該就是換的時候沒換好，導致攻擊者也能拿到新的 token。雖然說大家都會犯錯，但是一個資安公司連錯兩次，客戶對他們的信任度可能掉了不少...

總之呢，開頭提過 Trivy 是掃描工具，所以一堆專案都有裝這個，那自然也一堆專案直接被入侵。為了安全裝了資安掃描工具，卻因為裝了這個被入侵，有點諷刺。

而目前最新的受害者是今早才爆出來的 Python 套件 LiteLLM，被入侵的管道就是之前 Trivy 被駭的時候偷到了maintainer 的 token，就利用了這個 token 發布惡意版本。

就是巢狀供應鏈攻擊啦，先打下一個套件，再打下用這個套件的套件，以此類推，越打越多，影響也越來越大。雖然說 LiteLLM 有問題的版本已經被快速下架，但是大多數人（包含我）都猜測攻擊還沒停止，一定會有下一波的到來，請大家多多注意。

防範的方式還是老樣子：

1. 安裝套件的時候永遠固定版本
2. 承上，在某些版本不是 immutable 的情境下要固定 hash（如 GitHub Actions）

如果要安裝的專案是別人的，別人沒有寫死的話，也建議加減裝個 socket 之類的，在下載後似乎會先做一些基本掃描，也算是多少有防到。想更安全的話就是在 VM 或是 docker container 裡面裝，至少能保證影響範圍有限。

話說單個套件被打就已經這麼恐怖了，何況是整個 package manager 都被打下來。之前在 DEVCORE CONFERENCE 2026 聽到 splitline 的議程，就是在講直接去把整個 package manager 打下來，而且成功了不少，涵蓋一堆程式語言。簡報要四月底左右才會公開，到時公開了再來分享一波。

參考資料：<https://snyk.io/articles/poisoned-security-scanner-backdooring-litellm/>
