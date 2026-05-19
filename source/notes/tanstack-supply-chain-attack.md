---
layout: note
title: "TanStack 供應鏈攻擊"
date: 2026-05-19 21:41:49
---
上週知名的前端開源套件 TanStack 被供應鏈攻擊，連 OpenAI 的員工也慘遭毒手（？）

稍微看了一下 TanStack 發的 [Postmortem](https://tanstack.com/blog/npm-supply-chain-compromise-postmortem)，剛好這塊我小熟，可以稍微聊一下。

這次打進去的管道一樣是俗稱的 Pwn Request，只要發一個 Pull Request 就能打進去，偷到 npm token 或其他 credentials，就可以拿這個來發版，根本原因就是 CI workflow 有問題。

不過這次的 Pwn Request 算是一個變形版本，先來講最經典的版本，就是你拿來跑 PR 的 workflow 權限沒設好，讓人可以讀 secrets 等等，一跑就直接拿到。

這次攻擊是利用 cache poisoning，在跑這個 workflow 的時候，其實本身偷不到任何 secrets，這段的權限配置是沒問題的，所以我才說是變形版。

有問題的是，當 workflow 跑完之後，會把 pnpm store 存到 cache 中，而這個 cache 是「整個 repo 共用的」，而非 by branch 或是 PR 獨自用一個。

也就是說呢，攻擊者在 PR 裡面加了一段程式碼去污染這個 pnpm store，在 workflow 結束以後，這個被污染過的版本就被存到 cache 裡，而下次發版的 workflow 執行時，就讀到了這個被污染過的 cache，執行裡面的東西，此時發版用的 token 已經在 memory 裡了，就 dump memory 以後就能拿到 token。

算是一種橫向移動，你從低權限的地方寫 cache，而高權限的地方讀 cache 時就會被污染，你就移動到了高權限的環境。

為什麼會說我小熟，是因為之前打滲透測試的時候有打過一個 CI 類產品，那時就有稍微研究了一下 Pwn Request 有哪些方法可以打，就發現了 Adnan Khan 在 2024 年寫過的[這個 cache 污染手法](https://adnanthekhan.com/2024/05/06/the-monsters-in-your-build-cache-github-actions-cache-poisoning/)，那時打的案子也有類似問題，我是直接回報說平台本身應該把這個修掉。

而 GitHub 雖然也在 [GitHub Actions 安全文章](https://securitylab.github.com/resources/github-actions-new-patterns-and-mitigations/)裡提過這類問題，不過看起來不把這個視為要修掉的漏洞，比較像是 by design，然後要使用者自己注意。我最喜歡這類的 bug 了，就是平台不覺得這需要修，責任拋回使用者，但使用者不知道就是不知道，會用錯的還是會用錯，但知道的一眼就能看出問題在哪。
