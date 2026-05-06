---
layout: note
title: "visited歷史洩漏修補"
date: 2025-04-14 19:51:22
---
前幾天看到 Chrome 在新版中把 [:visited](https://github.com/explainers-by-googlers/Partitioning-visited-links-history?tab=readme-ov-file) 的一個小問題修掉了，簡單講一下來龍去脈。

沒點的連結是藍色，點過的是紫色，應該很多人都有這個印象。但其實除了預設的顏色之外，你也可以透過 a:visited 這樣的方式去調整「已經點過的連結」的樣式，無論是改顏色或者是加其他東西都是可以的。

不過這個功能方便歸方便，背後的隱憂是如果我們能偵測出這個顏色變化，就能反過來推導出某個 link 是否被點擊過，就等於是洩漏了使用者的 history。

因此呢，最新的 Chrome 就把這個問題修了，把 :visited 的生效機制改掉，不再是 global 的，而是分區計算。這就像以前我提過的快取分區一樣，都是為了解決這些 XS-Leaks 的問題。

但話又說回來，實務上能利用這些攻擊的情境多不多呢？我是覺得沒有很多啦，因為這個手法比較像是「給一個連結 A，知道使用者是否造訪過 A」，而不是「直接洩漏出你造訪過 A」。

我看過最多的應用情境只有 CTF 而已，已經是個在 CTF 中出現過不少次的手法，但拿到現實生活中利用的話，成功率跟可行性應該都還是偏低的。Chrome 官方也有一篇[介紹這次修補的文章](https://developer.chrome.com/blog/visited-links?hl=en)。
