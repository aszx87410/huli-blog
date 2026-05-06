---
layout: note
title: "從React學底層運作"
date: 2025-11-19 07:41:20
---
從大型開源專案的發展歷程以及原始碼裡面，其實可以學到不少東西。最近把之前去 JSDC 線上前導活動分享的主題：「從 [React](https://blog.huli.tw/2025/11/16/learn-advanced-javascript-from-react/) 中學習 JavaScript 底層運作」寫成了文章，主要在談三件事情：

1. React 早期版本（真的很早了，10 年前 2015 的時候）的 XSS 漏洞，以及如何從這個漏洞的 fix 中學習 Symbol 的使用方式

2. React fiber 是把大任務切成多個非同步小任務，那這個「非同步」又是怎麼被執行的？文章會談到 React 如何從最早的 requestIdleCallback 切到自己做的 requestAnimationFrame + postMessage，再把後者換成 MessageChannel，這中間的考量是什麼，這些的觸發時機點又有什麼不一樣

3. React profiler 碰過的 V8 bug，從這個 bug 學習 V8 底層的運作方式，例如說從規格來看 JavaScript 只有浮點數，但 V8 其實還是分成 small integer(簡稱 smi) 跟其他，才能保證性能是好的。
以及 V8 中物件是怎麼被儲存的，shape 又是什麼，這些又是如何跟 React profiler 有所關聯。

以上大概就是文中會提到的內容，文章了，有興趣的可以看看，一次看 React 原始碼外加學習 JavaScript，一舉兩得。

補充文章：<https://github.com/aszx87410/blog/issues/153>
