---
layout: note
title: "Material Theme下架疑雲"
date: 2025-03-02 17:33:45
---
到底是刻意製作惡意擴充套件、供應鏈攻擊，還是全部烏龍一場？

前幾天在推特上有看到 VSCode 的知名擴充套件 Material [Theme](https://medium.com/extensiontotal/a-wolf-in-dark-mode-the-malicious-vs-code-theme-that-fooled-millions-85ed92b4bd26) 被強迫下架，而且會由 VSCode 主動移除，理由是裡面包含惡意程式碼，這幾天也看到一些新聞或是臉書上有人在分享這件事情。

剛剛花了點時間看了一下原始資料，發現事情並不單純。

目前看起來講述比較完整的新聞是 BleepingComputer 的這一篇：VSCode extensions with 9 million installs pulled over security risks [1]，裡面提到了資安研究員 Amit Assaraf 與 Itay Kruk 向 VSCode 回報這個套件可能含有惡意程式碼，在他們自已發表的文章 A Wolf in Dark Mode: The Malicious VS Code Theme That Fooled [Million](https://www.bleepingcomputer.com/news/security/vscode-extensions-with-9-million-installs-pulled-over-security-risks/)s [2] 中是這麼說的：

> A deep analysis concluded that hiding inside it’s codebase are multiple red flags indicating malicious intent. The malicious code seems to be inside a dependency of the theme, which was compromised. 
> 經過深入分析後發現，其程式碼中隱藏著多個顯示惡意意圖的警訊。惡意程式碼似乎存在於該主題的一個依賴項內，而該依賴項已遭到入侵。

但是文章中並沒有提到具體細節，雖然有說更多資訊公開後會更新文章，但目前還沒更新。

事情的發生是在 2/26，這些套件被強制下架後在 [Hacker News](https://news.ycombinator.com/item?id=43178831) [3] 上引起了相關討論，在微軟官方的 Visual Studio Marketplace [GitHub](https://github.com/microsoft/vsmarketplace/issues/1173) repo [4] 中也有這件事情的討論串，在 HN 上 VSCode 團隊的成員 Isidor 有出來說明狀況：

> A member of the community did a deep security analysis of the extension and found multiple red flags that indicate malicious intent and reported this to us. Our security researchers at [Microsoft](https://github.com/microsoft/vsmarketplace/issues/1168) confirmed this claims and found additional suspicious code.
> 社群中的一名成員對該擴充功能進行了深入的安全分析，發現多個顯示惡意意圖的警訊，並向我們報告。微軟的安全研究人員隨後確認了這些發現，並進一步發現了額外的可疑程式碼。

而 GitHub 的討論串則是有 VS Code Marketplace 的 PM Sean 出來回覆：

> We take the decision to remove seriously and thoroughly verify any reports. To protect developers, we also prioritize speedy removal of positives. We've posted the reason for removal in RemovedPackages, where we plan to add any future removals as well.
> 我們對移除決策持謹慎態度，並會徹底驗證所有舉報。為了保護開發者，我們也優先迅速移除確定存在問題的項目。我們已在 RemovedPackages 中發布了移除原因，並計劃未來將所有移除記錄統一發布在該處。

而在 RemovedPackages 中紀錄的原因是：

> A theming extension with heavily obfuscated code and unreasonable dependencies including a utility for running child processes
> 一個主題擴充功能，其程式碼經過高度混淆，並包含不合理的依賴項，例如用於執行 child process 的 utility。

好，看到這邊，我相信大家應該很好奇這個惡意擴充套件到底幹了什麼。至少身為對資安有興趣的人，我很好奇他到底偷了什麼，那些惡意程式碼又是什麼。

而資安人的報導《資安風險！微軟禁下載量達900萬次的VSCode Material Theme擴充套件》[5] 中，有一段是：

> 技術專家進一步檢查發現，擴充套件中的「release-notes.js」文件包含高度混淆的JavaScript代碼，這在通常追求透明和可讀性的開源項目中是非常罕見且危險的信號。混淆的程式碼中頻繁出現與使用者名稱和密碼相關的引用，這進一步增加了安全疑慮。

這段的來源應該是開頭提過的 BleepingComputer 的報導中所寫的：

> A partial deobfuscation of the code showed numerous references to usernames and passwords
> 對該程式碼進行部分反混淆後，發現其中包含大量與使用者名稱和密碼相關的引用。

所以目前已知的證據是：
1. 擴充套件的某些程式碼經過混淆
2. 用到了不合理的依賴，會去呼叫 child_process
3. 反混淆後發現有提到許多使用者名稱跟密碼

看起來似乎...確實有點可疑？

但仔細想想會發現，可疑的不止上面這些，而是原始程式碼都有了，為什麼給不出一個罪證確鑿的證據說：「你看這段程式碼，就是偷偷讀取你的 SSH key 然後傳到這個 domain 去」。一開始回報的資安人員只說有很多 red flags，而微軟那邊也確認發現了可疑的程式碼，那第一個重點就出現了，到底那一段混淆過的程式碼，是單純的可疑，還是真的有問題？

那如果有問題，背後到底做了哪些惡意的事情？雖然混淆過了比較難解析，但微軟一定是有能力去反混淆的。

但很遺憾的是，目前無論是微軟還是當初的資安研究員，都還沒提出確切的證據。甚至在 GitHub Issues 中有些人把程式碼反混淆之後，說看不出來可疑的地方，而那些「提到許多使用者名稱跟密碼」的部分可能跟 URL parser 的一個 library 有關（URL 上面可以帶帳號密碼，因此 URL parser 需要處理）。

總而言之呢，截止目前為止，沒有一個人拿出證據說：「對，就是這段惡意程式碼有問題，它會偷你東西」。

而套件的作者 equinusocio 也在 2/28 的時候發了一個 Issue [6]，描述了他的視角，說在他看來可疑的地方只有使用了一個太舊的 package 而已，明明就沒有經過證實，怎麼就把我的套件都下架，甚至連帳號都 ban 了。

也在裡面公開了一直被說有問題的檔案 release-notes.ts 混淆前以及混淆後的原始碼，並且指控 VSCode 團隊散播未經證實的假消息：

> As for the VS Code team — and by extension, @microsoftopensource — the entire team, and particularly @isidorn, publicly accused me of criminal activity by spreading false and unverified information. 
> 至於 VS Code 團隊，特別是 @isidorn，公開散播不實且未經證實的資訊，指控我涉及犯罪行為。

當然啦，整個故事還有其他案外案，包括了套件作者以前的其他事蹟（修改 commit 紀錄以及修改開源的 license，準備賣付費版的套件，有一說認為混淆程式碼是因為之後要賣付費版），以及有個技術網紅 t3dotgg fork 了一個號稱乾淨版的 Material Theme 重新上架等等，這些就都先不談了。

在我自己目前看來，儘管程式碼經過混淆確實可疑，但混淆過並不代表一定就是惡意程式碼。要說它是惡意程式碼，你必須要有明確的證據，這種事不能亂指控的，畢竟現在全天下都直接認定 Material Theme 就是惡意軟體了。

總之呢，我認為整件事情還沒蓋棺定論，還需要再讓子彈飛一會兒，目前還不能確認 Material Theme 含有惡意程式碼（因為沒有確切證據）。

故事大概會有兩種發展，看是微軟會先拿出證據一槍斃命，證實它就是個惡意軟體；還是拿不出證據反而變成 🤡，只要有疑慮，在沒有驗證過以前就可以把套件下架，讓無辜的套件背上惡意軟體的污名。

補充文章：<https://www.informationsecurity.com.tw/article/article_detail.aspx?aid=11684>
