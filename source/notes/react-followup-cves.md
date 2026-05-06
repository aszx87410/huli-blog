---
layout: note
title: "React 後續漏洞修補"
date: 2025-12-12 07:33:02
---
React 剛剛又發布兩個跟上週有關的漏洞囉，但這次一個是 DoS 另一個是特定情境下可以洩漏 server function 的 source code，嚴重程度都遠低於之前的 React2Shell，編號如下：

- Denial of Service (High): CVE-2025-55184
- Source Code Exposure (Medium):  CVE-2025-55183

然後 Next.js 也理所當然地受到影響，因此也推了一版 patch。

雖然說沒之前這麼嚴重，但有時間的話還是建議先修一修。話說 React 發布這個漏洞的部落格寫說：「It’s common for critical CVEs to uncover follow‑up vulnerabilities. 」，說這種嚴重的 CVE 公佈之後，可能會有更多類似的漏洞這很正常，拉了 Log4Shell 當作案例來解說。

是這樣沒錯，但好像又不是這樣（？）

我以為像 Meta 這種大公司，收到第一個 report 之後會找 security team 進來整個看一遍，把其他潛在該修的問題都修一修再上 patch，但看起來整個反序列化的機制一樣有問題，才出現這兩個洞。應該是我對這種大公司有什麼誤解，看來也是見一個修一個。

不過往好處想，現在一堆資安研究員都往這邊看了，看了一週後才出現這兩個漏洞，代表應該還算安全 😅

建議最近這一兩週還是密切關注一下 React 的新消息，有可能還會有更多小的漏洞出現。
