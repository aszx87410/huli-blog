---
layout: note
title: "GitLab重設密碼漏洞"
date: 2025-02-26 20:58:31
---
今天看到 [HackerOne](https://hackerone.com/reports/2293343) 公開了一個 2023 年底的 [GitLab](https://gitlab.com/gitlab-org/gitlab/-/commit/48154de65e174b93d70bc561c7a0c8b0815d367f?view=parallel) 漏洞報告，最嚴重的那種，賞金 35000 美金。

查了一下發現是 CVE-2023-7028，只要知道 email 就可以透過漏洞，把重設密碼的信件送到自己信箱，輕輕鬆鬆重設其他人的密碼然後登入（如果沒有 2FA 的話）。

而這個漏洞的細節也很簡單，原本重設密碼的請求裡是這樣寫的：
{
  "email": "victim@gmail. com"
}

你只要把它改成 array：
{
  "email": ["victim@gmail. com", "huli@huli .tw"]
}

GitLab 就會順便送一封重設密碼的信到我信箱，就是這樣 😅

身為開發者，看到這種漏洞的第一反應就是：「後端到底幹了什麼奇耙的事，為什麼陣列也能過」，於是我去找了 patch 來看。

看起來好像是原本拿到 input 中的 email 之後就呼叫一個 find_by_any_email 的方法，去找出背後對應的 user 然後寄信，而這些方法既支援字串也支援陣列，但用的時候是以 input 是字串去考量的，沒想到會有陣列的可能性，因此就出包了。

之後的 patch 把找 email 那段改成了簡單的 Email.confirmed.find_by(email: attributes[:email].to_s)，先轉成字串再去找對應的 user 準沒錯，就不會寄到其他人那裡了。

話說這種型態的混淆一直都是很好的攻擊面，尤其是針對 JavaScript 或 PHP 這種超級彈性的語言，這種原本預期是字串卻變成陣列的攻擊滿常碰到的，但 Ruby 我就不太熟了，至少這次的 GitLab 漏洞原理也類似。

講到這個，我最喜歡看到的其實是背後用 TypeScript 寫的後端，因為很多開發者誤以為用 TypeScript 宣告了某個東西是字串，它就一定是字串，不知道這只在靜態檢查生效，動態才不管你 😆

參考資料：<https://github.com/Vozec/CVE-2023-7028>
