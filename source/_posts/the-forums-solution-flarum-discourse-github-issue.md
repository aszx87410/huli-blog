---
title: '自架論壇的解決方案：flarum, github issue, nodeBB, discourse'
date: 2017-07-02 09:13
catalog: true
header-img: "/img/header_img/article-bg.png"
tags: [other]
---
最近想幫[ Lidemy 鋰學院](https://www.facebook.com/lidemytw)建一個論壇，方便讓大家在那裡討論問題，於是就研究了一下現成的幾個方案，寫在這裡做個紀錄，順便給以後想建論壇的人參考。

在這邊介紹到的論壇系統基本上都是開源的，可以自己架或是有些會提供 hosting 的服務。

## Flarum

[Flarum](http://flarum.org/)是我認為比較新一點的論壇系統，實際範例可以看：[他們自己的討論區](https://discuss.flarum.org/)，目前還在 Beta 階段，而且沒有提供任何 hosting 服務，必須要自己架起來。

技術棧是：php + mysql + [Mithril.js](https://mithril.js.org/)，一套輕巧的 SAP 框架。

## Github Issues

Github 本來就有為每個 repo 都提供了 issue 這個討論區，但原本的用途是拿來開 issue，討論 issue 用的。之後有人發現不只可以這樣，就拿來寫 Blog，所以要拿來做論壇也是可以的，只是功能沒有其他論壇這麼齊全而已。

採用這個系統當論壇的人很少，比較有名的只看到[ express.js 的討論區](https://github.com/expressjs/discussions/issues)，或是[EasyIME](https://github.com/EasyIME/forum/issues)。

## NodeBB

[nodeBB](https://nodebb.org/) 顧名思義就是一套用 node.js 寫出來的論壇，其他用到的還有 MongoDB、Redis 跟 Socket.IO。

有提供 hosting 的服務，最便宜的方案是 100 usd/month。

[他們自己的討論區](https://community.nodebb.org/)跟[ Notepad++ ](https://notepad-plus-plus.org/community/category/2/general-discussion)都是用這個系統。

## Discourse

最厲害的放壓軸，[Discourse](https://www.discourse.org/) 是一套後端用 Rails，前端用 Ember.js 寫出來的論壇系統，一樣有提供 hosting，最便宜也是 100 usd/month。

像是[freeCodeCamp](https://forum.freecodecamp.org/latest)、[atom](https://discuss.atom.io/)、[xdite 的全棧營](https://forum.qzy.camp/latest)都是用這個系統，而 DigitalOcean 在建機器的時候也可以直接選擇 Discourse 的 image，但最低需求的機器要 20 usd/month。

## 結論

其他老牌的那些論壇系統像是 [phpBB](https://www.phpbb.com/) 或是 [Discuz!](http://www.discuz.net/forum.php)我就不再特別介紹了。

那最後我選了哪套呢？

考量到成本跟維護問題，選了最低成本最容易維護的 Github issues。
