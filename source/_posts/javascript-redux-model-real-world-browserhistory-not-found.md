---
layout: post
title: '[Javascript] redux範例real world, BrowserHistory找不到'
date: 2015-09-01 09:59
catalog: true
header-img: "/img/header_img/article-bg.png"
tags: [javascript,frontend,redux]
---
最近下載redux的範例想要來看看，結果`real-world`這個範例沒辦法跑
出現`Module not found: Error: Cannot resolve module 'react-router/lib/BrowserHistory'`
看`package.json`裡面是`"react-router": "^1.0.0-beta3"`，看起來滿正常
但是刪掉重裝之後也沒辦法跑

最後我就新開一個資料夾然後`npm install react-router@1.0.0-beta3`
把安裝後的react-router覆蓋到原本的
就解決了這個問題

但我到現在還是不知道為什麼會這樣...
