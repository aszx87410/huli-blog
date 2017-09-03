---
title: '[Android] Pending Intent bug'
date: 2016-03-02 17:39
catalog: true
header-img: "/img/header_img/article-bg.png"
tags: [android]
---
這樣也可以碰到bug...
總之就是在發送 notification 的時候帶一個 pending intent
點擊之後開 acitivty 並帶入 intent
改完 code 重裝發現 intent 怎麼帶不進去，activity 居然不會啟動
結果重開機就好了...

ref:
http://blog.piasy.com/Android-Notification-Pending-Intent-Bug/
https://code.google.com/p/android/issues/detail?id=61850