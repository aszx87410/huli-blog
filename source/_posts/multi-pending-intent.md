---
title: '[Android] 多個 Pending Intent 注意事項'
date: 2016-03-02 18:38
catalog: true
header-img: "/img/header_img/article-bg.png"
tags: [android]
---
需求是這樣的：
接收到 GCM 之後，裡面會帶一個 url, 要發一個通知，當點擊這個通知的時候，打開 Proxy.Activity，並且帶入 url

把 intent 建好之後，原本的 code 是長這樣的
```
PendingIntent contentIntent = PendingIntent.getActivity(this, 0, intent, 0);
```
可是卻發生了神奇的現象
那就是如果我收到兩個通知，第一個帶的網址是 google, 第二個帶的是 yahoo
點了第二個網址是 yahoo 的，卻還是跑到 google 去
也就是說之後的 intent 沒效果，帶的 bundle 會長一樣

最後翻到這篇文：[Android开发陷阱：利用PendingIntent传递唯一的Intent](http://zhiweiofli.iteye.com/blog/1972513)
第二個參數是 requestCode，只要確保不同的通知，有不同的 code 就好
```
PendingIntent contentIntent = PendingIntent.getActivity(this, UNIQUE_CODE, intent, 0);
```
