---
title: '[Android] 聊天app的layout'
date: 2015-08-14 12:04
catalog: true
header-img: "/img/header_img/article-bg.png"
tags: [Android]
---
最近在做IM app
對話框那邊一直有個功能搞不定
layout很簡單，就是一個listview是對話記錄，然後下面一個文字輸入框
觀察各大IM，有些動作跟反應幾乎都相同
1. 當listview是在最底下時，按下輸入框，鍵盤跑出來，listview高度變小（action bar還在），捲到最底
2. 當listview不是在最底下時，按下輸入框，鍵盤跑出來，listview高度變小（action bar還在），位置不變

但是我的那個app的行為是
無論listivew在哪裡，按下輸入框鍵盤跑出來時，listview的位置不會變，就是說會蓋到上面的訊息

google一陣子之後發現是因為要設定一個屬性
原本我是自己手動在code裡面寫說，有新訊息進來時，`listview.setSelection(chat_list.size() - 1);`
但是才發現原來這個需求直接用layout屬性設置就好
```
android:stackFromBottom="true"
android:transcriptMode="alwaysScroll"
```
加上這兩行，可以在每次listview有變的時候都捲到最底
所以上面的那兩個case，都會把listview捲到最底，就不符合需求
需求是：當listview不在最底下時，不能捲到最底

這時候只要改成
```
android:transcriptMode="normal"
```
只要這一行就夠了，就是我們想要的功能

ref:
[istview Scroll to the end of the list after updating the list](http://stackoverflow.com/questions/3606530/listview-scroll-to-the-end-of-the-list-after-updating-the-list)
[環信sdk demo](https://github.com/easemob/sdkexamples-android/blob/master/ChatDemoUI/res/layout/activity_chat.xml)
