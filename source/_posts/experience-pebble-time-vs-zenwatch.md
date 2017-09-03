---
title: '[心得] Pebble time vs ZenWatch'
date: 2015-09-23 23:26
catalog: true
header-img: "/img/header_img/article-bg.png"
tags: [hardware]
---
因為我兩隻手錶都有，所以拿來做比較是再正常不過的事情
以下會盡量涵蓋到所有我有察覺到有差異的地方
可能會帶有一點主觀意見，但是我會盡可能說明清楚
以下的Pebble指的都是Pebble time（第二代），因為懶得打time所以就沒有刻意說明
<!-- more -->

#價錢
##Pebble Time：
199USD，折合台幣約6500

##ZenWatch：
4700台幣
（現在已經有降價了，我當初買的時候沒記錯是6000左右）

從價錢上面看來，ZenWatch顯然是大勝的
而且台灣有貨，所以大概一兩天就可以拿到貨了
壞掉或是送修也很容易
這幾點都大勝Pebble

#螢幕
##Pebble Time：
採用彩色電子紙材質，優點是省電
缺點是可以顯示的色彩沒有這麼多

還有一個特性是「遇強則強，遇弱則弱」，這是什麼意思呢？
就是太陽大（光源強）的時候螢幕就很亮，反之亦然
這點跟一般螢幕完全相反，因為一般螢幕在光源很強的時候就會看的很不清楚
但是Pebble反而會超級亮，但缺點就是晚上也會超級暗
你不按任何按鍵的情況下幾乎什麼都看不到，但是ZenWatch就明顯很多

##ZenWatch：
就一般的觸控螢幕
沒什麼特別好講的

#通知
這邊不太好分所以直接混在一起講
ZenWatch的通知就是每一個都是一張card，你可以往右滑消掉，或是往左滑看更多資訊
往上往下就是別的通知
同樣類型的通知會集合在一起
例如說我有2個email，那就會顯示第一封的標題跟一些文字，按下+號之後看之後幾封
（補圖）

所以通知多的時候非常方便
你就一直滑滑滑就好，跟手機差不多

Pebble的話是用按鍵操控
這邊就跟ZenWatch有超級大的差異
第一點差異是Facebook訊息的通知ZenWatch會集中到一個裡面
有個頁面是可以看之前的訊息
而Pebble是每一則都是一個通知
還有如果你把一個通知消掉想看另外一個通知
你必須到「通知頁面」去看
但是ZenWatch把錶面跟通知頁面做在同一個地方（其實也沒有所謂的通知頁面）
你就直接滑就好了
這點我覺得ZenWatch在方便性上面大勝

第二點是速度
假設你收到一封信，通常文字都會有點內容
ZenWatch的話你就滑一滑就看完了
Pebble的話你要按住按鍵....
這點不太方便

第三點是文字支援
ZenWatch可以完整支援各種語言
Pebble的話我裝繁中語言包之後可以支持中文跟日文
但若是韓文、泰文等等的話一樣會變成方塊字
不過這點應該影響不會很大

第四點是歷史紀錄
ZenWatch的通知刪掉就是刪掉了
Pebble的通知會有歷史紀錄保留著，你可以看之前收到哪些通知
這點我覺得Pebble做的不錯

第五點是回覆方式
其實ZenWatch跟Pebble對於通知的選項都差不多
是看Android上的app實作而定
但差別在於ZenWatch的語音回覆功能支援的很好
Pebble的語音回覆目前是支援英文（應該是不支援中文，或是我不會調？）
這點滿可惜的

但是Pebble多了一個快速回覆的選項
你可以先設好你要哪些字串，收到訊息就可以用樣板回覆
這點Pebble做的很不錯！這功能我滿喜歡
例如可以預設「好棒」、「我在忙」、「掰掰」之類的字樣

第六點是處理方式
在ZenWatch上面，假設我在手機上有把某個簡訊加入黑名單
我就不會有通知，簡訊裡面也看不到
但是神奇的是，Pebble居然可以收到通知！
猜測是因為Pebble的優先順序在比較前面，在通知處理掉之前就先送到手錶上了
這點Pebble滿不好的

在（我認為）智慧型手錶最重要的功能上面
顯然這兩隻有著很大很大的差異
要我選的話，我選ZenWatch贏

#連線遺失警告
ZenWatch有選項可以設定
只要跟手機斷線以後，手錶就會震動一下，上面也會顯示斷線
這功能滿重要的，可以防止手錶或是手機遺失

令人驚訝的，Pebble沒有原生支援這個
要你用的錶面有實作這個功能才行！
[Notification on WATCH of lost bluetooth connection](http://forums.getpebble.com/discussion/6094/notification-on-watch-of-lost-bluetooth-connection)
[What is the app that vibrates your watch when it looses connection with the phone? ](https://www.reddit.com/r/pebble/comments/1y5p78/what_is_the_app_that_vibrates_your_watch_when_it/)

結論：ZenWatch樂勝

#續航力
ZenWatch頂多兩天
Pebble號稱七天但實測應該四五天，看你裝的app跟錶面有關

Pebble的賣點之一就是在這，大勝

#App
##Pebble Time：
有自己的store，但無論是錶面或app都是免費的
這邊用開發者的角度多解釋一點
錶面可以用C開發，app可以用javascript寫
我當初就是因為這點才買pebble的！
javascript寫Pebble App，多誘人！

##ZenWatch：
就Android wear，只要開發者在寫android時有寫手錶版本的就會有

#總結
智慧型手錶對我來說，最重要的功能就是通知
ZenWatch跟Pebble在通知的表現上，我覺得ZenWatch是大勝的
原本很期待的電子紙材質，在夜晚的表現也不佳，幾乎什麼都看不到
如果一直把光開著應該可以，只是這樣子耗電量也會增加許多

Pebble大勝的點大概只在續航力而已
總之，我覺得ZenWatch在整體CP值上面是大勝Pebble的
不過要買哪隻還是看個人需求而定
以我的需求（通知最重要）來說，ZenWatch比較適合

