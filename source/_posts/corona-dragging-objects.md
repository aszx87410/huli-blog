---
title: '[Corona] 拖曳物體'
date: 2014-05-15 11:06
catalog: true
header-img: "/img/header_img/article-bg.png"
tags: [corona]
---
官方範例：[Tutorial: How to Drag Objects](http://coronalabs.com/blog/2011/09/24/tutorial-how-to-drag-objects/)
但是這個範例有一個小bug，那就是你把東西拖到一半，然後把滑鼠移到其他物體上面放開時會有問題

像是我原本寫了一個翻頁的功能，你可以拖曳頁面，超過一定幅度時放開，就會做翻頁的動作
但是如果只用上面那段code，你在拖曳的時候把滑鼠移到螢幕外面放開，頁面就停在那邊了

解決方法是參考[官方的docs](http://docs.coronalabs.com/api/event/touch/phase.html)
把下面那段sample code跟上面那段合起來

或是[這篇教學（Dragging an Object in Corona SDK）](http://thatssopanda.com/corona-sdk-tutorials/dragging-an-object-in-corona-sdk/)裡面有附完整code

就可以解決這個問題了

