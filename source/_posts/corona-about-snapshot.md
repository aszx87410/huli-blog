---
title: '[Corona] snapshot簡介'
date: 2014-03-20 16:08
catalog: true
header-img: "/img/header_img/article-bg.png"
tags: [corona]
---
snapshot是Graphics 2.0開始提供的一個新東西
使用起來跟group很像，但卻有著一點差異
snapshot可以幹嘛呢？可以想成就是一張「圖片」的group
先直接看示意圖跟code吧! 
<!-- more -->

``` lua
function scene:createScene( event )
    local group = self.view    

    local rect = display.newRoundedRect( 0,0, 200, 200, 10 )
    local rect2 = display.newRect(0,0,50,50)
    rect2:setFillColor( 1,0,0 )
    local snapshot = display.newSnapshot(200,200)
    snapshot.x = 300
    snapshot.y = 500
    snapshot.group:insert(rect)
    snapshot.group:insert(rect2)
    group:insert(snapshot)
end
```

![](https://www.dropbox.com/s/6591kh8kk0mb6ue/%E8%9E%A2%E5%B9%95%E5%BF%AB%E7%85%A7%202014-03-20%20%E4%B8%8B%E5%8D%884.10.32.png?dl=1)

在使用以上這段code的時候，console會跳出：
> WARNING: display.newSnapshot() is a premium graphics feature that requires a Pro (or higher) subscription. To view your project on a device, you must upgrade your subscription.

就是說在模擬器上可以跑，但是如果要發佈到手機的話，需要Pro以上的帳號才能
所以如果只是個Starter或是Basic就只能在模擬器上用而已

好，現在回到我們剛剛的那張示意圖
這樣子用group就可以達成，為什麼要用snapshot?
我一開始會找到snapshot這個東西是因為想要體驗看看2.5D的威力
可以參考這篇：Tutorial: 2.5D Perspective in Graphics 2.0
http://coronalabs.com/blog/2013/10/31/tutorial-2-5d-perspective-in-graphics-2-0/

我用snapshot的原因是因為可以使用snapshot.path這個屬性
至於如果要詳細看group跟snapshot的不同
這邊：Snapshot Programming Guide
http://docs.coronalabs.com/guide/graphics/snapshot.html

那path可以做什麼呢？
可以對圖片的四個角進行操作，進而達成2.5D的效果
2.5D/3D: Perspective, depth, and all that.
http://docs.coronalabs.com/guide/graphics/3D.html

這篇文章裡面就有附上一個翻頁效果的影片，那個特效多棒阿！！！
雖然要直接對矩形做一樣的事情也可以，但是如果你要對兩個以上的物件做這種事
就要加入到snapshot了

``` lua
function scene:createScene( event )
    local group = self.view    

    local rect = display.newRoundedRect( 0,0, 200, 200, 10 )
    local rect2 = display.newRect(0,0,50,50)
    rect2:setFillColor( 1,0,0 )
    local snapshot = display.newSnapshot(200,200)
    snapshot.x = 300
    snapshot.y = 500
    snapshot.group:insert(rect)
    snapshot.group:insert(rect2)
    transition.to(snapshot.path, { x1=100, x3=-100, y3=-10, 
                           x2=100, x4=-100, y4=10,
                           time=7000})
    group:insert(snapshot)
end
```
![](https://www.dropbox.com/s/gm4qixosipqna6h/%E8%9E%A2%E5%B9%95%E5%BF%AB%E7%85%A7%202014-03-20%20%E4%B8%8B%E5%8D%884.17.11.png?dl=1)

很酷吧！上面這段code可以讓那張圖轉半圈
再修改一下就可以讓他轉一圈之類的
除了轉圈當然還有很多其他的操作也可以
總而言之，如果你想對一群物件做這種操作的話，就一定要用snapshot
（例如說想把文字也轉一圈）
再附上一篇官方資料：
Tutorial: Snapshots in Graphics 2.0
http://coronalabs.com/blog/2013/10/22/tutorial-snapshots-in-graphics-2-0/

還有一點需要注意的是，由於Corona會把snapshot當成一張圖片
所以你沒辦法對snapshot裡面的物件增加事件
例如說上面那段code，我如果對rect2（那個紅色矩形）增加tap事件
那個tap事件永遠都不會被觸發到

Corona員工的回答：
>That's expected behavior. As far as Corona's hit-testing is concerned, snapshots are no different from normal rectangles.
 
>Also, it's important to note that snapshots are *not* groups. They have group properties but they use those groups to control how the snapshot's texture is generated. So those child object are effectively offscreen.

完整文章：[RESOLVED] events not working on objects inside snapshot
http://forums.coronalabs.com/topic/42049-resolved-events-not-working-on-objects-inside-snapshot/

那如果真的很需要有點擊事件怎麼辦呢？
我想到兩個解法：
1.針對snapshot增加點擊事件，判斷click的座標決定他點到了什麼
2.在snapshot之外new一個新物件蓋上去

不知道有沒有更好的解法