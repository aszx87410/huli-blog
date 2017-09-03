---
title: '[Corona] event互相干擾'
date: 2014-03-20 15:31
catalog: true
header-img: "/img/header_img/article-bg.png"
tags: [corona]
---
比如我現在有一張背景圖叫做bg
有一個畫出來的矩形叫做rect
當我點擊那個矩形的時候，我想像中的情況是：只有那個矩形的tap事件會發生
但實際上的情況是：bg的tap事件也會被觸發
![](https://www.dropbox.com/s/szrrmopp7tz29fq/%E8%9E%A2%E5%B9%95%E5%BF%AB%E7%85%A7%202014-03-20%20%E4%B8%8B%E5%8D%883.37.19.png?dl=1)

測試code（部分）：
``` lua
function scene:createScene( event )
    local group = self.view    
    local function bg_tap()
        print("bg tap!!")
    end
    local function rect_tap()
        print("rect tap!!")
    end
    local bg = display.newRoundedRect( screenW*0.5, screenW*0.5, 1000, 1000, 10 )
    bg:setFillColor( black )
    bg:addEventListener( "tap", bg_tap )
    group:insert(bg)

    local rect = display.newRoundedRect( screenW*0.5, screenW*0.5, 100, 100, 10 )
    rect:addEventListener( "tap", rect_tap )
    group:insert(rect)
end
```

點我點rect的時候
看到的訊息是：
> 2014-03-20 15:41:11.789 Corona Simulator[2807:507] rect tap!!
2014-03-20 15:41:11.789 Corona Simulator[2807:507] bg tap!!

也就是說兩個事件都會被執行
那該怎麼辦呢？
只要在rect_tap這個事件加上一行`return true`就好

``` lua
--原本的
    local function rect_tap()
        print("rect tap!!")
    end
--修改過後
    local function rect_tap()
        print("rect tap!!")
        return true
    end
```

這樣子就只會執行到第一個事件，而不會一直傳遞下去

參考資料：
Why touch event of bacground through objects above?
http://forums.coronalabs.com/topic/39703-why-touch-event-of-bacground-through-objects-above/

