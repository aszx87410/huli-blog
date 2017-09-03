---
title: '[Corona] storyboard to composer'
date: 2014-06-11 15:04
catalog: true
header-img: "/img/header_img/article-bg.png"
tags: [corona] 
---
今天終於把其中一個project的storyboard全面改為composer了
過程滿輕鬆的，可能是因為原本就沒有用到什麼太複雜的功能
基本上遵循幾個步驟就好

1. 把storyboard取代成composer
2. 把原本的事件名稱改一改，createScene變成create，enterScene變成show...
3. 在show跟hide兩個事件裡加上if判斷phase是will還是did

基本上做完這三個步驟就差不多了
不過依然有幾個小問題需要修正
1. `storyboard.printMemUsage`
這個method在composer當中是沒有的
所以我們可以在 `main.lua`裡面加上
``` lua
--新增composer的printMemUsage
local function printMemUsage()
	collectgarbage("collect")
	local memUsage_str = string.format( "MEMORY= %.3f KB", collectgarbage( "count" ) )
	print( memUsage_str .. " | TEXTURE= "..(system.getInfo("textureMemoryUsed")/1048576) )
end
composer.printMemUsage = printMemUsage
```
就可以達成跟之前storyboard差不多的功能了

2. `scene:overlayEnded`
這個在composer裡面也是沒有的
值得注意的點是，在composer裡可以使用`event.parent`存取原本的scene
於是我就用了一個最簡單，不會更動以前結構的寫法
``` lua
function scene:hide( event )
  local group = self.view

  if(event.phase=="will")then
    local params={
        sceneName="Scene.game_pause"
    }
    event.parent:overlayEnded(params)
  end
end
```
就直接去呼叫parent的overlayEnded事件，模仿之前的storyboard
不過我覺得這樣改好像不太好
或許改天有機會再改成composer的寫法


延伸閱讀：
[Tutorial: Understanding the Composer API](http://coronalabs.com/blog/2014/06/03/tutorial-understanding-the-composer-api/)
[Composer Guide](http://docs.coronalabs.com/guide/system/composer/index.html)
[Composer Documentation](http://docs.coronalabs.com/api/library/composer/index.html)
[Introducing the Composer API (blog post)](http://coronalabs.com/blog/2014/01/21/introducing-the-composer-api-plus-tutorial/)