---
title: '[Lua] MoonScript筆記 '
date: 2014-06-05 18:02
catalog: true
header-img: "/img/header_img/article-bg.png"
tags: [lua]
---
http://moonscript.org/

http://moonscript.org/compiler/

http://moonscript.org/reference/#function_literals

有點想把它拿到corona上面用用看
只是細節還要再想一下
先note一下一些事情
原本在corona裡面
``` lua
function scene:createScene(event)
end
```

也可以寫成這樣
``` lua
scene.createScene = function(self, event)
end
```

所以在MoonScript裡面
``` lua
scene.createScene = (event) =>
```

