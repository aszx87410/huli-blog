---
title: '[Lua] 語法筆記'
date: 2014-04-24 14:31
catalog: true
header-img: "/img/header_img/article-bg.png"
tags: [lua]
---
先note一下幾個跟OO有關的連結
[Metatables and Metamethods](http://www.lua.org/pil/13.html)
[Metamethods Tutorial](http://lua-users.org/wiki/MetamethodsTutorial)
[From Zero to OO – ArdentKid’s Guide to Object-Oriented Lua (Corona SDK)](http://www.omidahourai.com/from-zero-to-oo-ardentkids-guide-to-object-oriented-lua-with-corona-sdk)
[Tutorial: Modular Classes in Corona](https://coronalabs.com/blog/2011/09/29/tutorial-modular-classes-in-corona/)

lua中的and跟or不是傳回true or false
而是和傳進去的數字有關
除了nil跟false其他都是true

```lua
a and b -- 如果 a為false，則返回 a，否則返回 b 
a or b -- 如果 a為true，則返回 a，否則返回 b
--就是運算到哪個結果就傳回哪個

print(4 and 5) --> 5 
print(nil and 13) --> nil 
print(false and 13) --> false 
print(4 or 5) --> 4 
print(false or 5) --> 5
```
``` lua
if x==nil then
  x = 10
end
```
可以寫成
``` lua
x = x or 10
```

在C裡面的三元運算符號
``` C
max = x>y ? x:y
```
在lua裡面可以這樣寫
``` lua
max = ( (x>y) and x) or y
```

要做swap的動作，只需要
``` lua
x,y = y,x
```
假設你現在有個日期的table
``` lua
days = {"Sunday", "Monday", "Tuesday", "Wednesday", 
 "Thursday", "Friday", "Saturday"}
```
而你想要構造一個反向查詢的表，例如說
``` lua
print(rev_days[1]) --Sunday
```
可以這樣寫
``` lua
local rev_days = {}
for i,v in iparis(days) do
  rev_days[v] = i
end
```

return只能放在end前或else前或until前，所以你有需要的時候可以這樣用
``` lua
function foo () 
 return --<< SYNTAX ERROR 
 -- 'return' is the last statement in the next block 
 do return end -- OK 
 ... -- statements not reached 
end 
```

可以傳入未定數量的參數，會存在arg裡面
``` lua
function print(...) 
 for i,v in ipairs(arg) do 
   printResult = printResult .. tostring(v) .. "\t" 
 end 
 printResult = printResult .. "\n" 
end 
```

當你不想要某個參數時，可以用_代替掉
``` lua
local _, x = string.find(s, p) 
```

要把字串接起來的時候，用concat可以快很多
``` lua
local t = {"a","b","c","d","e"}
s = table.concat(t, "\n") 
print(s)
```

