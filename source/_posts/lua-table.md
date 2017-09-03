---
title: '[Lua] Table使用手冊'
date: 2014-05-14 11:05
catalog: true
header-img: "/img/header_img/article-bg.png"
tags: [lua]
---
在lua裡面有個很重要的東西叫做table，是個非常好用的東西
有多好用呢？
這篇就來介紹一下一些table的用法

<!-- more -->


第一，它可以當做陣列來用
``` lua
local t = {2,3,5,7,11,13,17,19}

print(t[3]) --5

--印出所有元素
for i = 1,#t do
	print(t[i].." ")
end
```

要注意的是lua的第一個index是1而不像某些程式語言（java、C)是0
而`#table_name`是取得陣列長度的意思

如果你想要一個二維陣列，那也很方便
``` lua
local t = {
	{1,1,1},
  {2,2,2},
  {3,3,3}
}

print(t[2][2]) --2
print(t[3][1]) --3
```

不像C/C++必須先定義好陣列長度，lua的table長度是可以隨時變動的
要加入一個元素你有幾種方法可以用
``` lua
local t = {}
t[1]=2
t[#t+1]=3
table.insert(t,4)
--t = {2,3,4}
```
`table.insert`還可以指定要從table的哪個位置插入
例如說`table.insert(t,1,4)`就會在table的開頭插入4這個元素
原本在index 1的元素則會被推到index 2，往後的元素也都以此類推

雖然你可以把table當做純粹的陣列使用，但是table能做的事情多更多！
例如說，他可以當做C++裡面的map來使用，也就是使用字串當做索引值

``` lua
local t = {
	["a"] = "apple",
  ["b"] = "baby",
  ["c"] = "cool"
}
print(t["a"]) --apple
```

除了可以這樣子用以外，你也可以換一種表示方法
``` lua
local t = {
	a = "apple",
	b = "baby",
	c = "cool"
}

print(t["a"]) --apple
```
除了使用`t["a"]以外`，你還可以用`t.a`來達成同樣的目的
像是
``` lua
local peter = {
	name = "peter",
	height = 180
}
print(peter.height) --180
```

也可以嘗試更複雜的使用
``` lua
local family = {
	sister={
		name="Lisa"	
	},
	father={
		name="nick"	
	},
	mother={
		name="Elsa"
	}
}

print(family.sister.name) --Lisa
print(family["father"]["name"]) -- nick
```

前面有講過如何遍歷一個陣列，而如果要遍歷像是這樣的table也很簡單

``` lua
local family = {
	sister={
		name="Lisa"	
	},
	father={
		name="nick"	
	},
	mother={
		name="Elsa"
	}
}

for key,value in pairs(family) do
	print(key,value.name) 
	--sister	Lisa
	--mother	Elsa
    --father	nick
end
```

key就是table的索引值，而value就是那個索引值裡面的東西
例如說上面的例子，取代的value就會是`{name=..}`這個東西，所以要用`value.name`把名字取出來

而`pairs`是lua提供的一個函式，除了`pairs`以外還有一個很相似的`ipairs`

``` lua
local t = {
	10,20,30
}

for key,value in ipairs(t) do
	print(key,value) 
  -- 1 10
  -- 2 20
  -- 3 30
end
```
`ipairs`跟`pairs`的差異，看幾個例子就知道了
``` lua
local t = {
	a=100,10,20,[5]=30
}

for key,value in ipairs(t) do
	print(key,value) 
	--1 10
	--2 20
end
```
在上面這個範例中，`t[a]=100`,`t[1]=10`,`t[2]=20`,`t[5]=30`
`ipairs`會從index為1開始取，發現有`t[1]`所以繼續執行，發現有`t[2]`所以也繼續
但是當取到`t[3]`時發現沒有這個東西，於是就跳出了
所以可以知道`ipairs`會「順序性」的取出index為「數字」的值
而一旦中間斷掉了就不會再繼續（以上面的例子來說，沒有t[3]跟t[4]）

那`pairs`呢？

``` lua
local t = {
	a=100,10,20,[5]=30
}

for key,value in pairs(t) do
	print(key,value) 
	--1 10
	--2 20
	--a 100
	--5 30
end
```
`pairs`會把table裡面的每一組資料都取出來
這就是`pairs`跟`ipairs`的差異

接著要介紹幾個lua提供的好用的table方法
前面已經有介紹過`table.insert`了
還有相似的`table.remove`
``` lua
local t={1,3,5,7,9}
table.remove(t,3)

for i,v in ipairs(t) do
	print(i,v)
	--1 1
	--2 3
	--3 7
	--4 9
end
```
`table.remove(t,3)`的3代表的是index為3的元素，所以會把index為3的"5"這個元素刪除，後面的則會遞補上來

接下來還有`table.concat`，功能就跟javascript裡面的`join`差不多，就是用某個指定的字串把陣列串接起來

``` lua
local t={1,3,5,7,9}

print(table.concat(t,"!"))
--1!3!5!7!9
```

最後還有很方便的`table.sort`
``` lua
local t = {2,3,1,5,4}
table.sort(t)
print(table.concat( t,",")) 
-- 1,2,3,4 5
```

而你也可以使用`table.sort(t,compare_function)`傳入自己定義的函式，就會照著你的定義去排序
例如說你想要由大排到小
``` lua
local t = {2,3,1,5,4}
local function compare(a,b)
	return a>b
end
table.sort(t,compare)
print(table.concat( t,",")) 
-- 5,4,3,2,1
```
或是你想讓偶數排在前面，如果一樣是偶數的話由小到大排
``` lua
local t = {2,3,1,5,4}
local function compare(a,b)
	if(a%2==b%2) then
		return a<b
	else
		return a%2<b%2
	end
end
table.sort(t,compare)
print(table.concat( t,",")) 
-- 2,4,1,3,5
```

最後以一個實際上會用到table的例子做為這篇文章的總結
在Corona SDK中，我想建立一些按鈕，而我一開始是這樣寫的
```lua
	local start_button = widget.newButton{
	    left = 100,top = 200,id = "start",
	    label = "start",onEvent = handleButtonEvent
	}

	local game_button = widget.newButton{
	    left = 300,top = 400,id = "game",
	    label = "game",onEvent = handleButtonEvent
	}

	local end_button = widget.newButton{
	    left = 500,top = 400,id = "end",
	    label = "end",onEvent = handleButtonEvent
	}

	local pause_button = widget.newButton{
	    left = 600,top = 400,id = "pause",
	    label = "pause",onEvent = handleButtonEvent
	}
```
一共有四個按鈕，但是這樣寫十分冗長，而且如果我要新增/修改都很不方便
於是我就改用table來做這件事
``` lua
	local button_data = {
		{id="start",left=100,top=500,label="start"},
		{id="game",left=300,top=400,label="game"},
		{id="end",left=500,top=400,label="end"},
		{id="pause",left=600,top=500,label="pause"}
	}

	local buttons = {}

	for i=1,#button_data do
		local btn=button_data[i]
		buttons[i] = widget.newButton{
			id=btn.id,label=btn.label,
			left=btn.left,top=btn.top,
			onEvent = handleButtonEvent
		}
	end
```

這樣子不覺得版面簡潔很多嗎？

table真的是個很好用而且很方便的東西。

參考資料：
[Tables Tutorial](http://lua-users.org/wiki/TablesTutorial)
[Programming in Lua - Tables](http://www.lua.org/pil/2.5.html)