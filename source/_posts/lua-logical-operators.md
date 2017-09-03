---
title: '[Lua] 邏輯運算'
date: 2014-05-14 12:41
catalog: true
header-img: "/img/header_img/article-bg.png"
tags: [lua]
---
Lua裡面的and、or運算跟其他語言的不太一樣
以C來說，在經過這種邏輯運算以後，只會有true跟false兩種結果
但是在Lua，回傳值卻跟你拿去做運算的運算元有關

而且要特別注意的是，Lua跟Ruby一樣，除了false跟nil外，其他值都是true
所以0也是true

直接來看看範例
``` lua
print(10 or false) --10
print(0 or 0) --0
print(0 or true) --0
print(true or 0) --true
print(false or 100) --100
print(100 or false) --100
print(20 or 100) --20

print(100 and false) --false
print(false and 100) --false
print(true and 20) --20
print(20 and true) --true
print(0 and true) --true
print(0 and nil) --nil
print(20 and 100) --100
```

有一個很簡單的規則可以看出回傳值會是什麼
邏輯運算有個「短路」的性質，什麼是短路呢？
例如說`ture or false`，由於第一個運算元是true，而運算子是or，所以根本不用看第二個運算元，就可以知道這個指令的結果。因為true跟任何東西做or運算結果都是true
所以`20 or 100`這個指令中，只要看到第一個運算子20就可以決定結果，於是就回傳20
而`false or 100`，第一個運算子是false，所以要看第二個，而第二個是100，所以回傳100
只要把自己當做機器的角度去思考，就可以知道回傳值了

`false and 100`，由於false跟任何東西做and結果都是false，所以不用看第二個運算元就直接回傳false
`20 and 100`，因為第一個運算元是true，所以決定結果的是第二個運算元，於是就回傳第二個運算元100

最後來看看一個經典例子
在某些程式語言裡面會有所謂的三元運算子
`max = (a>b)? a:b`，如果?前面的條件是true就回傳第一個值，否則就回傳第二個

在Lua裡面可以寫成這樣
`max = (a>b) and a or b`
可以來思考一下，假如a>b是true的話，就變成`true and a or b`
因為沒有括弧，所以會先從左邊的運算子開始執行，而`true and a`會回傳a
於是就變成`a or b`，由於a不是false也不是nil，所以就回傳a

假如a>b是fasle，就變成`false and a or b`，而`false and a`是false
就變成`false or b`，所以會回傳b


參考資料：
[Logical Operators](http://www.lua.org/pil/3.3.html)

