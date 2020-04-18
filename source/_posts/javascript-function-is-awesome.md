---
title: 覺得 JavaScript function 很有趣的我是不是很奇怪
catalog: true
date: 2020-04-18 10:56:48
tags: [Front-end,JavaScript]
categories:
  - JavaScript
---

## 前言

如果有先寫過其他 function 不是 first-class 的程式語言，在寫 JavaScript 的時候應該會經歷一些陣痛期，想說到底在做什麼——至少我是這樣的。

我當初發現可以把 function 當作參數到處傳遞的時候，對於比較複雜的 code 就要想很久，而 function 的其他行為也是讓我一頭霧水，例如說 function 居然也是 object，還有 this 到底是什麼鬼東西。

這一篇主要是想分享一些我覺得 function 比較有趣的地方。可是呢，直接開始講一大堆知識太無趣了，我希望能引起大家對這些知識的好奇程度，而想要引起好奇，最好的方法就是提供一個「你也會感興趣的問題」，你就會有動力繼續往下看了。

因此底下就以幾個小問題作為開場，雖然是問題的形式，但答不出來也完全沒有關係，如果你對這些問題的答案有興趣的話再往下看，沒興趣的話出口直走到底左轉。

話說這篇標題本來想取叫：「JavaScript function 知多少」或是「有趣的 JavaScript function」，但這種標題太無趣了，所以才想到這種輕小說式（？）的標題。

<!-- more -->

### 問題一：Named function expression

一般來說在寫 function expression 的時候，都會這樣子寫：

``` js
var fib = function(n) {
  if (n <= 1) return n
  return fib(n-1) + fib(n-2)
}

console.log(fib(6))
```

但其實後面的那個 function 也可以有名字，例如說：

``` js
var fib = function calculateFib(n) {
  if (n <= 1) return n
  return fib(n-1) + fib(n-2)
}

console.log(calculateFib) // ???
console.log(fib(6))
```

問題來了：

1. 那這個 function 到底叫做 fib 還是 calculateFib？
2. 底下那行 `console.log(calculateFib)` 會輸出什麼？
3. 既然前面都已經給它名字了，為什麼後面還要再多一個？

### 問題二：apply 與 call

大家都知道呼叫 function 基本上有三個方法：

1. 直接呼叫
2. call
3. apply

如底下範例所示：

``` js
function add(a, b) {
  console.log(a+b)
}

add(1, 2)
add.call(null, 1, 2)
add.apply(null, [1, 2])
```

問題來了：

1. 為什麼除了一般的呼叫 function 以外，還需要 call 跟 apply？什麼情形下需要用到它們？

### 問題三：建立函式

要建立函式也有幾個方法，基本上就是：

1. Function declaration
2. Function expression
3. Function constructor

如下所示：

``` js
// Function declaration 
function a1(str) {
  console.log(str)
}

// Function expression
var a2 = function(str) {
  console.log(str)
}

// 很少看到的 Function constructor
var a3 = new Function('str', 'console.log(str)')

a1('hi')
a2('hello')
a3('world')
```

大家可以發現在宣告函式的時候，一定都會有 function 這個關鍵字
那有沒有辦法做到不用 function 關鍵字，也能建立函式呢？

這時候可能有人立刻會想到：那不就是 arrow function！對，所以我要多加一個限制，不能使用 arrow function。

大家可以想一下是否還有其他方法。

### 問題四：黑魔法

有一個 function 叫做 log，接收一個物件，然後印出物件的 str 這個屬性：

``` js
function log(obj) {
  console.log(obj.str)
}

log({str: 'hello'})
```

現在在印出之前多呼叫一個函式，請你在那個函式裡面施展魔法，讓輸出從 hello 變成 world：

``` js
function log(obj) {
  doSomeMagic()
  console.log(obj.str) // 要讓這邊輸出的變成 world
}

// 只能改動這個函式裡面的東西
function doSomeMagic() {
  // 在這邊施展魔法
}

log({str: 'hello'})
```

只能改動 `doSomeMagic` 這個函式內部，加上一些程式碼，到底該怎麼做才能改動到另一個函式裡的東西呢？先提醒一下，覆寫 `console.log` 是一種解法，但很遺憾的不是這篇文章想討論的東西。

希望以上這四個問題有引起你的興趣，一二題是實作上真的會碰到的問題，三四題就是純屬好玩，基本上碰不太到。接著我們先不一一解答，而是直接來講一下 function 相關的知識，在講解到相關的段落時會順便一起回答問題。

## Fun fun function

（附註：這個標題其實是一個 [YouTube 頻道](https://www.youtube.com/channel/UCO1cgjhGzsSYb1rsB4bFe4Q)，我自己沒什麼看過但我有些學生很推，所以也推薦給大家）

在 JavaScript 裡面，function 也是一個物件，或是用更專業的口吻來說，function 就是個 `Callable Object`，可以呼叫的物件，內部會實作 `[[Call]]` 這個 method。

既然是物件，你就可以用任何像物件的方式去操作它：

``` js
function add(a, b) {
  return a + b
}

// 正常呼叫
console.log(add(1, 2))

// 當成一般物件
add.age = 18
console.log(add.age) // 18

// 當成陣列
add[0] = 10
add[1] = 20
add[2] = 30
add[3] = 40
add[4] = 50

for(let i=0; i<5; i++) {
  console.log(i, add[i])
}
```

眼尖的朋友們可能會注意到，為什麼陣列那邊是 `i<5` 而不是常見的 `i<add.length`，這是因為 add 是個函式，所以 `add.length` 會是參數的總數也就是 2，而且這個屬性沒辦法被更改，所以才不行直接使用 `add.length`：

``` js
function add(a, b) {
  return a + b
}

// 當成陣列
add[0] = 10
add[1] = 20
add[2] = 30
add[3] = 40
add[4] = 50

add.length = 100
console.log(add.length) // 2
```

直接把 function 拿來當一般物件跟陣列來使用，都是實作上不會發生而且應該盡量避免的情況，比較相似的只有「把 object 當作 array」來用，最知名的範例就是 function 裡面的 `arguments` 這個東西，它其實是一個「很像陣列的物件」，又稱做是偽陣列或是 array-like object。

``` js
function add(a, b) {
  console.log(arguments) // [Arguments] { '0': 1, '1': 2 }
  console.log(arguments.length) // 2

  // 像陣列一樣操作
  for(let i=0; i<arguments.length; i++) {
    console.log(arguments[i])
  }

  // 可是不是陣列
  console.log(Array.isArray(arguments)) // false
  console.log(arguments.map) // undefined
}

add(1, 2)
```

那要怎麼樣讓這個偽裝成陣列的物件變成陣列呢？有幾種方法，例如說呼叫 `Array.from`：

``` js
function add(a, b) {
  let a1 = Array.from(arguments)
  console.log(Array.isArray(a1)) // true
}
```

還有，呼叫 `Array.prototype.slice`：

``` js
function add(a, b) {
  let a2 = Array.prototype.slice.call(arguments)
  console.log(Array.isArray(a2)) // true
}
```

這時就可以回答到前面提的問題了，明明 function 就可以直接呼叫，為什麼需要 apply 跟 call 這兩個方法？其中一個原因就是：`this`，大家可以發現在呼叫 slice 的時候，並不用把陣列傳進去，而是直接呼叫 `[1,2,3].slice()`，這背後跟 prototype 有關，因為 slice 這個方法其實是在 `Array.prototype` 上面：

``` js
console.log([].slice === Array.prototype.slice) // true
```

比如說我們今天要幫 Array 新增一個方法叫做 first，可以返回第一個元素，就會這樣寫：

``` js
// 提醒一下，幫不屬於自己的物件加上 prototype 不是一件好事
// 應該盡可能避免
Array.prototype.first = function() {
  return this[0]
}

console.log([1].first()) // 1
console.log([2,3,4].first()) // 2
```

可是大家可以發現，這個 first 的方法裡面只有短短一行：`return this[0]`，其實不只陣列，物件也可以用，那如果我想用在物件身上呢？我就只能直接去呼叫 `Array.prototype.first` 並且把 this 改掉，才能應用在我想要的物件身上。

所以這就是 apply 與 call 存在的原因之一，我需要去改 this 才能把這個函式應用在我想要的地方，這種情況就沒辦法像普通 function 一樣去呼叫，而 `Array.prototype.slice.call(arguments)` 就是這樣的道理。

你可能有看過這種 slice 的用法，但你有想過到底為什麼可以嗎？

想知道原理，看一個東西準沒錯：ECMAScript Specification。

在 [22.1.3.25 Array.prototype.slice](http://www.ecma-international.org/ecma-262/10.0/index.html#sec-array.prototype.slice) 可以看到相關說明跟運行方式，

![22.1.3.25 Array.prototype.slice](/img/js-func/p1.png)

第一段是參數的說明，第二段是運行的步驟，第三段是其他額外說明。可以先看到最後面 Note3 的地方：

> The slice function is intentionally generic; it does not require that its this value be an Array object. Therefore it can be transferred to other kinds of objects for use as a method.

這邊就有寫了，這個 function 也可以用在物件身上，沒有一定要是 Array。而且從運行的步驟當中，可以看到是用 `HasProperty` 跟 `Get` 這兩個內部函式在處理的，而物件也是用這兩個，所以用在物件身上完全 ok。

而且一旦你知道了原理，還可以把前面提到的 function 也變成陣列：

``` js
// 記得這邊參數一定要是三個，才能讓長度變成 3
function test(a,b,c) {}
test[0] = 1
test[1] = 2
test[2] = 3

// function 搖身一變成為陣列
var arr = Array.prototype.slice.call(test)
console.log(arr) // [1, 2, 3]
```

既然都提到了 call，那我們來提一下另外兩個我們需要 call 或者是 apply 的理由。第一個是當你想要傳入多個參數，但你只有陣列的時候。

這是什麼意思呢？例如說 `Math.max` 這個函式，其實是可以吃任意參數的，例如說：

``` js
console.log(Math.max(1,2,3,4,5,6)) // 6
```

今天你有一個陣列，然後你想要求最大值，怎麼辦？你又不能直接呼叫 `Math.max`，因為你的參數是陣列而不是一個個的數字，直接呼叫的話你只會得到 NaN：

``` js
var arr = [1,2,3,4]
console.log(Math.max(arr)) // NaN
```

這時候就是 apply 派上用場的時刻了，第二個參數本來就是吃一個陣列，可以把陣列當作參數傳進去：

``` js
var arr = [1,2,3,4]
console.log(Math.max.apply(null, arr)) // 4
```

或是也可以運用 ES6 的展開運算子：

```
var arr = [1,2,3,4]
console.log(Math.max(...arr)) // 4
```

那你有沒有好奇過，為什麼 `Math.max` 可以吃無限多個參數？

其實也沒為什麼，[規格](http://www.ecma-international.org/ecma-262/10.0/index.html#sec-math.max)就是這樣寫的：

![Math.max](/img/js-func/p2.png)

再來有關於第二個要使用 apply 或是 call 的理由，先給大家一個情境：

有一天小明想來寫一個函式判斷傳進來的參數是否是物件，而且不能是陣列也不能是函式，就是個普通的物件就好，聰明的他想到了一個方法叫做 `toString`，回憶起 toString 的幾個例子：

``` js
var arr = []
var obj = {}
var fn = function(){}
console.log(arr.toString()) // 空字串
console.log(obj.toString()) // [object Object]
console.log(fn.toString()) // function(){}
```

既然在物件身上用 `toString` 以後會變成 `[object Object]`，那就利用這樣來判斷就行了吧！於是小明寫下這段程式碼：

``` js
function isObject(obj) {
  if (!obj || !obj.toString) return false
  return obj.toString() === '[object Object]'
}

var arr = []
var obj = {}
var fn = function(){}
console.log(isObject(arr)) // false
console.log(isObject(obj)) // true
console.log(isObject(fn)) // false
```

好，看起來十分合理，的確能夠判斷出是不是單純的物件，那到底有什麼問題呢？

問題就出在 `obj.toString()` 這一行，太天真了，萬一 obj 自己覆寫了 toString 這個方法怎麼辦？

``` js
function isObject(obj) {
  if (!obj || !obj.toString) return false
  return obj.toString() === '[object Object]'
}

var obj = {
  toString: function() {
    return 'I am object QQ'
  }
}

console.log(isObject(obj)) // false
```

那要怎麼樣才能確保我呼叫的 `toString` 一定是我想呼叫的那一個？

跟剛剛呼叫陣列的 slice 一樣，找到原始的 function 搭配使用 call 或是 apply：

``` js
function isObject(obj) {
  if (!obj || !obj.toString) return false

  // 新的
  return Object.prototype.toString.call(obj) === '[object Object]'
  
  // 舊的
  // return obj.toString() === '[object Object]'
}

var obj = {
  toString: function() {
    return 'I am object QQ'
  }
}

console.log(isObject(obj)) // true
```

這樣就能確保我是真的呼叫到我要的那一個，而不是依賴於原本的物件，就可能會有被覆寫的風險。以上幾點就是 apply 與 call 存在的幾個原因，這都是用一般的 function call 沒有辦法達成的。

（附註：以上判斷物件的方法應該還是有一些 case 過不了，但我只是想示範 call 的存在理由之一，並不是真的想寫出 isObject 這個函式）

## 神秘的 function 自帶變數

前面有提到 function 裡面會有一個自動被系統綁定的變數叫做 arguments，可以拿到傳進來的參數列表，雖然看起來像是陣列但其實是物件，而 arguments 其實有個神奇的特性，就是會自動跟參數做綁定，直接看下面範例就懂了：

``` js
function test(a) {
  console.log(a) // 1
  console.log(arguments[0]) // 1
  a = 2
  console.log(a) // 2
  console.log(arguments[0]) // 2
  arguments[0] = 3
  console.log(a) // 3
  console.log(arguments[0]) // 3
}
test(1)
```

改了 a，arguments 裡的參數也會改變；改了 arguments，a 也會跟著改變。這個行為最貼近我們一般所講的 `call by reference`，就算是重新賦值也還是會跟原本的東西綁在一起。

我知道這個行為是因為這一篇文章：[JS 原力覺醒 Day12- 傳值呼叫、傳址呼叫](https://ithelp.ithome.com.tw/articles/10221506)底下良葛格的回覆，才讓我發現原來 JS 的 arguments 還有這種特性。

講到這裡，還記得最前面的第四題嗎？

``` js
function log(obj) {
  doSomeMagic()
  console.log(obj.str) // 要讓這邊輸出的變成 world
}

// 只能改動這個函式裡面的東西
function doSomeMagic() {
  // 在這邊施展魔法
}

log({str: 'hello'})
```

就是利用 arguments 的這個特性：

``` js
function log(obj) {
  doSomeMagic()
  console.log(obj.str) // 要讓這邊輸出的變成 world
}

// 只能改動這個函式裡面的東西
function doSomeMagic() {
  // magic!
  log.arguments[0].str = 'world'
}

log({str: 'hello'})
```

可以從別的函式用 `log.arguments` 取得傳進去的參數，再利用 arguments 跟 formal parameter 會互相同步的特性，來改到看似不可能改到的 obj。

那如果把題目改一下呢？

``` js
(function(obj) {
  doSomeMagic()
  console.log(obj.str) // 要讓這邊輸出的變成 world
})({str: 'hello'})

// 只能改動這個函式裡面的東西
function doSomeMagic() {
  
}
```

沒有函式名稱了，那我們該怎麼拿到那個匿名函式的 arguments？

除了 arguments 以外，還有一些參數是會自動幫你帶進來的，例如說最常見的 this，還有很不常見的幾個，其中一個叫做 [caller](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Function/caller)，MDN 的解釋是這樣的：

> The function.caller property returns the function that invoked the specified function. It returns null for strict, async function and generator function callers.

可以用 caller 取得是哪一個 function 呼叫你的，例如說：

``` js
function a(){
  b()
}

function b(){
  console.log(b.caller) // [Function: a]
}

a()
```

既然知道了這個特性，那前面匿名函式的問題就迎刃而解了：

``` js
(function(obj) {
  doSomeMagic()
  console.log(obj.str) // 要讓這邊輸出的變成 world
})({str: 'hello'})

// 只能改動這個函式裡面的東西
function doSomeMagic() {
  doSomeMagic.caller.arguments[0].str = 'world'
}
```

如果你從來沒有看過 `caller` 這個參數，完全沒有關係，因為這本來就在開發上應該盡量避免用到，MDN 也把這個功能標示為 `Deprecated`，日後可能會被全面棄用，所以就跟我開頭講的一樣，這個題目純粹是 for fun，沒有什麼實際教學意義。

你以為結束了嗎？我原本也以為結束了，直到我在寫這篇文章的時候又想到還有一個延伸題，那就是如果連 `doSomeMagic` 都變成匿名函式呢？

``` js
(function(obj) {
  (function() {
    // show your magic here
    // 只能改動這個函式
    
  })()
  console.log(obj.str) // 要讓這邊輸出的變成 world
})({str: 'hello'})
```

這樣還能達成目標嗎？

這邊先賣個關子，之後會一起解答。

## 建立函式

前面寫了這麼多，最後才講回函式宣告，是因為我覺得這是相對上比較無聊的東西。如同我前面所說的，要建立函式的方法主要就三種：

1. Function declaration
2. Function expression
3. Function constructor

先講第三種，因為在日常開發上幾乎不會用到，就是利用 function constructor 來建立函式：

``` js
var f = new Function('str', 'console.log(str)')
f(123)
```

當我們在使用 `new` 這個關鍵字的時候，就會去呼叫到 Function 的 constructor，如果不想用 `new`，我們其實也可以這樣子寫：

``` js
var f = Function.constructor('str', 'console.log(str)')
f(123)
```

或是你只留 Function 其實也可以：

``` js
var f = Function('str', 'console.log(str)')
f(123)
```

而這邊想強調的重點就在 constructor，先來看一個簡單的 JS 物件導向的範例：

``` js
function Dog(name) {
  this.name = name
}

Dog.prototype.sayHi = function() {
  console.log('I am', this.name)
}

let d = new Dog('yo')
d.sayHi() // I am yo
```

這邊 d 是 Dog 的 instance，所以有一個特性就是 `d.constructor` 就會是 Dog 這個被當作建構子來呼叫的函式：

``` js
function Dog(name) {
  this.name = name
}

Dog.prototype.sayHi = function() {
  console.log('I am', this.name)
}

let d = new Dog('yo')
d.sayHi() // I am yo

console.log(d.constructor) // [Function: Dog]
```

知道這個特性可以做什麼呢？既然是這樣的話，那任意一個函式的 constructor，不就是 `Function.constructor` 了嗎？

``` js
function test() {}

console.log(test.constructor) // [Function: Function]
console.log(test.constructor === Function.constructor) // true
```

再搭配我們前面提到過的，可以利用 function constructor 來建立函式，就可以這樣使用：

``` js
function test() {}

var f = test.constructor('console.log(123)')
f() // 123
```

這邊 test 可以是任意函式，代表說我們隨便找一個內建函式，一樣能達到相同效果：

``` js
var f1 = [].map.constructor('console.log(123)')
var f2 = Math.min.constructor('console.log(456)')
f1() // 123
f2() // 456
```

如此一來，就可以達到：「不用 function 關鍵字也不用箭頭函式，但依然可以建立新的函式」，也就是開頭的問題三的解答。

這種用法通常會用在哪裡呢？用在繞過一些檢查！常見的做法是把 function 關鍵字濾掉、把 eval 濾掉、把箭頭函式濾掉等等來防止別人執行函式，這時就可以用 `constructor` 相關的東西來繞過，例如說這個：[Google CTF 2018 Quals Web Challenge - gCalc](https://blog.orange.tw/2018/06/google-ctf-2018-quals-web-gcalc.html) 就用到了類似的技巧。

談完了 function constructor，就剩下 function declaration 跟 function expression 了，先來講這兩者的差別：

``` js
// function declaration
function a() {}

// function expression
var b = function() {}
```

這兩者最大的差別在於 a 的做法是真的宣告一個名為 a 的函式，而 b 其實是：「宣告一個匿名函式，並且指定給變數 b」，而且 b 是執行到那一行的時候才會做函式的初始化，而 a 是在進入這段程式碼的時候就初始化了，所以你就算在宣告 a 以前也可以執行 a：

``` js
// function declaration
a()
function a() { }
```

可是 b 卻沒有辦法：

``` js
// function expression
b() // TypeError: b is not a function
var b = function () {}
```

這行為跟 hoisting 有關，詳情可參考：[我知道你懂 hoisting，可是你了解到多深？](https://blog.huli.tw/2018/11/10/javascript-hoisting-and-tdz/)。

不過上面有一個地方其實有點講錯，我說了 b 是：「宣告一個匿名函式，並且指定給變數 b」，但其實後面宣告的這個函式並不是沒有名字的，你可以 throw 一個 error 就知道了：

![error](/img/js-func/p3.png)

這個函式其實還是叫做 b，否則的話 stacktrace 的紀錄就會寫 `annoymous`。這個看似好像很直觀，但其實背後有點學問在，這個命名是在我們把函式賦值給 b 時才作用的，可以參考 [12.15.4 Runtime Semantics: Evaluation](http://www.ecma-international.org/ecma-262/10.0/index.html#sec-assignment-operators-runtime-semantics-evaluation)：

![12.15.4 Runtime Semantics: Evaluation](/img/js-func/p4.png)


得到你要 assign 的名稱以後再去呼叫 NamedEvaluation 來幫函式命名，可參考 [14.1.21 Runtime Semantics: NamedEvaluation](http://www.ecma-international.org/ecma-262/10.0/index.html#sec-function-definitions-runtime-semantics-namedevaluation)：

![[14.1.21 Runtime Semantics: NamedEvaluation]](/img/js-func/p5.png)

除了讓 JS 引擎自動幫你命名以外，其實也可以自己命名，這我們就叫做 named function expression：

``` js
// function expression
var b = function helloB() {
  throw 'I am b'
}
b()
```

不要把它跟函式宣告搞混了，這依然不是 function declaration，只是有名稱的 function expression，一樣是執行到這一行的時候才會初始化函式，而且這個名稱 `helloB` 跟你想的不一樣，他是沒辦法在外面呼叫到的：

``` js
// function expression
var b = function helloB() {
  throw 'I am b'
}
helloB() // ReferenceError: helloB is not defined
```

對外來說，它只看得見 b 這個變數，看不到 `helloB`。

那這個函式名稱到底有什麼用？第一個用途是在 function 內部可以呼叫到：

``` js
// function expression
var b = function fib(n) {
  if (n <= 1) return n
  return fib(n-1) + fib(n-2)
}
console.log(b(6)) // 8 
```

第二個是 stacktrack 上面也會顯示這個名稱而不是 b：

![error](/img/js-func/p6.png)

在這個時候可能感受不到他的好處，讓我換個例子來講，應該會更清楚一點，例如說以下程式碼：

``` js
var arr = [1,2,3,4,5]
var str = 
  arr.map(function(n){ return n + 1})
    .filter(function(n){ return n % 2 === 1})
    .join(',')
console.log(str) // 3, 5
```

雖然大家現在都習慣寫箭頭函式了，但是在箭頭出現以前，基本上都是這樣寫的。大家以前可能只注意到我們傳了兩個 anonymous function 進去，但更精確一點地說，map 跟 filter 傳的參數其實就是兩個不同的 function expression。

這時候我們假設 filter 傳進去的函式出問題了：

``` js
var arr = [1,2,3,4,5]
var str = 
  arr.map(function(n){ return n + 1})
    .filter(function(n){ throw 'errr' })
    .join(',')
console.log(str) // 3, 5
```

那我們在 debug 的時候，會看到 stacktrace 哀傷地只顯示了 `anonymous`：

![anonymous](/img/js-func/p7.png)

這時候若是改用 named function expression，就可以解決這個問題：

![named function expression](/img/js-func/p8.png)

這就是使用 named function expression 的好處。

前面有提到另一個好處是在函式內部可以呼叫到，像是底下的範例：

``` js
function run(fn, n) {
  console.log(fn(n)) // 55
}

run(function fib(n) {
  if (n <= 1) return n
  return fib(n-1) + fib(n-2)
}, 10)
```

`run` 只是一個空殼，會接收一個函式跟一個參數，接著就只是呼叫函式然後把執行結果印出來。在這邊我們傳入一個 named function expression 來算費氏數列，因為需要遞迴的關係，所以才幫函式取了名稱。

那如果傳進去的是一個 anonymous function 呢？也做得到遞迴嗎？

還真的做得到。

``` js
function run(fn, n) {
  console.log(fn(n)) // 55
}

run(function (n) {
  if (n <= 1) return n
  return arguments.callee(n-1) + arguments.callee(n-2)
}, 10)
```

`arguments` 這個神奇的物件前面已經介紹過了，但沒有講到的是上面有一個屬性叫做 `callee`，[MDN](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Functions/arguments/callee) 的解釋是：

> callee is a property of the arguments object. It can be used to refer to the currently executing function inside the function body of that function. This is useful when the name of the function is unknown, such as within a function expression with no name (also called "anonymous functions").

簡單來說就是可以取得自己，所以就算是匿名函式也可以做遞迴。

好，既然是這樣的話，大家還記得前面那個題目嗎？施展魔法的那個：

``` js
(function(obj) {
  (function() {
    // show your magic here
    // 只能改動這個函式
    
  })()
  console.log(obj.str) // 要讓這邊輸出的變成 world
})({str: 'hello'})
```

解答就是十分噁心的組合：

``` js
(function(obj) {
  (function() {
    arguments.callee.caller.arguments[0].str = 'world'
  })()
  console.log(obj.str) // 要讓這邊輸出的變成 world
})({str: 'hello'})
```

先利用 `arguments.callee` 取得自己，再加上 `caller` 取得呼叫自己的函式，然後再透過 `arguments` 改動參數。

## 解答時間

先來解答一下最前面提的幾個問題：

``` js
var fib = function calculateFib(n) {
  if (n <= 1) return n
  return fib(n-1) + fib(n-2)
}

console.log(calculateFib) // ???
console.log(fib(6))
```

### 1.那這個 function 到底叫做 fib 還是 calculateFib？
叫做 calculateFib，但是在函式外面要用 fib 才能存取到，在函式內可以用 calculateFib。

### 2. 底下那行 `console.log(calculateFib)` 會輸出什麼？

ReferenceError: calculateFib is not defined

### 3. 既然前面都已經給它名字了，為什麼後面還要再多一個？

1. 想呼叫自己的時候可以用這個名稱
2. stacktrace 會出現這個名字

### 4. 為什麼除了一般的呼叫 function 以外，還需要 call 跟 apply？什麼情形下需要用到它們？

1. 當我們想傳入陣列，但原本的函式只支援一個一個參數的時候
2. 當我們想自訂 this 的時候
3. 當我們想避開函式覆寫，直接呼叫某個函式的時候

### 5. 有沒有辦法做到不用 function 關鍵字，也能建立函式呢？

利用 function constructor：

``` js
var f1 = [].map.constructor('console.log(123)')
var f2 = Math.min.constructor('console.log(456)')
f1() // 123
f2() // 456
```

### 6. doSomeMagic 那題

透過 `arguments` 的各種噁心組合搭配就可以了。

## 總結

這篇整理了一些我對 JavaScript 函式的一些心得，有些我覺得很實用，有些就純粹是好玩，例如說 doSomeMagic 的那一題，就只是好玩而已，基本上改變 arguments 或是存取 caller 跟 callee 都是在實作上應該避免的行為，因為通常沒什麼理由這樣做，而且就算你真的想做什麼，也應該會有更好的做法。

至於實用的部分，named function expression 就滿實用的，YDKJS 的作者 Kyle Simpson 就提倡說：Always prefer named function expression，並且提出了一些好處，詳情可以參考：[[day19] YDKJS (Scope) : Kyle Simpson 史上超級無敵討厭匿名函式（Anonymous function)](https://ithelp.ithome.com.tw/articles/10224853)

然後 call 跟 apply 則是蔡逼八時期的我曾經思考過的問題，想說既然都可以直接呼叫 function，為什麼要有這兩個？在一些程式碼裡面看到 `Object.prototype.toString.call(obj)` 的時候，也會想說那為什麼不直接 `obj.toString()` 就好？後來才知道原來是為了避開函式覆寫的問題，例如說陣列也是個物件，但是它的 toString 就有重新寫過，會做跟 `join` 差不多的事情。所以才需要直接去呼叫到 `Object.prototype.toString`，因為那才是我們想要的行為。

寫到這邊不禁想起一些前端的面試題，例如說考你 apply 與 call 的差異跟用法，我自己覺得與其考這個，不如考我在這篇文章裡面問的「為什麼要有 apply 與 call」，會比較有鑑別度，也能知道對方是不是真的理解這兩個函式。

總之呢，大概就是這樣了，如果有人有發現什麼 function 相關的好玩的特性，無論實不實用都可以分享給我，我很樂意知道！