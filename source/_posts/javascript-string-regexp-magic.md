---
title: JavaScript 中 RegExp 與字串取代的神奇特性
catalog: true
date: 2022-04-14 20:29:17
tags: [Security, Front-end]
categories: [Security]
---

簡單記錄幾個最近碰到的神奇特性，直接講不有趣，先來幾個小挑戰：

<!-- more -->

### 挑戰一

猜猜底下程式碼的執行結果是什麼？

``` js
var regexp = /huli/g
var str = 'blog.huli.tw'
var str2 = 'example.huli.tw'

console.log(regexp.test(str)) // ???
console.log(regexp.test(str2)) // ???
```

### 挑戰二

先讓你輸入一個密碼，然後讓你輸入一段程式碼，可以拿到已經不見的變數嗎？

``` js
var password = prompt('input password')
while (!/^[a-zA-Z0-9]+$/.test(password)) {
  console.log('invalid password')
  password = prompt('input password')
}
password = ''
// 如果可以在底下動態執行程式碼，拿得到 password 嗎？
eval(prompt('try to get password'))
```

### 挑戰三

底下的寫法會出事嗎？會的話是出什麼事？怎麼觸發？

``` js
var tmpl = '<input type="submit" value="{{value}}">'
var value = prompt('your payload')
value = value.replace(/[>"]/g, '')
tmpl = tmpl.replace('{{value}}', value)
document.body.innerHTML = tmpl
```

## 有狀態的 RegExp

猜猜底下程式碼的執行結果是什麼？

``` js
var regexp = /huli/g
var str = 'blog.huli.tw'
var str2 = 'example.huli.tw'

console.log(regexp.test(str)) // ???
console.log(regexp.test(str2)) // ???
```

無論是誰來看都會覺得兩個都是 true 吧？但答案是 true 跟 false，甚至你寫成這樣，第二個也是 false：

``` js
var regexp = /huli/g
var str = 'blog.huli.tw'

console.log(regexp.test(str)) // true
console.log(regexp.test(str)) // false
```

會有這樣的結果，是因為 [RegExp 是 stateful 的](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/RegExp/test)，如果有 global 或是 sticky 的 flag 的話。

RegExp 有一個 `lastIndex` 的屬性，會記錄上次符合的位置，下次再使用 `test` 時就會從 `lastIndex` 開始找起。如果找不到的話，`lastIndex` 會自動歸零。

``` js
var regexp = /huli/g
var str = 'blog.huli.tw'

console.log(regexp.test(str)) // true
console.log(regexp.lastIndex) // 9，因為 str[5..8] 是配對到的 'huli' 

console.log(regexp.test(str)) // false
console.log(regexp.lastIndex) // 0，因為找不到所以自動歸零

console.log(regexp.test(str)) // true，此時再找一次就可以找到了，因為 lastIndex 是 0
console.log(regexp.lastIndex) // 9
```

所以根據上面所講的 `lastIndex` 的特性，這樣乍看之下是沒問題的：

``` js
var regexp = /huli/g
var str = 'huli.tw' 
var str2 = 'blog.huli.tw'

console.log(regexp.test(str)) // true
console.log(regexp.test(str2)) // true
```

但並不代表沒有 bug。

上面這一段之所以看起來沒問題，只是因為第一次找完以後 `lastIndex` 是 4，而剛好 str2 中 huli 出現的位置是從 5 開始，所以一樣找得到，如果把最後兩行位置對調，就會產生預期外的結果。

總之呢，在使用 global RegExp 的時候要小心這個特性。而對資安來說，則是可以關注這些潛在的 bug，看看有沒有能利用的地方。

## RegExp 的神奇紀錄屬性

延續開頭的小挑戰：

``` js
var password = prompt('input password')
while (!/^[a-zA-Z0-9]+$/.test(password)) {
  console.log('invalid password')
  password = prompt('input password')
}
password = ''
// 如果可以在底下動態執行程式碼，拿得到 password 嗎？
eval(prompt('try to get password'))
```

變數已經被清空了，所以是拿不到變數的。

但我們可以靠著 RegExp 上的一個神奇屬性來拿到，叫做：[RegExp.input](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/RegExp/input)，這個屬性會紀錄上一次 `regepx.test()` 符合時的 input：

``` js
/hello/.test('hello world')
console.log(RegExp.input) // hello world
console.log(RegExp.$_) // 同上
```

除此之外，還有其他參數也會被記錄：

1. [RegExp.lastMatch ($&)](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/RegExp/lastMatch)
2. [RegExp.lastParen ($+)](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/RegExp/lastParen)
3. [RegExp.leftContext ($`)](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/RegExp/leftContext)
4. [RegExp.rightContext ($')](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/RegExp/rightContext)

第一次知道這技巧是在 [DiceCTF 2022 - web/nocookies](https://blog.huli.tw/2022/02/08/what-i-learned-from-dicectf-2022/)

## RegExp 的特殊變數

開頭的挑戰三中我們給出了底下這段程式碼：

``` js
var tmpl = '<input type="submit" value="{{value}}">'
var value = prompt('your payload')
value = value.replace(/[>"]/g, '')
tmpl = tmpl.replace('{{value}}', value)
document.body.innerHTML = tmpl
```

雙引號被濾掉了，所以照理來說應該沒辦法跳脫出屬性才對，`>` 也被拿掉了，所以也沒辦法關閉標籤。


但是呢，在做字串取代的時候，有種東西叫做：[special replacement patterns](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/String/replace#specifying_a_string_as_a_parameter)，舉例來說 $&#x60; 可以拿到字串取代的地方的「前面」，`$'` 則是可以拿到後面，看個範例會更容易理解：

``` js
const str = '123{n}456'

// 123A456
console.log(str.replace('{n}', 'A'))

// 123123A456，原本 {n} 的地方變成 123A
console.log(str.replace('{n}', "$`A"))

// 123456A456，原本 {n} 的地方變成 456A
console.log(str.replace('{n}', "$'A"))
```

因此回到我們的題目：

``` js
var tmpl = '<input type="submit" value="{{value}}">'
var value = prompt('your payload')
value = value.replace(/[>"]/g, '')
tmpl = tmpl.replace('{{value}}', value)
document.body.innerHTML = tmpl
```

｛{value}} 的後面是 `">`，雖然這兩個字元都被過濾掉，但我們可以用 `$'` 來拿到這兩個字元。

因此這題的答案是 `$'<style onload=alert(1) `：

``` js
var tmpl = '<input type="submit" value="{{value}}">'
var value = "$'<style onload=alert(1) "
value = value.replace(/[>"]/g, '')
tmpl = tmpl.replace('{{value}}', value)
document.body.innerHTML = tmpl
```

先用 `$'` 也就是 `">` 來關閉標籤，就可以用其他標籤進行 XSS，最後產生的結果是：

``` html
<input type="submit" value=""><style onload=alert(1) ">
```

我第一次知道這個是在 [PlaidCTF 2022 - YACA](https://gitea.nitowa.xyz/nitowa/PlaidCTF-YACA)，但在 [DragonCTF 2021 - Webpwn](https://balsn.tw/ctf_writeup/20211127-dragonctf2021/#webpwn) 中似乎也出現過類似的技巧。