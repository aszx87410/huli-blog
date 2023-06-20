---
title: The Magical Features of RegExp and String Replacement in JavaScript
catalog: true
date: 2022-04-14 20:29:17
tags: [Security, Front-end]
categories: [Security]
---

Here are a few magical features that I recently encountered. Let's start with a few challenges:

<!-- more -->

### Challenge One

Guess what the result of the following code will be?

``` js
var regexp = /huli/g
var str = 'blog.huli.tw'
var str2 = 'example.huli.tw'

console.log(regexp.test(str)) // ???
console.log(regexp.test(str2)) // ???
```

### Challenge Two

First, you enter a password, and then you enter a piece of code. Can you get an already missing variable?

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

### Challenge Three

Will the following code cause any problems? If so, what kind of problems? How to trigger it?

``` js
var tmpl = '<input type="submit" value="{{value}}">'
var value = prompt('your payload')
value = value.replace(/[>"]/g, '')
tmpl = tmpl.replace('{{value}}', value)
document.body.innerHTML = tmpl
```

## Stateful RegExp

Guess what the result of the following code will be?

``` js
var regexp = /huli/g
var str = 'blog.huli.tw'
var str2 = 'example.huli.tw'

console.log(regexp.test(str)) // ???
console.log(regexp.test(str2)) // ???
```

Everyone would think that both are true, right? But the answer is true and false, and even if you write it like this, the second one is also false:

``` js
var regexp = /huli/g
var str = 'blog.huli.tw'

console.log(regexp.test(str)) // true
console.log(regexp.test(str)) // false
```

There will be such a result because [RegExp is stateful](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/RegExp/test) if there is a global or sticky flag.

RegExp has a `lastIndex` property that records the last matching position. The next time `test` is used, it will start searching from `lastIndex`. If it cannot be found, `lastIndex` will automatically be set to zero.

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

Therefore, based on the characteristics of `lastIndex` mentioned above, this looks fine at first glance:

``` js
var regexp = /huli/g
var str = 'huli.tw' 
var str2 = 'blog.huli.tw'

console.log(regexp.test(str)) // true
console.log(regexp.test(str2)) // true
```

But it doesn't mean there are no bugs.

The reason why the above paragraph looks fine is only because after the first search, `lastIndex` is 4, and the position where huli appears in str2 starts from 5, so it can still be found. If the last two lines are swapped, unexpected results will occur.

In short, be careful with this feature when using global RegExp. For security, you can pay attention to these potential bugs and see if there are any exploitable areas.

## The Magical Recording Properties of RegExp

Continuing with the small challenges at the beginning:

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

The variable has already been cleared, so it cannot be obtained.

But we can use a magical property on RegExp to get it, called: [RegExp.input](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/RegExp/input), which records the input of the last `regepx.test()` match:

``` js
/hello/.test('hello world')
console.log(RegExp.input) // hello world
console.log(RegExp.$_) // 同上
```

In addition, other parameters are also recorded:

1. [RegExp.lastMatch ($&)](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/RegExp/lastMatch)
2. [RegExp.lastParen ($+)](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/RegExp/lastParen)
3. [RegExp.leftContext ($`)](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/RegExp/leftContext)
4. [RegExp.rightContext ($')](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/RegExp/rightContext)

I first learned about this technique in [DiceCTF 2022 - web/nocookies](https://blog.huli.tw/2022/02/08/what-i-learned-from-dicectf-2022/).

## Special Variables in RegExp

In the third challenge of the PlaidCTF, we were given the following code:

``` js
var tmpl = '<input type="submit" value="{{value}}">'
var value = prompt('your payload')
value = value.replace(/[>"]/g, '')
tmpl = tmpl.replace('{{value}}', value)
document.body.innerHTML = tmpl
```

Since the double quotes were filtered out, it should not be possible to escape the attribute, and since the `>` was also removed, it should not be possible to close the tag.

However, when doing string replacement, there is something called [special replacement patterns](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/String/replace#specifying_a_string_as_a_parameter). For example, `$&#x60;` can get the "front" of the string replacement, and `$'` can get the back. An example will make it easier to understand:

``` js
const str = '123{n}456'

// 123A456
console.log(str.replace('{n}', 'A'))

// 123123A456，原本 {n} 的地方變成 123A
console.log(str.replace('{n}', "$`A"))

// 123456A456，原本 {n} 的地方變成 456A
console.log(str.replace('{n}', "$'A"))
```

Therefore, returning to our question:

``` js
var tmpl = '<input type="submit" value="{{value}}">'
var value = prompt('your payload')
value = value.replace(/[>"]/g, '')
tmpl = tmpl.replace('{{value}}', value)
document.body.innerHTML = tmpl
```

The string after `｛{value}}` is `">`. Although both of these characters are filtered out, we can use `$'` to get these two characters.

Therefore, the answer to this question is `$'<style onload=alert(1) `:

``` js
var tmpl = '<input type="submit" value="{{value}}">'
var value = "$'<style onload=alert(1) "
value = value.replace(/[>"]/g, '')
tmpl = tmpl.replace('{{value}}', value)
document.body.innerHTML = tmpl
```

By using `$'`, which is `">`, to close the tag, we can use other tags for XSS. The final result is:

``` html
<input type="submit" value=""><style onload=alert(1) ">
```

I first learned about this in [PlaidCTF 2022 - YACA](https://gitea.nitowa.xyz/nitowa/PlaidCTF-YACA), but a similar technique seems to have appeared in [DragonCTF 2021 - Webpwn](https://balsn.tw/ctf_writeup/20211127-dragonctf2021/#webpwn).
