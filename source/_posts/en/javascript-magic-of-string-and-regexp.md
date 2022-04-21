---
title: The Magical Features of RegExp and String Replacement in JavaScript
catalog: true
date: 2022-04-14 20:29:17
tags: [Security, Front-end]
categories: [Security]
---

It's a blog post about a few magical features that I have encountered recently. It is not interesting to say it directly. Let’s start with a few small challenges:

<!-- more -->

### Challenge 1

Guess what is the result of the code below?

``` js
var regexp = /huli/g
var str = 'blog.huli.tw'
var str2 = 'example.huli.tw'

console.log(regexp.test(str)) // ???
console.log(regexp.test(str2)) // ???
```

### Challenge 2

First let you enter a password, and then let you run some JavaScript, can you get the password that has been removed?

``` js
var password = prompt('input password')
while (!/^[a-zA-Z0-9]+$/.test(password)) {
  console.log('invalid password')
  password = prompt('input password')
}
password = ''
// If you can dynamically execute the code below, can you get the password?
eval(prompt('try to get password'))
```

### Challenge 3

Will something go wrong with the code below? What is it?

``` js
var tmpl = '<input type="submit" value="{{value}}">'
var value = prompt('your payload')
value = value.replace(/[>"]/g, '')
tmpl = tmpl.replace('{{value}}', value)
document.body.innerHTML = tmpl
```

## Stateful RegExp

Guess what is the result of the code below?

``` js
var regexp = /huli/g
var str = 'blog.huli.tw'
var str2 = 'example.huli.tw'

console.log(regexp.test(str)) // ???
console.log(regexp.test(str2)) // ???
```

Whoever looks at it will think both are `true`, right? But the answer is `true` and `false`.

Even if you write it like this, the second is still false:

``` js
var regexp = /huli/g
var str = 'blog.huli.tw'

console.log(regexp.test(str)) // true
console.log(regexp.test(str)) // false
```

It's because of [RegExp is stateful](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/RegExp/test), as long as there is a global or sticky flag.

RegExp has an attribute called `lastIndex`, which will record the position of the last match. The next time `test` is used, it will start from `lastIndex`. If not found, `lastIndex` will automatically reset to zero.

``` js
var regexp = /huli/g
var str = 'blog.huli.tw'

console.log(regexp.test(str)) // true
console.log(regexp.lastIndex) // 9, because str[5..8] === 'huli' 

console.log(regexp.test(str)) // false
console.log(regexp.lastIndex) // 0, reset to zero because not found

console.log(regexp.test(str)) // true, because lastIndex was reset to 0
console.log(regexp.lastIndex) // 9
```

So, according to the featue of `lastIndex` , this looks fine at first glance:

``` js
var regexp = /huli/g
var str = 'huli.tw' 
var str2 = 'blog.huli.tw'

console.log(regexp.test(str)) // true
console.log(regexp.test(str2)) // true
```

But that doesn't mean there are no bugs.

The reason why the above code seems to be no problem is because `lastIndex` is 4 after first match, and the position where huli appears in str2 starts from 5, so it can be found as well.

If the last two lines are swaped, it will produce unexpected results.

Anyway, be careful with this feature when using global RegExp. As a security engineer, we can pay attention to these potential bugs and see if there is anything that can be exploited.

## The Magical Property of RegExp

Continuing the small challenge at the beginning:

``` js
var password = prompt('input password')
while (!/^[a-zA-Z0-9]+$/.test(password)) {
  console.log('invalid password')
  password = prompt('input password')
}
password = ''
eval(prompt('try to get password'))
```

The variable `password` has been cleared, so we can't access the value from `prompt`.

Fair enough, but that's not true.

we can get it via a magical property on RegExp called [RegExp.input](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/RegExp/input), this property will record the input for the last match of `regepx.test()`:

``` js
/hello/.test('hello world')
console.log(RegExp.input) // hello world
console.log(RegExp.$_) // same as above
```

In addition to this, other parameters are also logged:

1. [RegExp.lastMatch ($&)](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/RegExp/lastMatch)
2. [RegExp.lastParen ($+)](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/RegExp/lastParen)
3. [RegExp.leftContext ($&#x60;)](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/RegExp/leftContext)
4. [RegExp.rightContext ($')](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/RegExp/rightContext)

I learned about this trick at [DiceCTF 2022 - web/nocookies](https://blog.bawolff.net/2022/02/write-up-for-dicectf-2022-nocookies.html)

## Special Variables for RegExp

In the challenge 3, we gave the following code:

``` js
var tmpl = '<input type="submit" value="{{value}}">'
var value = prompt('your payload')
value = value.replace(/[>"]/g, '')
tmpl = tmpl.replace('{{value}}', value)
document.body.innerHTML = tmpl
```

The double quotes have been filtered out, so there should be no way to escape the attribute, and `>` has also been removed, so there is no way to close the tag.

However, when doing string replacement, there is something called: [special replacement patterns](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/String/replace#specifying_a_string_as_a_parameter). For example, $&#x60; can get the "front" of the place where the string is replaced, `$'` can get the back.

Let's see an example:

``` js
const str = '123{n}456'

// 123A456
console.log(str.replace('{n}', 'A'))

// 123123A456, the original {n} becomes 123A
console.log(str.replace('{n}', "$`A"))

// 123456A456, the original  {n} becomes 456A
console.log(str.replace('{n}', "$'A"))
```

So back to our challenge:

``` js
var tmpl = '<input type="submit" value="{{value}}">'
var value = prompt('your payload')
value = value.replace(/[>"]/g, '')
tmpl = tmpl.replace('{{value}}', value)
document.body.innerHTML = tmpl
```

`">` is right after｛{value}}, although both characters are filtered out, we can use `$'` to get these two characters.

So the answer to this question is `$'<style onload=alert(1) `:

``` js
var tmpl = '<input type="submit" value="{{value}}">'
var value = "$'<style onload=alert(1) "
value = value.replace(/[>"]/g, '')
tmpl = tmpl.replace('{{value}}', value)
document.body.innerHTML = tmpl
```

We can use `$'` which is `">` to close the tag, then we can use other tags for XSS, and the final result is:

``` html
<input type="submit" value=""><style onload=alert(1) ">
```

I first learned about this at [PlaidCTF 2022 - YACA](https://gitea.nitowa.xyz/nitowa/PlaidCTF-YACA), but a similar trick seems to have occurred at [DragonCTF 2021 - Webpwn](https://balsn.tw/ctf_writeup/20211127-dragonctf2021/#webpwn).
