---
title: Intigriti 0222 XSS Challenge Author Writeup
catalog: true
date: 2022-02-14 15:43:37
tags: [Security]
categories: [Security]
translator: huli
photos: /img/intigriti-0222-author-writeup/cover-en.png
---

In May 2021, I solved my first Intigriti XSS challenge. Since then, I play every XSS challenge afterward, and solved most of them. Sometimes it's painful when you try everything you know but still can't solve it, however, the moment you made it, the pain is gone, replaced with joy and happiness.

As a player, I want to be on the other end(as a challenge maker) at least once, if I have an idea of an interesting XSS challenge. 

I talked to @PinkDraconian in Jan 2021 and share an XSS challenge I created, after a few discussions, it gets accepted. This write-up is about the story behind the challenge.

<!-- more -->

## Where the story begins

One day, when I was studying the famous [Tiny XSS Payloads](https://tinyxss.terjanq.me/) website, I noticed a  payload:

``` js
<svg/onload=eval(`'`+URL)>
```

My question is: "Why do we need a quote before the URL?"

If we can control the URL, we can make it something like this: `https://example.com/#';alert(1)`. After adding a quote before the URL, it becomes `'https://example.com/#';alert(1)`, just a string and a function call.

I realized that the quote is to make the URL a valid JavaScript snippet.

When I pasted the URL on the code editor, I noticed another interesting thing:

<img width="656" alt="截圖 2022-02-09 下午2 23 25" src="https://user-images.githubusercontent.com/2755720/153786488-f404eaf5-bb51-41eb-85b2-3c8dc5649ed4.png">


The part after `//` is grey out, because `//` means comment in JavaScript. Moreover, `https:` is also a valid syntax in JavaScript because it's a "label", what a coincidence! 

Unlike other languages like C, JavaScript has no `goto` statement. But, you can still use the `label` with `break` and `continue`, it's useful when you have nested for-loop:

``` js
// without label, you need to have a flag to break outer loop
let isOver = false
for(let i=0; i<5; i++) {
  console.log(i)
  for(let j=0; j<5; j++) {
    if (i*j === 9) {
      isOver = true
      break
    }
  }
  if (isOver) break
}

// with label, it's easier
outer:
for(let i=0; i<5; i++) {
  console.log(i)
  for(let j=0; j<5; j++) {
    if (i*j === 9) {
      break outer
    }
  }
}
```

So, `https://example.com` is a valid JavaScript code, it's composed of labels and comments, cool, isn't it? That is to say, `https://example.com\nalert(1)` is also valid and will pop up an alert!

After I found this, I was thinking that maybe I can make it an XSS challenge.

Then I do.

## Let's talk about the challenge

The core of the challenge is the following code:

``` js
window.name = 'XSS(eXtreme Short Scripting) Game'

function showModal(title, content) {
  var titleDOM = document.querySelector('#main-modal h3')
  var contentDOM = document.querySelector('#main-modal p')
  titleDOM.innerHTML = title
  contentDOM.innerHTML = content // DOM-XSS here
  window['main-modal'].classList.remove('hide')
}

if (location.href.includes('q=')) {
  var uri = decodeURIComponent(location.href)
  var qs = uri.split('&first=')[0].split('?q=')[1]
  if (qs.length > 24) {
    showModal('Error!', "Length exceeds 24, keep it short!")
  } else {
    showModal('Welcome back!', qs)
  }
}
```

I hope it looks normal, like what a normal developer will do. It's just extracting the query string `q` and checking its length, then putting it into HTML.

The challenge here is the length limit, you can only insert HTML with no more than 24 characters.

The shortest payload on TinyXSS is `<svg/onload=eval(name)>` which is 23 in length, but it doesn't work because of this line: `window.name = 'XSS(eXtreme Short Scripting) Game'`, it prevents the payload from `window.name`.

How about `<script/src=//Ǌ.₨></script>`? I saw so many people were trying this way, but it won't work even if there is no length limitation, because a `<script>` tag inserted with innerHTML should not execute.

All other payloads exceed 24 characters, including what I have mentioned previously: `<svg/onload=eval("'"+URL)>`

If you remember what I wrote at the beginning, you may try this payload as well: `<svg/onload=eval(URL)>` with the URL: `https://challenge-0222.intigriti.io/challenge/xss.html?q=%3Csvg/onload=eval(URL)%3E&first=1#%0aalert(1)`

Unfortunately, this doesn't work, because the `URL` is encoded, it's `%0a` instead of a newline character.

It seems a dead-end, unless you look at the code again carefully.

## Reuse the existing thing

If you check the scope in devtool or print all properties of `window`, you should find a variable called `uri`. Let's look at the code again:

``` js
if (location.href.includes('q=')) {
  var uri = decodeURIComponent(location.href)
  var qs = uri.split('&first=')[0].split('?q=')[1]
  if (qs.length > 24) {
    showModal('Error!', "Length exceeds 24, keep it short!")
  } else {
    showModal('Welcome back!', qs)
  }
}
```

Although the variable `uri` is declared inside the if block, it's still a global variable because [var is function-scoped or globally scoped](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Statements/var), not block-scoped.

Is this variable helpful? Absolutely.

`uri` is a decoded URL, our `%0a` turns into `\n`, a new line character! So, just replace the payload from `eval(URL)` to `eval(uri)`, the payload works now: https://challenge-0222.intigriti.io/challenge/xss.html?q=%3Csvg/onload=eval(uri)%3E&first=1#%0aalert(1)

We have to fix one last thing: it doesn't work on Firefox.

it's not hard to find out that `<style>` can be used instead of `<svg>`, here is the final payload: https://challenge-0222.intigriti.io/challenge/xss.html?q=%3Cstyle/onload=eval(uri)%3E&first=1#%0aalert(document.domain)

The length is 24 characters, perfectly fits the limitation.

By the way, if `%0a` is blocked, try `U+2028`(`%E2%80%A8`) and `U+2029`(`%E2%80%A9`) instead, it's also [line terminators](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Lexical_grammar#line_terminators). I learned this trick from 0621 XSS challenge.

## Other invalid but interesting solutions

I have another solution but with user interaction: https://challenge-0222.intigriti.io/challenge/xss.html?q=%3Cq%20oncut=eval(%22%27%22+URL)%3E1&first=1#';alert(1)

``` html
<q/oncut=eval("'"+URL)>1
```

One needs to focus on the `<q>` element and press `ctrl+x` to trigger the XSS.

If you have other solutions, feel free to DM me([@aszx87410](https://twitter.com/aszx87410)).
                                              
## Closing Thoughts

Thanks for playing the challenge I created, I hope all of you have fun and enjoy it.

There is another great article that has mentioned the same technique: [Smuggling Script via URL: Short HTML-based XSS payload](https://securitygoat.medium.com/smuggling-script-via-url-short-html-based-xss-payload-3036df8d9820), I haven't seen this until a player who solved the challenge sent me this via DM.

I should have added a new line filter to make it harder, at least not so easy to find the answer lol 
