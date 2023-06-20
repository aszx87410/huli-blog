---
title: iframe and window.open black magic
catalog: true
date: 2022-04-07 22:02:57
tags: [Security, Front-end]
categories: [Security]
---

If you want to generate a new window on a webpage, there are probably only two options: one is to embed resources on the same page using tags such as `iframe`, `embed`, and `object`, and the other is to use `window.open` to open a new window.

As a front-end developer, I believe that everyone is familiar with these. You may have used `iframe` to embed third-party web pages or widgets, or used `window.open` to open a new window and communicate with the original window through `window.opener`.

However, from a security perspective, there are many interesting things about iframes, which often appear in the real world or in CTF competitions. Therefore, I want to record some of the features I learned recently through this article.

<!-- more -->

## Basic iframe

Let's take a look at the basic use of iframes. You can use the `<iframe>` tag to bring other people's web pages into your own:

``` html
<iframe src="https://blog.huli.tw"></iframe>
```

But if you think about it carefully, if your web page can be embedded by anyone, there may be a risk of clickjacking.

Therefore, if you don't want your web page to be embedded or want to set only specific origins that can be embedded, you can use `Content-Security-Policy` and `X-Frame-Options`. I have mentioned these in [What is Clickjacking](https://blog.huli.tw/2021/09/26/what-is-clickjacking/), so I won't go into detail here.

Some websites that allow posting or commenting usually open up a certain degree of HTML elements and do not completely block them. For example, at least harmless elements such as bold (`<b>`) and italic (`<i>`) will be opened, and some websites will also support the iframe tag to support functions such as YouTube players.

Better websites will restrict you to only enter the ID of the YouTube video and concatenate the YouTube prefix on the front end to ensure that the src loaded by the iframe comes from YouTube. Some websites may want to embed too many sites and want to provide users with more freedom, so they can allow users to customize the content of the iframe src and put whatever they want.

What are the risks if the attacker can control the iframe src?

The first and most easily thought of risk is that you can directly embed a phishing website in it. For example, write a page for logging in again or receiving prizes, and someone may actually enter their account password and submit the form.

However, the impact of this is limited, and it involves a bit of social engineering. In fact, there is a simpler and more violent way, like this:

``` html
<iframe src="javascript:alert(1)"></iframe>
```

Yes, the src of the iframe can be in the format of `javascript:` at the beginning, and JavaScript code can be executed directly to achieve XSS. By the way, the action of `<form>` and the href of `<a>` can also be placed. I mentioned this in [Learn Frontend from Security POV](https://blog.huli.tw/2021/10/25/learn-frontend-from-security-pov/).

Moreover, the things in HTML attributes can be encoded, and there are three ways to encode them, using the `&` character as an example:

1. Encode with names, such as `&amp;` (not every character is supported, there is a list here: [https://dev.w3.org/html5/html-author/charref](https://dev.w3.org/html5/html-author/charref))
2. Encode with decimal, such as `&#38;`
3. Encode with hexadecimal, such as `&#x26;`

So every character in `javascript:alert(1)` can be freely replaced with these encodings, for example:

``` html
<iframe src="&#x6a;&#65;vAScrIpt&colon;alert&lpar;1&rpar;"></iframe>
```

(If you want to play with encoding and decoding, you can go to this website: https://mothereff.in/html-entities)

In addition to `javascript:`, you can also use `data:` to load any web page:

``` html
<iframe src="data:text/html,<h1>hello</h1>"></iframe>
```

You can also specify base64 encoding:

``` html
<iframe src="data:text/html;base64,PGgxPmhlbGxvPC9oMT4="></iframe>
```

However, the above two methods are not very useful because if the src uses data URI, the origin will become `"null"`, which is different from the original page and cannot access the data on the page.

So as the defending party, what can we do? We can restrict the beginning to be `http://` or `https://`, which can block unexpected schemes.

However, if only this is done, there is another potential risk, which is open redirect. The embedded page can use `top.location = "https://huli.tw"` to redirect the top-level page to anywhere.

Usually, cross-origin operations are prohibited, and errors will be thrown when accessing properties on the window:

> Uncaught DOMException: Blocked a frame with origin "null" from accessing a cross-origin frame.

But there are a few exceptions, which can be found in the HTML spec's [7.2.3.1 CrossOriginProperties ( O )](https://html.spec.whatwg.org/multipage/browsers.html#crossoriginproperties-(-o-)):

> If O is a Location object, then return « { [[Property]]: "href", [[NeedsGet]]: false, [[NeedsSet]]: true }, { [[Property]]: "replace" } ».
>
> A JavaScript property name P is a cross-origin accessible window property name if it is "window", "self", "location", "close", "closed", "focus", "blur", "frames", "length", "top", "opener", "parent", "postMessage", or an array index property name.

Some are callable functions, such as `focus`, `blur`, and `postMessage`, which can be called across origins, and `postMessage` is also the primary way to pass information between windows across origins.

Most of the others are readable properties, such as `closes`, `frames`, `length`, `top`, `opener`, and `parent`.

The few writable properties are `location.href`, which can be used to redirect the webpage to another location using `location.href = 'https://huli.tw'` as long as you can access the window.

By the way, there is another way to execute JavaScript through the location + javascript protocol, like this: `location.href = 'javascript:alert(1)'`, which I mentioned in [What is Open Redirect](https://blog.huli.tw/2021/09/26/what-is-open-redirect/) .

At this point, you may wonder if the iframe src + data URI mentioned earlier can bypass the null origin restriction and perform XSS on the parent window using this method? Like this:

``` html
<iframe src="data:text/html,<script>top.location.href = 'javascript:alert(1)'</script>"></iframe>
```

The answer is no, the browser will give you this error:

> Unsafe attempt to initiate navigation for frame with URL 'file://poc.html' from frame with URL 'data:text/html,&lt;script>top.location.href = 'javascript:alert(1)'</script>'. The frame attempting navigation must be same-origin with the target if navigating to a javascript: url

If you want to jump to a URL starting with javascript:, it must be same-origin to allow you to jump.

## iframe's srcdoc

In addition to the commonly used src attribute, there is another attribute called srcdoc, which contains the content of the iframe. It is similar to src + data URI:

``` html
<iframe
  srcdoc="<h1>hello</h1><script>alert(top.document.body)</script>">
</iframe>
```

But there is a decisive difference, that is, the window generated by iframe + srcdoc will inherit the origin of the upper layer, which is different from the null origin of data URI. That is to say, the above code can access the upper layer's DOM elements because they are same origin.

In addition, srcdoc is not affected by the `frame-src` of CSP. Just like iframe's src, if it is `javascript:`, it is controlled by `script-src` instead of `frame-src`. For details, please refer to [Test of CSP: iframe srcdoc='...' is not governed by frame-src](https://csplite.com/csp/test188/).

Also, because srcdoc is an HTML attribute, the content is the same as mentioned before, it can be an encoded result, like this:

``` html
<iframe srcdoc="&lt;script&gt;alert(1)&lt;/script&gt;"></iframe>
```

Therefore, if the attribute of iframe srcdoc is controllable, even if the content has been escaped, it is useless and will still be parsed back to the original symbol for execution.

## iframe's CSP

There is a csp attribute on the iframe, which can specify the CSP rules for the document loaded by the iframe, but not every browser supports it. Please refer to [MDN: HTMLIFrameElement.csp](https://developer.mozilla.org/en-US/docs/Web/API/HTMLIFrameElement/csp):

``` html
<iframe csp="default-src 'self'; script-src 'none';"
  srcdoc="<script>alert(1)</script>"></iframe>
```

After adding the csp attribute, the content of the iframe will be affected by it. For example, opening test.html directly will pop up an alert, but using csp to block inline scripts will pop up an error message violating CSP:

``` html
// test.html
<script>alert(1)</script>

// csp.html
<iframe csp="default-src 'self'; script-src 'none';" src="test.html"></iframe>
```

> Refused to execute inline script because it violates the following Content Security Policy directive: "script-src 'none'". Either the 'unsafe-inline' keyword, a hash ('sha256-bhHHL3z2vDgxUt0W3dWQOrprscmda2Y5pLsLg4GF+pI='), or a nonce ('nonce-...') is required to enable inline execution.

In a previous Intigriti XSS challenge, CSP was inserted to make the CSP stricter, and some scripts would not be executed, relying on this to bypass some restrictions.

## iframe's sandbox

As mentioned earlier, when you use an iframe to embed other web pages, that web page can use `top.location = 'https://huli.tw'` to redirect the upper page to another place. The iframe has an attribute called sandbox, which can restrict various behaviors of the iframe and prevent it from doing some bad things. The basic usage is like this:

``` html
<iframe srcdoc="<script>alert(1)</script>" sandbox></iframe>
```

> Blocked script execution in 'about:srcdoc' because the document's frame is sandboxed and the 'allow-scripts' permission is not set.

Once the sandbox attribute is added, it enters sandbox mode. There are two main differences with or without it.

The first is that the origin of the loaded iframe becomes `null`.

The second is that a lot of functions will be turned off, and these functions can be actively turned on. According to the latest [spec](https://html.spec.whatwg.org/multipage/iframe-embed-object.html#the-iframe-element), there are a total of 13 flags, each representing a function:

1. allow-downloads
2. allow-forms
3. allow-modals
4. allow-orientation-lock
5. allow-pointer-lock
6. allow-popups
7. allow-popups-to-escape-sandbox
8. allow-presentation
9. allow-same-origin
10. allow-scripts
11. allow-top-navigation
12. allow-top-navigation-by-user-activation
13. allow-top-navigation-to-custom-protocols

Here, there are quite a few flags, and some of them are very similar. Let's start with the most important one, `allow-scripts`. This flag is easy to understand. If it is not added, JavaScript cannot be executed, as seen in the error above. After adding this flag, JavaScript can be executed, but there are still limitations on the available functions.

We can categorize the other flags into several types for better understanding.

### Flags related to redirection

The following three flags are related to redirection:

1. allow-top-navigation
2. allow-top-navigation-by-user-activation
3. allow-top-navigation-to-custom-protocols

If not added, the default is that the upper layer cannot be redirected:

``` html
<iframe
  srcdoc="<script>top.location='https://blog.huli.tw'</script>"
  sandbox="allow-scripts">
</iframe>
```

Error:

> Unsafe attempt to initiate navigation for frame with URL 'file:///test.html' from frame with URL 'about:srcdoc'. The frame attempting navigation of the top-level window is sandboxed, but the flag of 'allow-top-navigation' or 'allow-top-navigation-by-user-activation' is not set.

To allow the iframe to redirect to the upper layer, simply add `allow-top-navigation`. However, if you don't want the webpage to be automatically redirected without interaction, you can use the `allow-top-navigation-by-user-activation` flag:

``` html
<iframe
  srcdoc="<script>top.location='https://blog.huli.tw'</script>"
  sandbox="allow-scripts allow-top-navigation-by-user-activation">
</iframe>
```

Error:

> The frame attempting navigation of the top-level window is sandboxed with the 'allow-top-navigation-by-user-activation' flag, but has no user activation (aka gesture). See https://www.chromestatus.com/feature/5629582019395584.

With this flag, the user must have interaction (such as clicking a button to trigger an event) to redirect the webpage.

As for the `allow-top-navigation-to-custom-protocols` flag, it is not supported by Chrome at the moment, so it cannot be demoed. The flags supported by Chrome 102 can be found here: [third_party/blink/renderer/core/html/html_iframe_element_sandbox.cc](https://chromium.googlesource.com/chromium/src.git/+/refs/tags/102.0.4961.1/third_party/blink/renderer/core/html/html_iframe_element_sandbox.cc#17)

### Flags related to functions

1. allow-downloads
2. allow-forms
3. allow-orientation-lock
4. allow-pointer-lock
5. allow-presentation

The above five flags are related to functions, and you can roughly tell what they are for from their names.

For example, by default, forms cannot be submitted:

``` html
<iframe
  srcdoc="<form><input name=a value=a><input type=submit></form>"
  sandbox>
</iframe>
```

Error:

> Blocked form submission to '' because the form's frame is sandboxed and the 'allow-forms' permission is not set.

You need to add the `allow-forms` flag before submitting the form. Other flags are similar, but we won't go into detail here.

### Flags related to pop-up windows

1. allow-modals
2. allow-popups
3. allow-popups-to-escape-sandbox

`allow-modals` and `allow-popups` have similar names, but their definitions are quite different. The following functions are opened by `allow-modals`:

1. window.alert
2. window.confirm
3. window.print
4. window.prompt
5. beforeunload event

Here's a simple example: `<iframe srcdoc="<script>alert(1)</script>" sandbox="allow-scripts">`, with the error message:

> Ignored call to 'alert()'. The document is sandboxed, and the 'allow-modals' keyword is not set.

`allow-popups` is related to `window.open` and `target=_blank`. By default, you cannot open a new window:

``` html
<iframe
  srcdoc="<script>window.open()</script>"
  sandbox="allow-scripts">
</iframe>
```

Error message:

> Blocked opening '' in a new window because the request was made in a sandboxed frame whose 'allow-popups' permission is not set.

You need to add `allow-popups` to use `window.open`.

There's also a magical feature here. I think the [old spec](https://www.w3.org/TR/2010/WD-html5-20100624/the-iframe-element.html) explains it better:

> While the sandbox attribute is specified, the iframe element's nested browsing context must have the flags given in the following list set. In addition, any browsing contexts nested within an iframe, either directly or indirectly, must have all the flags set on them as were set on the iframe's Document's browsing context when the iframe's Document was created.

The [new spec](https://html.spec.whatwg.org/multipage/origin.html#sandboxing) removes that section and puts it somewhere else, but the meaning is the same: the window opened by the sandboxed iframe inherits the sandbox properties!

What does this mean?

For example, if I have an `iframe.html` with only this content: `<script>alert(1)</script>`, and then I write this in another page `test.html`:

``` html
<iframe
  srcdoc="<script>window.open('iframe.html')</script>"
  sandbox="allow-scripts allow-popups">
</iframe>
```

You will find that the newly opened `iframe.html` page cannot execute `alert(1)` because it inherits the sandbox, and the sandbox does not have the `allow-modals` property.

Another example: we can find a webpage that uses JS to render the page content on the internet, like this calculator: https://ahfarmer.github.io/calculator/

It works fine when opened directly, but if we open it with a sandboxed iframe:

``` html
<iframe
  srcdoc="<a href='https://ahfarmer.github.io/calculator/' target=_blank>click me</a>"
  sandbox="allow-popups">
</iframe>
```

You will see that the screen turns black, and if you open DevTools, you will see the error:

> Blocked script execution in 'https://ahfarmer.github.io/calculator/' because the document's frame is sandboxed and the 'allow-scripts' permission is not set.

This verifies what we said above, that windows opened from sandboxed iframes will inherit the sandbox properties. In addition, there's another feature: do you remember that the origin in the sandbox becomes null? Because of inheritance, the origin of the page opened with `window.open` will also become null.

What does this mean? It means that we can use a sandbox iframe + window.open to achieve:

1. Disable certain functions of any page
2. Let the origin of any page become null

As mentioned earlier, two different windows can exchange messages through `postMessage`, and when listening for messages, `event.origin` is checked to confirm whether it is legal:

``` js
window.onmessage = function(event) {
  if (event.origin !== 'https://example.com') return
}
```

However, some web pages will check like this:

``` js
window.onmessage = function(event) {
  if (event.origin !== window.origin) return
}
```

At this point, we can use the technique mentioned above to bypass the check, open the page with a sandbox iframe, and make its origin become `"null"`. Then we can use the window of the sandbox iframe itself to postMessage, so that `event.origin` is also `"null"`, thereby making the condition true. However, although doing so can bypass the check, even if XSS is obtained later, the things that can be done are still limited because the origin is `"null"`, so localStorage and cookies cannot be accessed.

There is a [soXSS challenge](https://github.com/terjanq/same-origin-xss) that uses this trick to solve it.

If you don't want the newly opened window to inherit the `sandbox` attribute, you can add `allow-popups-to-escape-sandbox`, so that the newly opened window will jump out of the sandbox:

``` html
<iframe
  srcdoc="<a href='https://ahfarmer.github.io/calculator/' target=_blank>click me</a>"
  sandbox="allow-popups allow-popups-to-escape-sandbox">
</iframe>
```

There was a problem that occurred before, that is, since `allow-popups-to-escape-sandbox` can jump out of the sandbox, it can be combined with `javascript:` to execute code, like this:

``` html
<iframe
  sandbox="allow-modals allow-popups allow-popups-to-escape-sandbox"
  srcdoc="<a target='_blank' href='javascript:window.opener.eval(`alert(location.href)`)'>click me</a>">
</iframe>
```

Details can be found in [Issue 1014371: Security: iframe sandbox can be worked around via javascript: links and window.opener](https://bugs.chromium.org/p/chromium/issues/detail?id=1014371) and [Gate javascript: navigation on sandboxing flags. #5083](https://github.com/whatwg/html/pull/5083) and the original [commit](https://chromium.googlesource.com/chromium/src.git/+/24134160cb7f395e2d82ddecdfe7ac0659c9477c).

Finally, let me also mention another thing similar to `window.origin`: `location.origin`, which is purely determined by the location to determine the origin, which is different from `window.origin`. According to the [specification](https://html.spec.whatwg.org/multipage/webappapis.html#dom-origin-dev):

> Developers are strongly encouraged to use self.origin over location.origin. The former returns the origin of the environment, the latter of the URL of the environment. Imagine the following script executing in a document on https://stargate.example/:

Then an example is given below to illustrate that `window.origin` is more reliable than `location.origin`:

``` js
var frame = document.createElement("iframe")
frame.onload = function() {
  var frameWin = frame.contentWindow
  console.log(frameWin.location.origin) // "null"
  console.log(frameWin.origin) // "https://stargate.example"
}
document.body.appendChild(frame)
```

But I think it still depends on the situation.

### allow-same-origin

Finally, we come to the last flag of the sandbox. As mentioned earlier, once the sandbox is added, the origin will become `"null"`, and even if JavaScript can be executed, cookies or localStorage cannot be obtained, which is actually very limited.

If you want to break through this limitation, you must add `allow-same-origin`. I used to be very confused about this flag and thought, "Does adding this flag make the iframe and parent window become the same origin?" But in my understanding, this flag is more like: "Keep the original origin". Below is a direct quote from the specification's precise description:

> The `allow-same-origin` keyword causes the content to be treated as being from its real origin instead of forcing it into a unique origin.

Take the following paragraph as an example, assuming that the URL of this page is: http://localhost:3000

``` html
<iframe
  sandbox="allow-same-origin allow-scripts allow-modals"
  srcdoc="<script>alert(window.origin)</script>"></iframe>
```

If `allow-same-origin` is not added, it will display `"null"`. However, if `allow-same-origin` is added, it will display `http://localhost:3000` as the original origin is preserved.

In addition, the specification also specifically warns that if you embed a same-origin webpage in an iframe and set `allow-same-origin allow-scripts` in the sandbox, the webpage in the iframe can remove the sandbox by itself, making it the same as with or without the sandbox, like this:

``` html
<iframe
  sandbox="allow-same-origin allow-scripts"
  srcdoc="<script>top.document.querySelector('iframe').removeAttribute('sandbox');location.reload();alert(1)</script>">
</iframe>
```

## Summary of iframes

I believe that for most developers, the following attributes should still be quite unfamiliar:

1. srcdoc
2. csp
3. sandbox

Only those who have used or dealt with related requirements may know about these things. For CTF, there are several features that I have seen or may be exploited:

1. Put `javascript:` in src to directly perform XSS
2. Add csp to the embedded page to block some function executions
3. Use the feature of the `srcdoc` attribute to put in an already escaped string, which will be restored to its original content at this time
4. Use the inheritance feature of `sandbox + window.open` to achieve "even if you cannot embed content with iframe, you can still change `window.origin`"

## window.open

After talking about iframes, let's continue to look at the `window.open` method, which has three optional parameters: `window.open(url, name, features)`, and it will return the opened window, and you can postMessage to this new window:

``` js
var win = window.open('https://blog.huli.tw', 'huliblog')

// 要先等 window 載入好
setTimeout(() => {
  win.postMessage("hello", '*')
}, 2000)
```

The newly opened window can be accessed by `window.opener`. I mentioned this feature before in [Starting a spec journey from SessionStorage](https://blog.huli.tw/2020/09/05/session-storage-and-html-spec-and-noopener/).

Then, the second parameter passed to `window.open` will be the name of this new window. For example, if I execute `console.log(window.name)` in the newly opened window, it will print `huliblog`.

This `window.name` is actually a very interesting feature. Usually, when we open a new link, we will do this: `<a href="https://example.com" target="_blank">open</a>`, using `target=_blank` to open a new window. However, this target can also be a string, and this string will be the name of the new window, like this:

``` html
<a
  href="https://example.com"
  target="example">
  open
</a>
```

If you open the console in this new window and log `window.name`, you will see the name we set, `example`.

What if this named window already exists? Let's try it out:

``` html
<a href="https://blog.huli.tw" target="blog">open link</a>
<button onclick="window.open('https://example.org/','blog')">open window</button>
```

Clicking on `<a>` will open a window named `blog` and redirect to my blog. Clicking the button will open a new window to another webpage, and the name is also `blog`. You can try clicking the link first and then the button, or vice versa.

In any case, the result is similar. When opening a new window, it will first check if there is a window with the same name. If there is, it will not open a new one, but will directly use that one. Therefore, in the example above, if you click the button to open a blog window first, and then click the link, it will not open a new window, but will only redirect the original window to the URL in `href`.

Apart from the target attribute of `<a>`, the target attribute of `<form>` can also specify the window name. The term used in the specification is "Valid browsing context name or keyword", and the keywords are the four well-known ones: `_blank`, `_self`, `_parent`, or `_top`.

According to the specification [7.1.5 Browsing context names](https://html.spec.whatwg.org/multipage/browsers.html#browsing-context-names), any string with at least one character that does not start with a U+005F LOW LINE character is a valid browsing context name. (Names starting with an underscore are reserved for special keywords.)

### Generating named windows and obtaining window references

There are several ways to generate named windows:

1. `<a target="">`
2. `<form target="">`
3. `<iframe name="">`
4. `<object name="">`
5. `<embed name="">`
6. `window.open(url, name)`

For the last four, you can directly obtain the reference of the opened window, like this:

``` html
<iframe name="w1" src="https://blog.huli.tw"></iframe>
<object name="w2" data="https://blog.huli.tw"></object>
<embed name="w3" src="https://blog.huli.tw"></embed>
<script>
  var w4 = window.open('https://blog.huli.tw')
  setTimeout(() => {
    console.log('w1', w1)
    console.log('w2', w2)
    console.log('w3', w3)
    console.log('w4', w4)
  }, 2000)
</script>
```

What about the first two? You can use the feature of `window.open` to obtain the window reference if the name already exists, like this:

``` html
<a target="blog" href="https://blog.huli.tw">open</a>
<button onclick="run()">get blog window</button>
<script>
  function run() {
    var blog = window.open('https://blog.huli.tw#abc', 'blog')
    console.log(blog)
  }
</script>
```

First, click "open" to open a new window, and then click the button. At this point, we use `window.open('https://blog.huli.tw#abc', 'blog')` to open a window with the same name. According to the specification:

> Opens a window to show url (defaults to "about:blank"), and returns it. target (defaults to "_blank") gives the name of the new window. If a window already exists with that name, it is reused.

Because there is a window with the same name, it will be reused. And we just added `#`, so it won't redirect. Although the focus will jump to the newly opened window, we can obtain the reference of the window opened with `<a target>` by this method (there is another way that won't jump, which is to give a non-existent scheme, like `xxxx://test`).

In addition, this named window should only be useful in the same browsing context. In other words, if I open two web pages A.html and B.html, open a window named "blog" in A.html, and then execute `window.open('', 'blog')` in B.html, I will not get the blog window opened in A.html, but will open a new one because A and B are in different browsing contexts.

But the situation is different when switching pages. It's quite interesting. Suppose I'm now at `http://localhost:5555/A.html` and I've opened a window named "blog", and then I navigate to `http://localhost:5555/B.html`:

``` html
<button onclick="run()">run</button>
<script>
  function run() {
    window.open('https://blog.huli.tw', 'blog')
    location = 'http://localhost:5555/B.html'
  }
</script>
```

Then I also open a window with the same name in B.html: `window.open('', 'blog')`. At this point, I will get the blog window opened in A.html, not a new one. Also, if I redirect from B.html to `https://blog.huli.tw`, and then execute `window.open('', 'blog')` in the console, I can still get the blog window opened in A.html.

But if I redirect to `https://example.org`, a new tab will be opened and I won't get the blog window. It seems that if the same page jumps to a page with the same origin as the opener or the opened window, it will be the same browsing context. This feature is quite interesting (it's time to study browsing context).

### Utilizing window.name

Sometimes, XSS is limited by length, for example, if the username has an XSS vulnerability, but only 32 characters can be used, we would want our payload to be as short as possible. To achieve this, we need to use other information to bring in the actual code we want to execute to control the length.

For example, you can put the code you want to execute after the `#` in the URL, and then write the payload as `eval(location.hash.slice(1))`.

`window.name` is a commonly used technique. We can set `window.name` on page A and then redirect to page B. At this point, the `window.name` of page B will be what we just set:

``` js
name = 'hello, world!'
location = 'https://example.org'
```

However, this trick only works on Chromium-based browsers (Chrome and Edge) because according to the specification, if the page being redirected to is not the same origin, the name should be cleared.

Chromium has a bug related to this: [Issue 706350: Clear browsing context name on cross site navigation or history traversal](https://bugs.chromium.org/p/chromium/issues/detail?id=706350&q=window.name&can=2), which has not been fixed since 2017. It was once fixed but caused other bugs, so it was reverted.

Safari was the first to implement this, and in January 2021, FireFox also implemented it, making Chromium an outlier. There is a great webpage that shows the testing status of each browser: https://wpt.fyi/results/html/browsers/windows/clear-window-name.https.html?label=master&label=experimental&aligned

### Detecting when a new window has finished loading

An iframe has an `onload` event that can be used to determine when it has finished loading. However, when using `window.open` to open a new window, there is no event to listen to (unless it is the same origin), so you don't know when it will finish loading.

But it's okay. If you open a cross-origin webpage, you can use the fact that accessing `window.origin` or other properties will cause an error to implement a simple polling mechanism:

``` js
var start = new Date()
var win = window.open('https://blog.huli.tw')
run()
function run() {
  try {
    win.origin
    setTimeout(run, 60)
  } catch(err) {
    console.log('loaded', (new Date() - start), 'ms')
  }
}
```

When the webpage has not finished loading, `win.origin` will be itself. It will only become the opened webpage after it has finished loading. Therefore, accessing `win.origin` after it has finished loading will cause an error due to cross-origin issues and be caught.

### Detecting whether a window with a certain name exists

Is there a way to detect whether a window with a certain name exists?

As mentioned earlier, if a named window is opened and a window with the same name already exists, it will not open a new window but will redirect to the existing one. We can use this difference to detect whether a window with a certain name exists, and we can also use the iframe sandbox mentioned earlier to prevent opening new windows.

The concept above is from [Easter XSS by @terjanq](https://easterxss.terjanq.me/writeup.html#Dark-Arts-solution), with some slight modifications to the code, only targeting Chrome:

``` html
<body>
  <a href="https://blog.huli.tw" target="blog">click</a>
  <button onclick="run()">run</button>
  <iframe
    name=f
    sandbox="allow-scripts allow-same-origin allow-popups-to-escape-sandbox allow-top-navigation">
  </iframe>
  <script>
    function run(){
      var w = f.open('xxx://abcde', 'blog')
      if (w) {
        console.log('blog window exists')
      } else {
        console.log('blog window not exists')
      }
    }
  </script>
</body>
```

## Conclusion

This article briefly describes some interesting features of iframes and windows, but some things are still not thoroughly researched, such as the related terms of browsing context and how to determine whether they are under the same browsing context. These will have to be absorbed slowly by reading the spec.

References:

1. https://developer.mozilla.org/en-US/docs/Web/HTML/Element/iframe#attr-sandbox
2. https://cloud.google.com/blog/products/data-analytics/iframe-sandbox-tutorial
3. https://www.w3.org/TR/2010/WD-html5-20100624/the-iframe-element.html
4. https://www.html5rocks.com/en/tutorials/security/sandboxed-iframes/
5. https://googlechrome.github.io/samples/allow-popups-to-escape-sandbox/
6. https://xsleaks.dev/

Please paste the Markdown content you want me to translate.
