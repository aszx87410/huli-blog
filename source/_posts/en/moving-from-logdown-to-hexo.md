---
title: "Experience of Moving Blog: From Logdown to Hexo"
catalog: true
date: 2017-09-03 21:34:38
subtitle: Should have moved earlier...
tags: [Others]
categories:
  - Others
photos: /img/moving-from-logdown-to-hexo/cover-en.png
---

# Preface

Finally, it's done!

It took me a whole day to deal with the moving stuff, which was really troublesome, and I encountered many small problems along the way. So I wrote this article to record my experience.

<!--more-->

# Why Move?

As you know, I know, and the one-eyed dragon knows, Logdown is basically a stagnant product. It hasn't been updated for a long time, and it seems that it won't be updated anymore.

I really like Logdown because I think it's very convenient and handy to use. However, since it is a product that has stopped maintenance, there are some risks if it continues to be used, such as the blog suddenly crashing or all articles disappearing one day.

So, I took advantage of the recent free time to quickly move the entire blog out to avoid any disasters that might happen later.

But actually, I didn't really want to move... After all, moving is really troublesome, and this time I also changed to a brand new domain, which is good in the long run, but it also means giving up the traffic I accumulated before.

# The First Challenge: Exporting Articles

There is a function in the Logdown backstage that can export all the blog's articles and send them to your mailbox, but when I clicked it several times, it only showed a notification saying "The articles will be sent to your mailbox in 5 minutes", and then I didn't receive anything.

So I guess either it's broken, or my articles are too many and the file size is too large, so it's GG. But no matter which one it is, I won't be able to use this function.

As an engineer, I immediately thought of writing a crawler or something, but after studying the structure of Logdown, I gave up because all the data returned by its APIs are in HTML... I don't want to parse it myself...

Just when I was desperate, I suddenly found a "Download in Markdown format" function in the backstage, which can download a single article. After trying this function and confirming that it works, I immediately thought of a solution:

> As long as I have all the download links for the articles, I can write a script to download them all.

## Step One: Get the URLs

Go to the Logdown backstage (http://logdown.com/account/posts) and scroll down until there are no more articles.

Open Chrome devtool and execute the following code, then right-click and save the result.
``` js
var a = Array.prototype.map.call(document.querySelectorAll('a'), item => item.getAttribute('href')).filter(item => item.indexOf('/raw') >= 0);for(var k of a) {console.log('"'+k+'"')}
```

If nothing unexpected happens, the console should display results like this:

``` js
....
VM192:1 "/account/posts/294284-javascript-redux-middleware-details-tutorial/raw"
VM192:1 "/account/posts/294037-javascript-redux-basic-tutorial/raw"
VM192:1 "/account/posts/293940-javascript-redux-model-real-world-browserhistory-not-found/raw"
```

After replacing the annoying string in front of it, you will get the URLs of all articles.

## Step Two: Download

But after getting the URLs, how do we download so many URLs?

It's very simple. We can write a bash script ourselves to do it! The core code is to use wget to grab the article. Here, the session key can be found by looking at the value of the cookie in Chrome:

``` bash
wget --heade="Cookie:_logdown_session=xxxx;" http://logdown.com/account/posts/2223627-review-the-classical-sort-algorithm-with-javascript/raw -O review-the-classical-sort-algorithm-with-javascript.md
```

Complete script:

``` bash
declare -a arr=(
"/account/posts/2223627-review-the-classical-sort-algorithm-with-javascript/raw"
"/account/posts/2223612-dom-event-capture-and-propagation/raw"
"/account/posts/2223601-http-cache/raw"
"/account/posts/2223581-ajax-and-cors/raw"
)

for i in "${arr[@]}"
do
  url="http://logdown.com"${i}
  name=`echo $url | sed "s/.*posts\/[0-9]*[-]//g" | sed "s/\/raw//g"`
  wget --heade="Cookie:_logdown_session=xxx;" $url -O $name".md"
done
```

Replace the URLs below with the URLs obtained from Chrome, and replace the session with your own, and you're done downloading all the articles!

It's great to be an engineer.

# The Second Challenge: Fixing Article Formats

The articles downloaded from Logdown still need to add some meta tags to run normally on Hexo, and I also want to fix the tags. This part was completely done manually... I fixed about two hundred articles because I couldn't automatically add tags. (It's possible to write a program to do it, but I'm too lazy to do it.)

There is also a place where I used the syntax forbidden by Hexo in some articles, which is the two curly braces. Hexo reports an error directly, but it doesn't tell me which article it is. So I had to use binary search to keep removing articles to see where the problem was.

# The Third Challenge: Table of Contents Broken

Now you can see the TOC on the right, which is a feature I really like, but I don't know why it's broken. After tracing the code of Hexo myself, I found a strange problem, which is that cheerio cannot grab the id of the span, so all the links become undefined.

As an engineer, of course, I can fix these small issues myself, so I fixed two small places:

``` js
// 原本的
var $ = cheerio.load(str);

// 改過的，加上 decodeEntities 處理中文
// https://cnodejs.org/topic/54bdd639514ea9146862ac37
var $ = cheerio.load(str, {decodeEntities: false});

// 原本的，會抓不到 id
var id = $(this).attr('id');

// 自己加上下面這一段用 Regexp 抓出來
if (!id) {
  var temp = $(this).html().match(/id="(.*)">/);
  if (temp && temp[1]) {
    id = temp[1];
  }
}
```

It's great to be an engineer.

# Conclusion

The template used this time is: [hexo-theme-beantech](https://github.com/YenYuHsuan/hexo-theme-beantech), which I think is a very good layout. However, I also made some small changes myself.

After experiencing this move, I feel that Hexo (blog system) + Github Page (Hosting) + Cloudflare (https) is the best practice for engineers to write blogs, all free solutions, and all necessary things are available at once, which is great.

By the way, it can be changed to cooperate with CI to do automatic deployment in the future, but let's study that later!
