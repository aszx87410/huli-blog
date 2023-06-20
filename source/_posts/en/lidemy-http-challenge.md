---
title: 'Behind the Scenes: Design and Easter Eggs of Lidemy HTTP Challenge'
date: 2019-05-18 20:10
tags: [Others]
categories:
  - Others
---

## Introduction

Recently, I created a small game called [Lidemy HTTP Challenge](https://lidemy-http-challenge.herokuapp.com/start) to help my students become more familiar with HTTP and API integration. The game requires players to obtain the correct token according to the instructions of each level. There are a total of fifteen levels, with the first ten being basic and the last five being advanced.

After some testing by friends and some adjustments and improvements, I let my students test it and found that the response was good. So I officially released this game to the [front-end community](https://www.facebook.com/groups/f2e.tw/permalink/2153812321322788/) so that everyone could participate.

If you haven't played it yet, I strongly recommend that you don't read this article because it will spoil the fun of playing the game (like a movie spoiler). I suggest you play it first, then come back and read this article to get a different experience.

Next, I will talk about the process of creating this game and the design of each level.

<!-- more -->

## Standing on the Shoulders of Giants

This technique of using games as a shell but filling it with technical content should not be unfamiliar to most people, at least not to me.

The idea of making a game actually came from a student who sent me this: [devtest](https://pretapousser.fr/devtest/), which is a French company's interview question. If you see a blank screen, don't worry, the webpage is not broken.

After completing the above game, I remembered that I was actually very familiar with this type of game. I played [高手過招](https://www.csie.ntu.edu.tw/~b94102/game/game.htm) and similar games like [Hack This Site!](https://www.hackthissite.org/) when I was a child.

Or there was a time when puzzle games were popular (not related to programming), and I once made one myself. At that time, I used the password-locked method of PIXNET articles to create levels, which is a very convenient method in retrospect.

Anyway, although I played them all when I was a child, I gradually forgot about this type of game as I grew up. The advantage of this type of game is that it is a game. If the game is well made, everyone will love it. And it is much more interesting than the usual question-and-answer or short-answer questions, so games are a good entry point.

After remembering the benefits of games, I decided to make one myself, and the theme was the Web API integration that my students were least familiar with!

## The Initial Idea

The initial idea was:

> I hope this is a game that you can play with curl.

Because I think it's cool that you can play this game with terminal and commands, without even opening a browser!

Therefore, in terms of presentation, I planned to use pure text from the beginning, without any links or fancy things. It's just a plain text file! If there are links, there won't be `<a>`, just a URL.

In terms of form, it is similar to other games that use checkpoints.

After roughly deciding on the form, it is time to decide what content each level should have. At first, I wanted to make twenty levels, but after listing the topics I wanted to appear, I realized that I could only make about six or seven levels.

The original plan is as follows:

1. CRUD must be included to make students familiar with the four basic operations of API integration.
2. Custom headers must be included.
3. Origin-related topics must be included.
4. User agent-related topics must be included.

The reason why the last three must be included is that I think they are also important in understanding HTTP and API integration.

Custom headers often bring additional information or are used for verification. Origin is to make students understand that the same origin policy is only related to browsers and has no restrictions outside of browsers. User agent is quite practical in work, and it is necessary to determine the user's browser or detect whether it is a search engine to do corresponding processing.

The things that need to appear are roughly thought out, and finally, it is the design of the content and token. If the content of the game is only "Please POST a piece of data to XXX," it would be too boring, so I set the scene to be that the player is a novice who goes to the library to help an old man solve some problems with the library information system.

As for the book data, I quickly crawled a website and did some processing, so the data part was quickly done.

After having the story, I also wanted to hide some Easter eggs in it. Rather than saying it is an Easter egg, it is more like some interesting little things that I think people might find. Therefore, there are some hidden things in the content and token of each level.

I remember that I spent about two days on the initial version. One day for designing levels and another day for writing code. The part of designing levels took longer because the implementation of the code was quite simple.

Next, let's take a look at the content of each level of the first ten levels!

Again, if you haven't completed it yet, I strongly recommend not to view it! Quickly go and play: [Lidemy HTTP Challenge](https://lidemy-http-challenge.herokuapp.com/start).

## Level 1

```
啊...好久沒有看到年輕人到我這個圖書館了，我叫做 lib，是這個圖書館的管理員
很開心看到有年輕人願意來幫忙，最近圖書館剛換了資訊系統，我都搞不清楚怎麼用了...
  
這是他們提供給我的文件，我一個字都看不懂，但對你可能會有幫助
先把這文件放一旁吧，這個待會才會用到
你叫做什麼名字呢？用 GET 方法跟我說你的 name 叫做什麼吧！
除了 token 以外順便把 name 一起帶上來就可以了
```

The first level is just to let everyone get the API documentation and familiarize themselves with the fact that some levels will require information to be directly carried in the URL. Therefore, the first level is just to let everyone familiarize themselves with the environment.

After passing in the name, you can get the token for the second level.

Actually, at the beginning, many people got stuck here because the instructions were not clear, so some people thought they had to call the API or something. Later, I changed the instructions and tried to make them as clear as possible, and also added a hint function.

## Level 2

```
我前陣子在整理書籍的時候看到了一本我很喜歡的書，可是現在卻怎麼想都想不起來是哪一本...
我只記得那本書的 id 是兩位數，介於 54~58 之間，你可以幫幫我嗎？
找到是哪一本之後把書的 id 用 GET 傳給我就行了。
```

The ID range for this level is 54-58, and the original intention was to let everyone try one by one, without any other methods.

The hidden Easter egg here is that the book with ID 56 is the book "5566 - Seriously" by Zheng Peifen:

```
{"id":56,"name":"5566－認真","author":"鄭佩芬","ISBN":"0614361311"}
```

So the token for the next level will be `5566NO1`.

## Level 3

```
真是太感謝你幫我找到這本書了！
  
剛剛在你找書的時候有一批新的書籍送來了，是這次圖書館根據讀者的推薦買的新書，其中有一本我特別喜歡，想要優先上架。
書名是《大腦喜歡這樣學》，ISBN 為 9789863594475。
  
就拜託你了。
新增完之後幫我把書籍的 id 用 GET 告訴我。
```

This level is just testing whether you know how to use POST.

There is a small detail that the original API documentation did not write clearly about how to POST, whether the content type is form or JSON? So later I added this part to avoid ambiguity.

## Level 4

```
我翻了一下你之前幫我找的那本書，發現我記錯了...這不是我朝思暮想的那一本。
我之前跟你講的線索好像都是錯的，我記到別本書去了，真是抱歉啊。
我記得我想找的那本書，書名有：「世界」兩字，而且是村上春樹寫的，可以幫我找到書的 id 並傳給我嗎？
```

This level tests whether you can use the parameters of the API to query books, but cheating by searching locally is also possible.

I love Haruki Murakami, and I have a friend who loves the book "The End of the World and the Cold and Cruel Land". So I put it in. In order to avoid only one result when searching for "world", I also found several other books with this keyword and put them in.

The token for the next level, "HarukiMurakami", is the name of Haruki Murakami.

## Level 5

```
昨天有個人匆匆忙忙跑過來說他不小心捐錯書了，想要來問可不可以把書拿回去。
跟他溝通過後，我就把他捐過來的書還他了，所以現在要把這本書從系統裡面刪掉才行。
那本書的 id 是 23，你可以幫我刪掉嗎？
```

This level is just testing the use of DELETE, with no difficulty.

The hidden Easter egg here is that the book he donated by mistake is the photo album of Chicken Cutlet Girl, so he wants to get it back quickly. This also corresponds to the token for the next level: `CHICKENCUTLET`.

## Level 6

```
我終於知道上次哪裡怪怪的了！
照理來說要進入系統應該要先登入才對，怎麼沒有登入就可以新增刪除...
這太奇怪了，我已經回報給那邊的工程師了，他們給了我一份新的文件：
這邊是帳號密碼，你先登入試試看吧，可以呼叫一個 /me 的 endpoint，裡面會給你一個 email。
把 email 放在 query string 上面帶過來，我看看是不是對的。
帳號：admin
密碼：admin123
```

For beginners, this is actually a more challenging level.

This level tests whether you know how to put content in the header and how to use HTTP basic authorization based on data. The main purpose is to let everyone know one of the authentication methods of HTTP.

## Level 7

```
那邊的工程師說系統整個修復完成了，剛好昨天我們發現有一本書被偷走了...
這本書我們已經買第五次了，每次都被偷走，看來這本書很熱門啊。
我們要把這本書從系統裡面刪掉，就拜託你了。
對了！記得要用新的系統喔，舊的已經完全廢棄不用了。
書的 id 是 89。
```

Actually, I just added a level to delete data because I ran out of ideas. A small episode here is that there was no "By the way! Remember to use the new system, the old one is completely obsolete." at first, which caused some people to still use the old API, so I added it to avoid confusion.

If you actually go to see this popular book, you will find that it is "Following the Moon: Han Kuo-yu's Night Raid Spirit and Enterprising Life", corresponding to the token for the next level: `HsifnAerok`, which is KoreanFish spelled backwards.

## Level 8

```
我昨天在整理書籍的時候發現有一本書的 ISBN 編號跟系統內的對不上，仔細看了一下發現我當時輸入系統時 key 錯了。
哎呀，人老了就是這樣，老是會看錯。
  
那本書的名字裡面有個「我」，作者的名字是四個字，key 錯的 ISBN 最後一碼為 7，只要把最後一碼改成 3 就行了。
對了！記得要用新的系統喔，舊的已經完全廢棄不用了。
```

This level is just testing finding and modifying data, with nothing special.

The token for the next level, "NeuN", is German for nine.

## Level 9

```
API 文件裡面有個獲取系統資訊的 endpoint 你記得嗎？
工程師跟我說這個網址不太一樣，用一般的方法是沒辦法成功拿到回傳值的。
  
想要存取的話要符合兩個條件：
1. 帶上一個 X-Library-Number 的 header，我們圖書館的編號是 20
2. 伺服器會用 user agent 檢查是否是從 IE6 送出的 Request，不是的話會擋掉
  
順利拿到系統資訊之後應該會有個叫做 version 的欄位，把裡面的值放在 query string 給我吧。
```

This level tests two things:

1. Whether you can pass custom headers
2. Whether you know how to change the user agent, and whether you know what the user agent represents

These are the elements that I must put in, as I think they are important.

I want students to know that the user agent actually has many functions, one of which includes letting the server know about your browser and operating system, etc.; I also want them to know that these things can be forged.

Originally, the server was set to check whether the request was sent from Safari, but people using Macs could pass the level by using Safari, so later it was changed to use IE6. If you want to install IE6's VM, then I give up XD

The token for the next level is `duZDsG3tvoA`, which is the YouTube video ID, corresponding to Jay Chou's "Peninsula Iron Box". Because I really like this song, and it has something to do with the book.

## Level 10

```
時間過得真快啊，今天是你在這邊幫忙的最後一天了。
  
我們來玩個遊戲吧？你有玩過猜數字嗎？
  
出題者會出一個四位數不重複的數字，例如說 9487。
你如果猜 9876，我會跟你說 1A2B，1A 代表 9 位置對數字也對，2B 代表 8 跟 7 你猜對了但位置錯了。
  
開始吧，把你要猜的數字放在 query string 用 num 當作 key 傳給我。
```

Originally, I wanted everyone to really play the guessing game, and it was expected to take about five or six guesses to pass the level. But I didn't write the judgment logic well, so if you pass in a number or a repeated number, I won't block it, or if you want to try all 9999 combinations directly, no one will stop you, so there are many ways to solve this problem.

So far, this is the content of the first ten levels.

## First Optimization

After completing the first ten levels, I let some friends try it out and the feedback was good, but I also found some problems, some of which I have already mentioned above, such as:

1. The instructions for the first level are not clear, and it is unclear where the name should be passed.
2. There is no prompt to use the new API, and it is thought that the old one can be used.
3. If the browser restricts Safari in a certain level, it is easy for Mac users.

The above problems can basically be improved by strengthening the textual description, but there is still a bigger problem:

> Stuck

Although it is common for people to get stuck, I don't want everyone to be stuck all the time. After all, the ultimate goal of this game is actually to learn, and fun is just an added value for me. But I can't destroy the game experience and explain the answer directly, so I must provide a way for them to see the hints.

You may ask me why not use white text for the hints, it's so troublesome to add `&hint=1`. You may have forgotten that I said at the beginning that I wanted curl to be able to play this game, so white text is useless.

Anyway, the hint function was added in the end, making the game more complete and the experience better.

The game originally ended here, but I happened to have some inspiration, so I continued to do some levels. Let's talk about the advanced levels below.

## Level 11

```
嘿！很開心看到你願意回來繼續幫忙，這次我們接到一個新的任務，要跟在菲律賓的一個中文圖書館資訊系統做串連
這邊是他們的 API 文件，你之後一定會用到。
  
現在就讓我們先跟他們打個招呼吧，只是我記得他們的 API 好像會限制一些東西就是了...
```

This level is the one mentioned at the beginning that must be done for the origin-related levels. It is placed in the advanced levels because I am afraid it is too difficult for my students, so I put it here.

In short, I want everyone to understand that even if the server checks the origin, the client can easily forge it. And this has nothing to do with the browser's CORS. Everyone should be very clear that sending a request from the browser and sending a request by themselves are two very different things. The former will have many restrictions, while the latter will not.

The token for the next level is `r3d1r3c7`, which is the `redirect` in [leet](https://en.wikipedia.org/wiki/Leet), hinting at the solution for the next level.

## Level 12

```
打完招呼之後我們要開始送一些書過去了，不過其實運送沒有你想像中的簡單，不是單純的 A 到 B 而已
而是像轉機那樣，A 到 C，C 才到 B，中間會經過一些轉運點才會到達目的地...算了，我跟你說那麼多幹嘛
  
現在請你幫我把運送要用的 token 給拿回來吧，要有這個 token 我們才能繼續往下一步走
```

This level is also a level that I really wanted to put in later. I think this concept is quite interesting. By stuffing something in the middle of the redirect process, it forces everyone to understand what the principle of server-side redirect is (301 and 302 status codes).

If you don't understand why you can redirect and the principle behind it, you won't be able to solve this problem.

The token for the next level is `qspyz`, which becomes `proxy` after shifting one character to the left, hinting at the solution for the next level.

## Level 13

```
太好了！自從你上次把運送用的 token 拿回來以後，我們就密切地與菲律賓在交換書籍
可是最近碰到了一些小問題，不知道為什麼有時候會傳送失敗
我跟他們反映過後，他們叫我們自己去拿 log 來看，你可以幫我去看看嗎？
從系統日誌裡面應該可以找到一些端倪。
```

This level is testing the use of a proxy, because the server checks whether the user's IP is from the Philippines.

The method of checking is using [node-geoip](https://github.com/bluesmoon/node-geoip):

``` js
advancedRouter.get('/logs', (req, res) => {
  const ip = req.ip || ''
  const info = geoip.lookup(ip) || {}
  if (info.country === 'PH') {
    res.end(text.lv13.reply)
  } else {
    res.end(text.lv13.wa)
  }
})

```

So as long as you find a proxy in the Philippines to send a request, you can pass the level.

However, there are two unexpected things about this level. The first thing is that many people will try to forge the `Accept-Language` header, which I didn't think of at all (but it doesn't matter).

The second thing is that there is another solution to this problem, which is to forge `X-Forwarded-For`, which is something I didn't think of at all.

I have set `app.set('trust proxy', true)` in Express, so when getting the user's IP, if there is the `X-Forwarded-For` header, the information here will be used.

I happened to read a similar article recently: [The Cause and Prevention of the X-Forwarded-For Header Forgery Vulnerability](https://xxgblog.com/2018/10/12/x-forwarded-for-header-trick/index.html).

Although it is not the solution I originally intended, I think this solution is more interesting, so I didn't specifically fix it.

## Level 14

```
跟那邊的溝通差不多都搞定了，真是太謝謝你了，關於這方面沒什麼問題了！
不過我老大昨天給了我一個任務，他希望我去研究那邊的首頁內容到底是怎麼做的
為什麼用 Google 一搜尋關鍵字就可以排在第一頁，真是太不合理了
  
他們的網站明明就什麼都沒有，怎麼會排在那麼前面？
難道說他們偷偷動了一些手腳？讓 Google 搜尋引擎看到的內容跟我們看到的不一樣？
  
算了，還是不要瞎猜好了，你幫我們研究一下吧！
```

This level wants everyone to know that not only browsers, but also various crawlers will bring specific User-Agent, so the server can still output different information for different UA (although it is not recommended).

For example, an SPA can only enable server-side rendering for Google search engines and Facebook to output content, and client-side rendering for ordinary users.

Or like the HTTP Challenge website, it has processed different UA (because the website is all text, but I hope to have a custom title and description when shared on Facebook):

``` js
// base on UA return differect result
router.get('/start', (req, res) => {
  const UA = req.header('User-Agent') || ''
  if (UA.indexOf('facebookexternalhit') >= 0 || UA.indexOf('Googlebot') >= 0 ){
    res.end(text.seo)
  } else {
    res.end(text.start.intro)
  }
})
```

But it seems a bit strange, I don't know if it succeeded.

This is the last level, and Level 15 is the conclusion.

## Second Optimization

After completing the advanced levels, the description part has actually been changed a bit, for example, some students in Level 14 thought it was related to Chrome (thinking of Google only reminds them of Chrome XD), so I specifically emphasized that it is "Google search engine" that they should look for in this direction.

One of the most surprising solutions to me was the `X-Forwarded-For` in level 13.

After it was made public, a friend suggested that I should put a gist at the end for people to leave comments. I was surprised because I didn't think of that before.

I had thought about adding a leaderboard or a comment board so that people who completed the game could leave a message as a souvenir, but it was too troublesome to implement and I was too lazy to do it. It was only when my friend reminded me that I realized that gist already has a built-in comment function, so I just put a gist there!

Therefore, the early players did not have a gist to leave comments on, it was added later.

## Conclusion

I am very happy to be able to package this knowledge into a game and share it with everyone, and the feedback seems to be quite good. Although some people are looking forward to new levels, I currently have no inspiration.

What is more likely to happen in the future is to make an HTML, CSS, and JavaScript version, which is similar in type, but the solutions and knowledge points for each level are different. I will share it with you when the time comes.

Thanks to the friends who helped me test it early on, and thanks to everyone who enjoyed the game with me. Below are some related experiences of completing the game, you can take a look if you are interested:

1. [One-day librarian: HTTP Challenge](https://github.com/jijigo/notes/issues/24)
2. [HTTP_Game攻略(一)](https://pvt5r486.github.io/note/20190513/2430981100/)
3. [Lidemy HTTP 圖書館小弟加班(V2)](http://enter3017sky.tw/article.php?id=124)
4. [小挑戰 http game 解題思路心得想法](https://medium.com/@hugh_Program_learning_diary_Js/%E5%B0%8F%E6%8C%91%E6%88%B0-http-game-%E8%A7%A3%E9%A1%8C%E6%80%9D%E8%B7%AF%E5%BF%83%E5%BE%97%E6%83%B3%E6%B3%95-8007cb7d2e81)
