---
title: 'The Evolution of Web Scraping on Medium'
date: 2019-07-12 20:10
tags: [Others]
categories:
  - Others
---

## Introduction

A few days ago, I posted an article on Medium titled [Medium Chinese Writers' Follower Ranking and Unprofessional Data Analysis](https://medium.com/@hulitw/medium-analysis-40752b9efa03), in which I used Node.js to write a simple web scraper and analyzed the data.

Although I briefly mentioned the data source of the web scraper in the original article, I did not elaborate much on the technical aspects. In fact, I encountered some difficulties while writing the Medium web scraper. Instead of teaching everyone how to write a Medium web scraper, I think it would be more interesting to share my experience and the solutions I found to the problems I encountered while writing the web scraper.

Therefore, this article is intended to document my experience of writing the Medium web scraper, and also includes some tutorial elements. After reading this article, you should be able to write a similar web scraper, or at least not be confused when looking at the source code.

Although the web scraper I eventually wrote was related to user data, I actually started with the article list because I had a need to scrape all of my own articles.

The reason for this need is that the built-in functionality of Medium is actually quite poor. It is difficult to find all the articles posted by an author, or it is difficult to see them at a glance. Therefore, early articles were difficult to find except through Google.

So I manually created an [index of articles](https://aszx87410.github.io/blog/medium) and organized all the articles I had previously posted. But as an engineer, this is clearly something that can be done with code! So I wanted to try writing a web scraper for the article list.

<!-- more -->

## First Attempt: Finding the Data Source

For me, the first and most difficult step in web scraping is finding the data source. Once this step is completed, everything else is relatively easy.

If you can get the Medium API, that would be the best. If not, you have to use something like puppeteer to scrape the HTML and parse it yourself.

Scrolling through the article list on Medium and opening the devtool, you can see that Medium uses GraphQL:

<img width="792" alt="p1" src="https://user-images.githubusercontent.com/2755720/61093603-2e954300-a400-11e9-9e70-acd06b97a6a8.png">


This is troublesome... I am not very familiar with GraphQL, and it takes time to study its data structure. So at that time, I temporarily gave up this route and decided to try using puppeteer.

## Second Attempt: Puppeteer

If you don't know what puppeteer is, I'll briefly introduce it here. You can think of puppeteer as automatically opening a browser for you, and you can write code to manipulate this browser. For example, if I want to open a page and execute JS on this page, etc., then using puppeteer, the principle of web scraping is to open a certain page, execute a piece of JS, and get the data on the page.

Puppeteer is easy to use. Just find an existing example and look at the syntax, modify it, and you can use it directly. After studying the HTML structure a bit, I wrote the following code:

``` js
const puppeteer = require('puppeteer')
  
async function main() {
  const username = 'hulitw'
  const url = 'https://medium.com/@' + username
  
  const browser = await puppeteer.launch({
    headless: true
  })
  
  // 造訪頁面
  const page = await browser.newPage()
  await page.goto(url, {
    waitUntil: 'domcontentloaded'
  })
  
  // 執行準備好的 script 並回傳資料 
  const data = await page.evaluate(mediumParser)
  console.log(data)
  
  await page.close()
  await browser.close()
}
  
function mediumParser() {
  
  // selector 是透過觀察而得來的
  const elements = document.querySelectorAll('section > div:nth-child(2) > div > div')
  const result = []
  for (let i = 0; i < elements.length; i++) {
    const h1 = elements[i].querySelector('h1')
    const a = elements[i].querySelectorAll('a')
    if (h1) {
      result.push({
        title: h1.innerText,
        link: a[3].href
      })
    }
  }
  return result
}
  
main()
```

As long as you observe the HTML and CSS rules, you can get the data you want. But Medium is difficult to scrape because it uses [functional CSS](https://blog.techbridge.cc/2019/01/26/functional-css/) in the class name, and the class names are processed programmatically, so they may be different when Medium is updated.

So in the end, I had to start with the HTML structure to extract the articles.

After solving this problem, there is another problem, which is infinite scrolling. Like many web pages, Medium needs to scroll down continuously to load new articles, and the rule that needs to be observed here is when to stop scrolling.

After observation, I found that when the published articles are loaded, the `Highlighted by xxx` block will be displayed. Therefore, this element can be used as the termination condition.

Then you can write a piece of code that keeps scrolling down until all articles are loaded:

``` js
/*
  要用的話就是： await scroll(page)
*/
  
function getArticlesCount() {
  const elements = document.querySelectorAll('section > div:nth-child(2) > div > div')
  return elements.length
}
  
async function scroll(page) {
  await page.evaluate('window.scrollTo(0, document.body.scrollHeight)')
  try {
  
    // 終止條件
    await page.waitForSelector('h4 ~ p', {
      timeout: 1000
    })
  } catch(err) {
  
    // 印出目前抓到的文章數目
    const count = await page.evaluate(getArticlesCount);
    console.log(`Fetching... ${count} articles`)
  
    // 繼續往下捲動
    await scroll(page);
  }
}
```

In order to let me see the progress on the console (to confirm that there are no bugs in the program), I added a piece of code that prints the number of articles on the screen every time it scrolls.

At this point, you can get all the titles and links of the user's articles.

What about the publication date? Can you get it?

Yes, I can, but it's complicated. You can see from the Medium screenshot below:

[Image]

If the article was published this year (2019), the year won't be displayed. Otherwise, the publication year will be shown. Therefore, special processing is required here, and only the date can be obtained, not the exact time of publication.

At this point, I got lazy and decided to switch to studying the API instead. 

## Third Attempt: Puppeteer + API

As I mentioned earlier, I wasn't familiar with GraphQL API at the time, so I gave up on it temporarily. However, after trying out Puppeteer, I came up with a new idea.

In Puppeteer, you can add an event listener for network responses. When the page loads the article, it will definitely call the API to retrieve the article. Isn't this much easier? I don't have to figure out how to call the API myself. I let the page call the API itself, and I just listen to the response and study its format!

The code looks something like this:

``` js
const apiResponses = []
  
page.on('response', async (response) => {
    if (response._url.indexOf('graphql') < 0) return
    const json = await response.json()
    try {
      const post = parsePosts(json)
      apiResponses.push(...post)
    } catch (err) {
    }
})
  
function parsePosts(json) {
  const result = []
  try {
  
    // 研究到一半沒做完
    const streams = json.data.user.profileStreamConnection.stream
    for (stream of streams) {
      if (stream.itemType.__typename === 'StreamItemCompressedPostList') {
  
      }
    }
  } catch (err) {
  
  }
}
```

Each time a new response comes in, I can parse it and add it to an array. Finally, I will get the complete data from the API.

But then I found out that this approach wouldn't work either.

Why? Because when the page is first loaded, the HTML returned from the server already contains the data for the first few articles. It's only when you scroll down that it uses AJAX to load new articles. This means that it's impossible to use the AJAX response to get all the article data, as you won't be able to get the data for the first few articles.

At this point, I was a bit discouraged and thought that I had spent two days writing something that couldn't be used. I gave up on trying to retrieve the article list and decided to focus on what I really wanted to get.

The need to retrieve the article list actually came up suddenly. Before that, there was something else I wanted to get: followers. I wanted to count the number of followers for Taiwanese writers and see where I ranked (just to satisfy my vanity).

After failing to retrieve the article list, I tried to use a similar approach to retrieve followers. However, I found that this method was too inefficient. If I loaded 25 followers each time I scrolled, it would take 40 scrolls to load 1000 followers.

If I couldn't do it myself, the answer was obvious: Google, please help me!

## Fourth Attempt: Google

I searched for "medium follower api" on Google, and the first search result was the official API, which was almost useless and required me to send an email to customer service to apply.

But the second search result caught my eye. It was a gist file: [Medium API: get number of followers for User · GitHub](https://gist.github.com/newhouse/843c444ddefe084ea7f01603627dbcfd).

The code was only fifty lines long, very short. The most important line was:

``` js
// BUILD THE URL TO REQUEST FROM
function generateMediumProfileUri(username) {
  return `https://medium.com/@${username}?format=json`;
}
```

What! It turns out that if you add `?format=json` to the URL, you can get the data in JSON format. This is amazing.

After putting the data into [JSON Formatter](https://jsonformatter.curiousconcept.com/), you can see the general structure:

[Image]

Here, you can get the user's profile information and some articles they've written, as well as our target: followers!

Let's take a look at what user information we can get:

``` js
"user":{  
   "userId":"f1fb3e40dc37",
   "name":"Huli",
   "username":"hulitw",
   "createdAt":1487549030919,
   "imageId":"1*WQyJUJBQpBNIHH8GEWE6Sg.jpeg",
   "backgroundImageId":"",
   "bio":"自學程式，後來跑去唸哲學系但沒念完，前往新加坡工作了兩年半後決定放一年的假，到處旅遊。喜歡教學，發現自己好像有把事情講得簡單又清楚的能力，相信分享與交流可以讓世界更美好。\bMedium 文章列表請參考：https://aszx87410.github.io/blog/medium",
   "allowNotes":1,
   "mediumMemberAt":1542441600000,
   "isNsfw":false,
   "isWriterProgramEnrolled":true,
   "isQuarantined":false,
   "type":"User"
}
```

In addition to basic self-introduction and name, you can also get the time when the user became a Medium paid member and the time when the user became a Medium member. There's also an interesting flag: isNsfw.

The only thing missing is the list of followers.

Here, I tried the same method and added the parameter `https://medium.com/@hulitw/followers?format=json` to the Medium URL, and I actually got something! In the response, I found the data for 10 followers.

Once we have the data, we can confirm that this API is useful. Next, we jump directly to the paging section at the bottom of the response:

``` js
"paging":{  
   "path":"https://medium.com/_/api/users/f1fb3e40dc37/profile/stream",
   "next":{  
      "limit":10,
      "to":"10590c54e527",
      "source":"followers",
      "page":2
   }
}
```

The path part looks like an API URL, and `next` should be a parameter. Try adding these parameters to the URL: https://medium.com/_/api/users/f1fb3e40dc37/profile/stream?limit=10&to=10590c54e527&source=followers&page=2, and only follower-related data appears!

<img width="660" alt="p4" src="https://user-images.githubusercontent.com/2755720/61093627-440a6d00-a400-11e9-9489-1eb6b1e49d62.png">

Try changing the `limit` value, and it seems that the maximum value should be 25, and 25 pieces of data can be obtained at a time. Changing the `page` value has no effect, so change the `to` value, and new data can be successfully obtained. It seems that the pagination mechanism is cursor-based.

After several attempts, we finally got two API URLs, one for obtaining detailed personal information and the other for obtaining a list of followers!

After determining the data source, we can start thinking about the crawler architecture.

## Crawler Architecture

How can we crawl as many Taiwanese writers as possible?

The first problem is that we need to expand the scope a bit, because there may be writers from Hong Kong or China among Chinese writers, and it is difficult for the program to distinguish where they come from, especially Hong Kong and Taiwan, because they both use traditional Chinese.

To avoid making the problem more complicated, we only need to be able to capture "Chinese users".

So how can we capture the most Chinese users? A very simple strategy is that we assume that the followers of Chinese users should all be Chinese users, so we just need to start from a user and put all of his followers into a queue, and keep doing this.

In text, it is simplified as follows:

1. Take a user out of the queue
2. Write his data to the database
3. Put all of his followers into the queue
4. Go back to step 1

This way, we can infinitely extend from one user, and theoretically, we can obtain data from a large number of users. The reason why we choose followers (people who follow me) instead of following (people I follow) is that the users I follow may come from other countries, such as foreign engineers, but because I don't write in English, foreign engineers should not come to follow me. This way, we can limit users to Chinese, which meets our goals.

Next is the system architecture part, which will have different methods depending on the efficiency you want to achieve.

For me, the most efficient way is to find a service that is very suitable for use as a queue, such as redis, and the database part can use MySQL or any software you are familiar with. The advantage of this is that you can open different machines, and each machine is a worker. For example, if you open five machines, there will be five workers constantly taking things out of the queue and putting followers in.

The reason why so many machines are opened instead of many threads or processes is because of the problem of rate limiting. Generally, APIs have traffic restrictions. If you send too many requests from the same IP, you will be banned or unable to get a response for a period of time. Therefore, opening more processes and threads is useless, and only different machines can be opened to solve the problem (or if there is a way to change the IP).

Later, because I didn't care about efficiency and was too lazy to open many machines, I only planned to open one and let it crawl slowly. If there is only one worker, the queue part can also be simplified. Here, I also use MySQL to implement a simple queue, making the entire crawler architecture very simple.

Let's take a look at the database structure:

### Users

| id     | userId    | username                      | name       | bio  | follower | fr   | mediumMemberAt     | createdAt      | 
|--------|-----------|-------------------------------|------------|------|----------|------|--------------------|----------------|
| Auto-increment ID | User ID | Add @ in front to get the profile URL | Username | Bio | Number of followers | Category | Time of becoming a paid member | Time of joining |

### Queue

| id     | userId    |
|--------|-----------|
| Auto-increment ID | User ID |

The execution process of the program is as follows:

1. Take out a userId from the Queue.
2. If the userId already exists in Users, go back to step 1.
3. Write the user's data into Users.
4. Put all of the user's followers into the Queue.
5. Go back to step 1.

When taking out from the queue, make sure that the user has not been crawled yet. If they have, skip them and put all of their followers back into the queue. This way, the program will keep running until there is nothing left in the queue.

After designing the architecture, we can start coding!

## First Version of the Crawler

First, we need a queue that can push and pop, and can determine whether the current userId has already been crawled. This is very suitable for implementation using a class:

``` js
class Queue {
  constructor(conn) {
    this.conn = conn
  }
  
  get() {
    return new Promise((resolve, reject) => {
      this.conn.query('SELECT userId from Queues limit 1', (error, results) => {
        if (error) {
          console.log(error)
          return reject(error)
        }
        if (results.length !== 1) {
          return resolve(null)
        }
        const data = results[0]
        this.conn.query('DELETE from Queues where userId=?', [data.userId], (err, results) => {
          if (error) {
            console.log(error)
            return reject(error)
          }
          return resolve(data.userId)
        })
      });
    })
  }
  
  check(uid) {
    return new Promise((resolve, reject) => {
      this.conn.query('SELECT userId from Users where userId=?', [uid], function (error, results) {
        if (error) {
          return reject(error)
        }
        if (results.length > 0) {
          return resolve(false)
        }
        return resolve(true)
      });
    })
  }
  
  push(list) {
    return new Promise((resolve, reject) => {
      const values = []
      for (let item of list) {
        values.push([item])
      }
      this.conn.query(`
        INSERT IGNORE INTO Queues (userId) VALUES ?`, [values], (err) => {
          if (err) {
            // console.log(err)
          }
          resolve()
        }
      )
    })
  }
}
```

After having the queue, we can write the main logic. The structure of the main program will look like this:

``` js
var connection = mysql.createPool({
  connectionLimit : 10,
  host     : process.env.host,
  user     : '',
  password : '',
  database : 'medium',
  charset: 'utf8mb4'
})

async function main() {
  const queue = new Queue(connection)
  
  // 不斷從 queue 拿東西出來
  while(true) {
    const userId = await queue.get()
    if (!userId) {
      console.log('no data from queue, end')
      break;
    }
  
    // 看看是否已經爬過，爬過就跳掉
    const check = await queue.check(userId)
    if (!check) {
      continue
    }
  
    // 拿 userId 做你想做的事
    console.log('uid:', userId)
  }
}
```

Then, we just need to implement the following two functions:

1. Fetch user data
2. Write user data into the database
3. Put followers back into the queue

Since the Medium API response always has an anti-[json hijacking](https://medium.com/@jaydenlin/%E7%82%BA%E4%BD%95-facebook-api-%E8%A6%81%E5%9B%9E%E5%82%B3%E7%84%A1%E7%AA%AE%E8%BF%B4%E5%9C%88-%E8%AB%87%E6%8D%B2%E5%9C%9F%E9%87%8D%E4%BE%86%E7%9A%84-json-hijacking-bc220617ceba) header, we can wrap a function specifically to parse the API response:

``` js
async function getMediumResponse(url) {
  try {
    const response = await axios.get(url)
    const json = JSON.parse(response.data.replace('])}while(1);</x>', ''))
    return json
  } catch(err) {
    return null
  } 
}
```

Then, we can write two functions, one to fetch user data and one to fetch follower data (functions with an underscore are lodash functions):

``` js
async function getUserInfo(uid) {
  const url = `https://medium.com/_/api/users/${uid}/profile/stream`
  const json = await getMediumResponse(url)
  if (!json) {
    return {}
  }
  const userId = _.get(json, 'payload.user.userId')
  const follower = _.get(json, `payload.references.SocialStats.${userId}.usersFollowedByCount`, 0)
  
  return {
    followerCount: follower,
    userId: userId,
    name: _.get(json, 'payload.user.name'),
    username: _.get(json, 'payload.user.username'),
    bio: _.get(json, 'payload.user.bio'),
    mediumMemberAt: _.get(json, 'payload.user.mediumMemberAt'),
    isWriterProgramEnrolled: _.get(json, 'payload.user.isWriterProgramEnrolled'),
    createdAt: _.get(json, 'payload.user.createdAt'),
  }
}

async function getFollowers(uid, to) {
  let url = `https://medium.com/_/api/users/${uid}/profile/stream?source=followers&limit=200`
  if (to) {
    url += '&to=' + to
  }
  const json = await getMediumResponse(url)
  if (!json) {
    return {}
  }
  const followers = _.keys(json.payload.references.Social) || []
  const nextTo = _.get(json, 'payload.paging.next.to')
  return {
    followers,
    nextTo
  }
}
```

Basically, we just call the API and process the data a little bit, then return what we are interested in.

We only implemented the function to "fetch one follower" above, so we need to implement another function to "fetch all followers and put them into the queue":

``` js
async function getAllFollowers(uid, queue) {
  const followers = []
  let to = undefined
  while (true) {
    const data = await getFollowers(uid, to)
    if (!data) {
      break;
    }
    followers.push(...data.followers)
    to = data.nextTo
    console.log(uid, 'fetching...', followers.length)
    if (data.followers.length === 0 || !to) {
      break;
    }
    await queue.push(data.followers)
  }
  return followers
}
```

This function will continuously fetch followers and put them into the queue, and print out how many followers have been fetched so far. Once all followers have been fetched, it will return all of the followers (it returns because I originally wrote the code to write all of the followers into the queue at once, but later found it to be less efficient, so I changed it to write them one by one).

Finally, here is the code to write user data into the database:

``` js
function format(time) {
  if (!time) return null
  return moment(time).format('YYYY-MM-DD HH:mm:ss')
}
  
function saveUserInfo(conn, info) {
  conn.query(`
    INSERT INTO Users
    (
      userId, username, name, bio, follower,
      mediumMemberAt, createdAt, isWriterProgramEnrolled
    ) VALUES ?`, [[[
      info.userId, info.username, info.name, info.bio, info.followerCount,
      format(info.mediumMemberAt), format(info.createdAt), info.isWriterProgramEnrolled
    ]]], (err) => {
      if (err) {
        // console.log(err)
      }
    }
  )
}
```

After writing these core functions, we just need to modify our main program to complete the entire crawler:

``` js
async function main() {
  const queue = new Queue(connection)
  
  while(true) {
  
    // 1. 從 Queue 裡面拿出一個 userId
    const userId = await queue.get()
    if (!userId) {
      console.log('no data from queue, end')
      break;
    }
  
    // 2. 如果 userId 已存在 Users，回到步驟一
    const check = await queue.check(userId)
    if (!check) {
      continue
    }
  
    console.log('uid:', userId)
    try {
      const info = await getUserInfo(userId)
      
      // 如果沒抓到資料有可能是被擋了，先停個 3 秒
      if (!info.userId) {
        console.log('sleep...')
        await sleep(3000)
      }
  
      // 3. 把他的資料寫進 Users
      saveUserInfo(connection, info)
  
      // 4. 把他的所有 follower 丟進 Queue
      if (info.followerCount > 0) {
        // 把 followers 放到 queue 並印出總共幾筆資料
        const followerList = await getAllFollowers(userId, queue)
        console.log('Add ' + followerList.length + ' into queue.')
      }
    } catch(err) {
      // 有錯誤就先睡個 3 秒
      console.log('error...sleep')
      await sleep(3000)
    } 
  }  
}
```

The above code is what we wrote according to the previous logic:

1. Take out a userId from the Queue.
2. If the userId already exists in Users, go back to step 1.
3. Write the user's data into Users.
4. Put all of the user's followers into the Queue.
5. Go back to step 1.

However, I added an additional logic that when there is a problem calling the API, it will pause for 3 seconds. This is to prevent being rate limited. However, this mechanism is not very good because there is no retry, so once an error occurs, the userId is skipped.

The original idea was that skipping one userId was not a big deal, after all, there may be 100,000 userIds in the queue, and even if it is skipped, it may still be thrown back into the queue later, so not implementing a retry mechanism is okay.

After assembling all of the above code, we have the framework for the first version of the crawler. It runs okay, but it is just slower than expected. Also, the speed at which the queue grows is surprisingly fast. I ran it overnight and the queue had about 100,000 more data, but there were only four or five thousand in users.

However, after running it overnight, I found a fatal error.

## Second Version of the Crawler: Judging Chinese

The fatal error is that the original assumption: "The followers of Chinese authors are all Chinese authors" is problematic, and upon careful consideration, this assumption is indeed very unreliable.

So after running the crawler overnight, I found that there were a lot of foreign users in the database. And once there is one, there will be a lot of foreign users in your queue.

To avoid this situation, I decided to start with the self-introduction and nickname, and write a function to determine whether the self-introduction and nickname contain Chinese characters. If they do, then they will be put in. Here, I directly copied the code I found on Stack Overflow, which looks very magical:

``` js
function isChinese(text = '') {
  // @see: https://stackoverflow.com/questions/44669073/regular-expression-to-match-and-split-on-chinese-comma-in-javascript/51941287#51941287
  const regex = /(\p{Script=Hani})+/gu;
  return text.match(regex)
}
```

After fetching user data from the queue, we perform a check:

``` js
const info = await getUserInfo(userId)
  
// 非中文，直接略過
if (!isChinese(info.bio) && !isChinese(info.name)) {
  continue;
}
```

When doing this check, I already thought of a potential issue. Some people like to use English in their self-introduction and nickname, even though they are writing in Chinese. This could cause them to be misjudged and not added to the queue.

At the time, I didn't think it was a big deal since there weren't many people like that, and it would be troublesome to fix. I had a solution in mind, which was to fetch their recently clapped or published articles and check if the titles were in Chinese. This would be a more accurate way to judge. However, I was too lazy to implement it and decided to let the crawler run for another day.

The next morning, I discovered another problem that I never thought I would encounter.

## Crawler Version 3: Judging Japanese Users

There were a lot of Japanese users in the user list.

Some of them had nicknames or self-introductions in kanji, so they wouldn't be filtered out by the Chinese check. When I discovered this problem, my first thought was, "If this were an interview, I would definitely be rejected for not thinking of this case..."

To solve this problem, I added a regular expression to check if there were any Japanese characters (excluding kanji):

``` js
function isJapanese(text = '') {
  // @see: https://gist.github.com/ryanmcgrath/982242
  const regexJP = /[\u3040-\u309F]|[\u30A0-\u30FF]/g; 
  const jp = text.match(regexJP)
  if (jp && jp.length >= 3) {
    return true
  }
  return false
}
```

If there were three or more Japanese characters, it would be considered Japanese. I set the quantity because I was afraid that some Taiwanese people might use characters like `の` and be misjudged. However, a better approach would be to look at the ratio, such as if 80-90% of a sentence was in Chinese, it would be considered Chinese.

The updated check logic is as follows:

``` js
const info = await getUserInfo(userId)
  
// 非中文，直接略過
if (!isChinese(info.bio) && !isChinese(info.name)) {
  continue;
}
  
if (isJapanese(info.bio) || isJapanese(info.name)) {
    continue;
}
```

If it's not Chinese, skip it. Then check if it's Japanese by looking at the self-introduction or nickname.

Okay, now everything should be fine! So I cleared the data and let the crawler run for another night.

The next day, I realized how naive I was.

## Crawler Version 4: Refactoring

When I opened the database, I found that there were still many Japanese users. The reason was that some of them had kanji nicknames and no self-introduction, or only a few words in their self-introduction, so they were still considered Chinese users.

In the end, the unreliable judgment mechanism was the root cause of the problem.

Since things had come to this point, I couldn't be lazy anymore. I had to implement the more accurate solution I mentioned earlier: "Check if the recently published or clapped articles are in Chinese." Fortunately, the API provided this data, and it was much easier to implement than I thought.

In addition to this, because the queue was growing much faster than it was being consumed, I changed the method. I wrote another small program that removed the "add followers to the queue" step from the original process and fetched 10 user data at a time.

In other words, this new program simply kept fetching user data and storing it in the database, so the queue would become smaller and the user data would accumulate. It could fetch 20,000 data in an hour, and the queue could be cleared in half a day.

The advantage was that I could quickly accumulate user data. The original implementation was too slow, and I could only fetch about 10,000 data a day. The new implementation didn't need to add things to the queue, so the user data grew quickly.

At that time, I copied and modified the code to create the new program, which made the code more and more messy. Considering that I wanted to open source it later, it was time to clean up the code, so I refactored the program.

The refactored architecture is as follows:

```
.
├── README.md     // 說明
├── app.js        // 主程式
├── getUsers.js   // 只抓使用者資料的小程式 
├── config.js     // 設定檔
├── db.js         // 資料庫相關
├── medium.js     // medium API 相關
├── package.json  
├── queue.js     
└── utils.js       
```

Let's start with config:

``` js
module.exports = {
  db: {
    connectionLimit: 10,
    host     : '',
    user     : '',
    password : '',
    database : 'medium',
    charset: 'utf8mb4'
  },
  batchLimit: 1, // 一次抓多少筆使用者資料
  randomDelay: function() {
    return Math.floor(Math.random() * 200) + 100
  },
  errorRateTolerance: 0.2,
  delayWhenError: 500
}
```

This is where the configuration files are stored, including the database settings and some parameters for fetching data, most of which are related to the program that fetches user data, such as how many data to fetch and how long to wait between each fetch. These are measures to avoid being blocked by sending too many requests.

Next is utils.js:

``` js
module.exports = {
  // @see: https://stackoverflow.com/questions/44669073/regular-expression-to-match-and-split-on-chinese-comma-in-javascript/51941287#51941287
  isChinese: (text = '') => {
    const regex = /(\p{Script=Hani})+/gu;
    return text.match(regex)
  },
  
  // @see: https://gist.github.com/ryanmcgrath/982242
  isJapanese: (text = '') => {
    const regexJP = /[\u3040-\u309F]|[\u30A0-\u30FF]/g; 
    const jp = text.match(regexJP)
  
    // more than 2 japanese char
    if (jp && jp.length >= 2) {
      return true
    }
    return false
  },
  
  sleep: ms => new Promise(resolve => {
    setTimeout(resolve, ms)
  }),
  
  log: function () {
    const args = Array.prototype.slice.call(arguments);
    console.log.apply(console, args)
  }
}
```

This is where some functions used earlier are placed, including limiting the number of Japanese characters to two and wrapping console.log to make it easier to customize later.

Then there's medium.js, which is related to the medium API and adds a function `isMandarinUser` to check if the user is Chinese:

``` js
const axios = require('axios')
const _ = require('lodash')
const utils = require('./utils')
const JSON_HIJACKING_PREFIX = '])}while(1);</x>'
  
// wrapper function, return null instead of throwing error
async function getMediumResponse(url) {
  try {
    const response = await axios.get(url)
    const json = JSON.parse(response.data.replace(JSON_HIJACKING_PREFIX, ''))
    return json
  } catch(err) {
    return null
  }
}
  
function isMandarinUser(name, bio, posts) {
  
  // if bio or name is japanese, must be japanese
  if (utils.isJapanese(name) || utils.isJapanese(bio)) {
    return false
  }
  
   // this user has no activity on medium, decide by name and bio
  if (!posts) {
    return utils.isChinese(name) || utils.isChinese(bio)
  }
  
  const contents = _.values(posts).map(item => item.title + _.get(item, 'content.subtitle'))
  return Boolean(
    contents.find(item => {
      return utils.isChinese(item) && !utils.isJapanese(item)
    })
  )
}
  
module.exports = {
  getFollowers: async (uid, to) => {
    let url = `https://medium.com/_/api/users/${uid}/profile/stream?source=followers&limit=200`
    if (to) {
      url += '&to=' + to
    }
    const json = await getMediumResponse(url)
    if (!json) {
      return null
    }
    const followers = _.keys(json.payload.references.Social) || []
    const nextTo = _.get(json, 'payload.paging.next.to')
    return {
      followers,
      nextTo
    }
  },
  
  getUserInfo: async (uid) => {
    const url = `https://medium.com/_/api/users/${uid}/profile/stream`
    const json = await getMediumResponse(url)
    if (!json) {
      return {}
    }
    const userId = _.get(json, 'payload.user.userId')
    const follower = _.get(json, `payload.references.SocialStats.${userId}.usersFollowedByCount`, 0)
  
    const posts = _.get(json, 'payload.references.Post')
    const name = _.get(json, 'payload.user.name')
    const bio = _.get(json, 'payload.user.bio')
  
    return {
      isMandarinUser: isMandarinUser(name, bio, posts),
      userId,
      name,
      username: _.get(json, 'payload.user.username'),
      bio,
      followerCount: follower,
      mediumMemberAt: _.get(json, 'payload.user.mediumMemberAt'),
      isWriterProgramEnrolled: _.get(json, 'payload.user.isWriterProgramEnrolled'),
      createdAt: _.get(json, 'payload.user.createdAt'),
    }
  }
}
```

isMandarinUser is determined based on three parameters: nickname, self-introduction, and related articles. Related articles may be the most recently published or clapped articles or replies, and the titles and subtitles of the articles are used to determine if they are in Chinese.

If the user has no activity, the self-introduction and nickname are used to judge, so there is still a possibility of misjudgment, but the misjudgment rate is already quite low in practice.

Next, let's look at the database-related operations, db.js:

``` js
const mysql = require('mysql')
const moment = require('moment')
  
function format(time) {
  if (!time) return null
  return moment(time).format('YYYY-MM-DD HH:mm:ss')
}
  
function transform(info) {
  return [
    info.userId, info.username, info.name, info.bio, info.followerCount,
    format(info.mediumMemberAt), format(info.createdAt), info.isWriterProgramEnrolled, null
  ]
}
  
class DB {
  constructor(config) {
    this.conn = mysql.createPool(config)
  }
  
  getExistingUserIds() {
    return new Promise((resolve, reject) => {
      this.conn.query('SELECT userId from Users', (err, results) => {
        if (err) {
          return reject(err)
        }
       return resolve(results.map(item => item.userId))
      });
    })
  } 
  
  getUserIds(limit) {
    return new Promise((resolve, reject) => {
      this.conn.query('SELECT userId from Users where fr="TW" order by follower desc limit ' + limit, (err, results) => {
        if (err) {
          return reject(err)
        }
       return resolve(results.map(item => item.userId))
      });
    })
  } 
  
  deleteUserIds(userIds) {
    return new Promise((resolve, reject) => {
      this.conn.query('DELETE from Queues WHERE userId IN (?)', [userIds], (err, results) => {
        if (err) {
          return reject(err)
        }
        return resolve(userIds)
      })
    })
  }
  
  insertUserData(info) {
    if (!info) return
    const data = Array.isArray(info) ? info.map(transform) : [transform(info)]
    this.conn.query(`
      INSERT INTO Users
      (
        userId, username, name, bio, follower,
        mediumMemberAt, createdAt, isWriterProgramEnrolled, fr
      ) VALUES ?`, [data], (err) => {
        if (err) {
          // console.log(err)
        }
      }
    )
  }
  
  insertIntoQueue(list) {
    return new Promise((resolve, reject) => {
      const values = []
      for (let item of list) {
        values.push([item])
      }
      this.conn.query(`
        INSERT IGNORE INTO Queues (userId) VALUES ?`, [values], (err) => {
          if (err) {
            // console.log(err)
          }
          resolve()
        }
      )
    })
  }
}
  
module.exports = DB
```

Basically, a bunch of SQL queries are wrapped into Promises and functions to make it easier for other modules to use. Most functions can accept an array for batch operations, which is more efficient.

And after packaging these things, the code for the queue becomes very simple:

``` js
class Queue {
  constructor(db) {
    this.db = db
  }
  
  async get(limit) {
    const items = await this.db.getUserIds(limit)
    await this.db.deleteUserIds(items)
    return items
  }
  
  async push(list) {
    await this.db.insertIntoQueue(list)
  }
}
  
module.exports = Queue
```

Finally, let's take a look at our main program app.js. After refactoring, the code becomes much cleaner and more readable:

``` js
const DB = require('./db')
const Queue = require('./queue')
const config = require('./config')
const medium = require('./medium')
const utils = require('./utils')
  
async function main() {
  const db = new DB(config.db)
  const queue = new Queue(db)
  const existingUserIds = await db.getExistingUserIds()
  const userIdMap = {}
  for (let userId of existingUserIds) {
    userIdMap[userId] = true
  }
  
  utils.log('Existing userId:', existingUserIds.length)
  
  while(true) {
    const userIds = await queue.get(1)
    if (userIds.length === 0) {
      utils.log('Done')
      break
    }
  
    const userId = userIds[0]
    if (userIdMap[userId]) {
      continue
    }
    userIdMap[userId] = true
    utils.log('userId:', userId)
  
    try {
      const userInfo = await medium.getUserInfo(userId)
  
      if (!userInfo.userId) {
        utils.log('getUerrInfo error, sleep for', config.delayWhenError)
        await utils.sleep(config.delayWhenError)
      }
  
      if (!userInfo.isMandarinUser) {
        utils.log(userId, 'not MandarinUser')
        continue
      }
  
      db.insertUserData(userInfo)
  
      if (userInfo.followerCount > 0) {
        let to = undefined
        let count = 0
        while (true) {
          const data = await medium.getFollowers(userInfo.userId, to)
          if (!data) {
            break
          }
          const { nextTo, followers } = data
          to = nextTo
          count += followers.length
          utils.log(userInfo.userId, 'fetching', count, 'followers')
          await queue.push(followers.filter(uid => !userIdMap[uid]))
          if (followers.length === 0 || !to) {
            break
          }
        }
      }
    } catch (err) {
      utils.log('sleep for', config.delayWhenError)
      utils.log(err)
      await utils.sleep(config.delayWhenError)
    }
  }
  process.exit()
}
  
main()
```

There is a mechanism here that is different from before. Previously, every time a userId was taken from the queue, it was checked in the database whether it had been crawled. But this is too inefficient. In this version, the program directly retrieves all data from the database when it is executed, and becomes a map. If there is a value, it means that it has been crawled, and vice versa.

The refactored code looks much better after the module is split, and it is easy to make changes. If it hadn't been refactored, I wouldn't dare to open source it...

Here is the refactored code: https://github.com/aszx87410/medium-user-crawler

## Summary

There were many pitfalls in the process of writing the crawler, and the most troublesome one was the language detection part. I didn't think about the case of Japanese characters at first, and it took a lot of time. Laziness also took a lot of time. Originally, I didn't want to use a more accurate method to do the judgment, but in the end, I had to use it, wasting a lot of time in the middle.

There are many places where this crawler can be improved, such as the execution speed or the language detection part. Currently, after I retrieve the data, I manually mark whether it is Hong Kong, Taiwan, or China, but perhaps a small program can be written to automatically determine it. For example, simplified Chinese is China, and if there are some Cantonese characters, it is Hong Kong, and vice versa. Although it may not be accurate, using a program to assist will be much more convenient.

This article mainly shares my experience in writing this crawler. As long as the data source can be determined to be retrievable, everything else is not a big problem. Plus, this crawler is not very complete (for example, there is no retry mechanism), so it can be implemented in a day or two.

I hope this article has attracted everyone's attention, and I also hope that everyone can try to crawl data and make interesting data analysis!
