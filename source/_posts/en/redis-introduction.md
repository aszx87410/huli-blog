---
title: 'Redis: The Perfect Companion for Databases'
date: 2016-09-29 00:30
catalog: true
tags: [Back-end,Redis]
categories:
  - Back-end
---
## Introduction
[Redis](http://redis.io/) is an in-memory key-value database, often used for caching data to reduce the load on the backend database. This article will briefly introduce some of the useful features of Redis and where it can be applied.

<!-- more -->

## Common Commands
[Redis's official website](http://redis.io/commands) lists every supported command. Let's start with the simplest:

### SET, GET

```
redis> SET mykey "Hello"
redis> GET mykey
"Hello"
```
As mentioned earlier, Redis is a key-value pair database. Therefore, the simplest SET is to set the value of a certain key, and to retrieve it, use GET.

### INCR, DECR

```
redis> SET mykey "10"
redis> DECR mykey
(integer) 9
redis> INCR mykey
(integer) 10
```

As the name suggests, it means to add or subtract one to a certain key, like `mykey++` and `mykey--` in programming languages.  
There is also `INCRBY` and `DECRBY`, which allows you to specify the amount you want to add or subtract.

### HSET, HGET

```
redis> HSET mydata name "nick"
redis> HSET mydata nickname "nicknick"
redis> HGET mydata name
"nick"
```

H stands for Hashmap, so you can access the field under a value, allowing you to use it more flexibly. For example, you can define the rule of the key as: POST + article id, and store the number of likes, replies, etc. of this article inside, so you don't have to fetch it from the database every time.

### SADD, SCARD

```
redis> SADD myset "nick"
redis> SADD myset "peter"
redis> SADD myset "nick"
redis> SCARD myset
(integer) 2
```

SADD's S stands for `Set`, which refers to the `Set` data structure you learned in school, where there is no duplicate content.

### LPUSH, RPUSH, LSET, LRANGE

```
redis> LPUSH mylist "a"
redis> LPUSH mylist "b"
redis> RPUSH mylist "c"
redis> LRANGE mylist 0 -1
1) "b"
2) "a"
3) "c"
redis> LSET mylist 0 "d"
redis> LRANGE mylist 0 -1
1) "d"
2) "a"
3) "c"
```

The data structure here is `List`, and you can choose to push values from the left or right, corresponding to the commands `LPUSH` and `RPUSH`. `LSET` specifies the value of a certain index.  

`LRANGE` can print out the specified range of values, supporting the `-1` format, which represents the last value.

## Practical Applications
Redis is useful because of its speed. Therefore, if you encounter situations that require high speed in development, you can consider whether Redis can help you. Here are a few examples that I have actually used.  

### URL Shortening System
The principle of URL shortening is very simple, which is a hash corresponding to a URL. The hash is randomly generated, and the number of digits or symbols can be determined by yourself. Then, store this set of corresponding relationships in the database. When someone queries the corresponding key, you just redirect to the corresponding URL.  

Because it is a one-to-one relationship of key-value, it is very suitable for using Redis.  
If you don't use a key-value cache like Redis, you must query from the database "every time". If the amount of data is small, it's okay, but when the amount of data increases, the time will definitely increase, and the load on the database will also increase. Therefore, introducing a layer of cache between the database and the logic layer is a good choice.  

The implementation process is also very simple:

1. The user adds a shortened URL, and the system randomly generates abc123 corresponding to http://techbridge.cc.
2. Write key=abc123, value=http://techbridge.cc to the database.
3. Same as above, but stored in Redis.
4. When a user clicks on the URL abc123, first check if there is this key in Redis.
5. If yes, redirect to the corresponding URL.
6. If not, you have to query the database. After querying, remember to write a copy to Redis.

If you have a lot of data and don't want to spend a lot of money on a Redis Server with a large memory (databases store data on hard disks, while Redis stores data in memory, making databases much cheaper in terms of storage costs), you can use Redis's `Expire` feature. 

When you store data, you can add an `Expire time` parameter. When this time is up, the key will be automatically cleared. For example, the expire time for a short URL can be set to 7 days. If a URL has not been visited by any user within 7 days, it will be automatically deleted. 

The advantage of this is that you can reduce memory usage by only keeping certain "hot data" in Redis, while storing other less popular or less frequently accessed data in the database, and writing it to Redis when it is accessed. 

### Statistical System
In addition to the URL shortening feature, another key feature of a URL shortening service is statistical data. For example, Google's URL shortening service provides information such as visit counts, charts, and device usage. These are the core features of a URL shortening service. 

To implement this feature, you need to record each request or at least the content of the request (such as the device used, time, and IP address) to have data to show users. 

If you read from the database every time, it will cause some performance issues. For example, every time you refresh the statistics page, you have to execute `select count(*) from short_url where id="abc123"` to get the total number of visits. 

Do you remember `INCR`? This is where it comes in handy! You can define the key format yourself, for example, `abc123:visit` represents the total number of visits to the short URL `abc123`. Then, every time a request is made, execute `INCR abc123:visit`, and the number you need will be in this key, which can be read from Redis in the future. 

In addition to this, if you want to provide "non-repeating IP visit counts," the `Set` mentioned earlier is very suitable. You can put the source IP of each request into a Set, and use `SCARD` to know how many unique IPs there are. It's very convenient, isn't it?

### High Real-time Ranking System
I once worked on a project with the following requirements:

1. Users can enter the website at noon and answer a question.
2. After answering the question, they will see their ranking (sorted by answer time), and receive a prize based on their ranking.
3. Only the top 300 users will receive a prize.

Think about where you need to communicate with the database:

1. When entering the website, check whether more than 300 people have already participated. If so, prompt that the event has ended (`select count(*)...`).
2. Then check whether the user has answered the question. If so, display their ranking (`select .. where id=..`).
3. If they haven't answered the question, display the question page.
4. After answering the question, display the user's ranking (`insert into .. id=..`).

Since only the top 300 users will receive a prize, if there are 10,000 users, the event may end within 10 seconds! 

Your database must "simultaneously handle" so many queries within 10 seconds, which may be a bit overwhelming. After careful examination, it will be found that many places do not need to use the database, or using Redis will be better! 

For example, you can plan it like this:

1. Use a key `isOver` to store whether the event has ended.
2. Use `account` as the key to store the user's ranking.

The above process can be rewritten as follows:

1. When entering the website, read `isOver` from Redis to see if the event has ended.
2. Check whether the user has answered the question by checking whether the user account key in Redis has data.
3. If they haven't answered the question and have answered it, write it to the database and write the ranking to Redis.
4. If the user's ranking is >=300, set `isOver = true`.

Originally, three database operations were required, but now only the most necessary one is left, and the rest can be handled by Redis. Moreover, because Redis is an in-memory database, the response speed is very fast! In addition, since we don't have many keys (just over 10,000), we use very little memory. 

Through the help of Redis, the problem of heavy database load that may be slow or even crash can be easily solved.

## Conclusion

If you have a project with a lot of users or need to return information quickly but are afraid that the database cannot handle it, consider using Redis or other caching services. In many cases, if caching is used properly, it can reduce the burden on the database and speed up response times. 

If you are interested in Redis, you can refer to the website [Redis Design and Implementation](http://redisbook.com/).

Please paste the Markdown content you want me to translate.
