---
title: 'Notes on HLS Protocol'
date: 2016-11-26 10:20
catalog: true
header-img: "/img/header_img/article-bg.png"
tags: [Hls,Others]
categories:
  - Others
---
# Introduction
Recently, I have been working on live streaming related projects. Although I am a frontend developer, I still need to understand some of the principles of live streaming. At least, I need to know what formats are available and what are the advantages and disadvantages of each format. This will make the development process smoother.

This article will briefly record some of my experiences and information. If you want to have a deeper understanding of HLS, you can refer to the following two articles:

1. [Choosing a Live Streaming Protocol: RTMP vs. HLS](http://www.samirchen.com/ios-rtmp-vs-hls/)
2. [HLS Protocol for Online Video - Study Notes: M3U8 Format Explanation and Practical Application Analysis](http://www.eduve.org/knowledge/732)

<!-- more -->

# What is HLS?
In terms of live streaming, I think HLS is a relatively easy-to-understand protocol. It is simply a `.m3u8` playlist that contains multiple `.ts` files. You just need to play the files in the order given in the playlist. It sounds easy, right?

To help you understand better, I will provide an example of a playlist extracted from somewhere:

```
#EXTM3U
#EXT-X-VERSION:3
#EXT-X-ALLOW-CACHE:YES
#EXT-X-MEDIA-SEQUENCE:4454
#EXT-X-TARGETDURATION:4
#EXTINF:3.998, no desc
25133_src/4460.ts
#EXTINF:3.992, no desc
25133_src/4461.ts
#EXTINF:3.985, no desc
25133_src/4462.ts
#EXTINF:3.979, no desc
25133_src/4463.ts
#EXTINF:3.996, no desc
25133_src/4464.ts
```

Even if you have never seen this format before, you can probably guess what it is doing. Each ts is a segment, and `#EXTINF:3.996` represents the duration of the segment. `#EXT-X-TARGETDURATION:4`, the number here must be greater than the time of any video in the playlist. It means that the player should fetch a new playlist every few seconds.

For example, the next playlist fetched may look like this:

```
#EXTM3U
#EXT-X-VERSION:3
#EXT-X-ALLOW-CACHE:YES
#EXT-X-MEDIA-SEQUENCE:4455
#EXT-X-TARGETDURATION:4
#EXTINF:3.992, no desc
25133_src/4461.ts
#EXTINF:3.985, no desc
25133_src/4462.ts
#EXTINF:3.979, no desc
25133_src/4463.ts
#EXTINF:3.996, no desc
25133_src/4464.ts
#EXTINF:3.998, no desc
25133_src/4465.ts
```

An additional segment is added at the end. So as long as you follow this rule, you can continuously fetch new segments. But what if the server does not generate a new playlist in time?

For example, if you fetch the playlist at 4 seconds and find that it has not been updated, but the server generates a new segment at 4.5 seconds. If this "fetching the same playlist" situation occurs, the fetching time will be halved until a new segment is fetched. In the above example, if a new segment is not fetched at 4 seconds, it will be fetched again after 2 seconds.

This rule can be found in: [HTTP Live Streaming draft-pantos-http-live-streaming-20](https://tools.ietf.org/html/draft-pantos-http-live-streaming-20#section-6.3.4)

> When a client loads a Playlist file for the first time or reloads a
   Playlist file and finds that it has changed since the last time it
   was loaded, the client MUST wait for at least the target duration
   before attempting to reload the Playlist file again, measured from
   the last time the client began loading the Playlist file.

> If the client reloads a Playlist file and finds that it has not changed then it MUST wait for a period of one-half the target duration before retrying.

As for the latency issue that is most concerned with live broadcasting, it can be directly inferred from this playlist. In the example above, there are a total of 5 segments, each segment is 4 seconds, and the latency is 20 seconds. Apple's official recommendation is 3 segments, each segment is 10 seconds.

> What duration should media files be?
A duration of 10 seconds of media per file seems to strike a reasonable balance for most broadcast content.

> How many files should be listed in the index file during a continuous, ongoing session?
The normal recommendation is 3, but the optimum number may be larger.

Refer to: [Apple: HTTP Live Streaming Overview](https://developer.apple.com/library/content/documentation/NetworkingInternet/Conceptual/StreamingMediaGuide/Introduction/Introduction.html#//apple_ref/doc/uid/TP40008332-CH1-SW1)

However, according to the official recommendation, there will be a delay of 30 seconds. Of course, the longer the delay, the better the live broadcast situation, but the experience will be slightly worse. Therefore, let's take a look at how several live streaming websites are set up.

First, let's take a look at the big live streaming website: [Twitch](twitch.tv)

```
#EXTM3U
#EXT-X-VERSION:3
#EXT-X-TARGETDURATION:5
#ID3-EQUIV-TDTG:2016-11-26T02:40:23
#EXT-X-MEDIA-SEQUENCE:376
#EXT-X-TWITCH-ELAPSED-SYSTEM-SECS:1511.137
#EXT-X-TWITCH-ELAPSED-SECS:1508.980
#EXT-X-TWITCH-TOTAL-SECS:1535.137
#EXTINF:4.000,
index-0000000377-6zCW.ts
#EXTINF:4.000,
index-0000000378-vHZS.ts
#EXTINF:4.000,
index-0000000379-Gkgv.ts
#EXTINF:4.000,
index-0000000380-PNoG.ts
#EXTINF:4.000,
index-0000000381-h58g.ts
#EXTINF:4.000,
index-0000000382-W88t.ts
```

6 segments * 4 seconds = 24 seconds. However, if you observe carefully (you can use chrome devtool), after the twtich player gets the list, it will directly try to load from the "third to last" segment, so the delay is shortened to 3 * 4 = 12 seconds.

Next, let's take a look at Taiwan's [livehouse.in](https://livehouse.in)

```
#EXTM3U
#EXT-X-VERSION:3
#EXT-X-ALLOW-CACHE:NO
#EXT-X-MEDIA-SEQUENCE:2291
#EXT-X-TARGETDURATION:6

#EXTINF:5.2090001106262207,
1480116261segment_v02291.ts
#EXTINF:5.2080001831054688,
1480116261segment_v02292.ts
#EXTINF:5.2080001831054688,
1480116261segment_v02293.ts
```

5 * 3 = 15 seconds.

Therefore, the delay of general live streaming websites using HLS is usually within the range of 10-20 seconds. I guess if it is shorter than this, the server pressure may be very high, and if the network speed is slow, it will look very stuck. If it is longer than this, although it is very smooth, the user experience is not good and the delay is too high. Therefore, the best delay can be found in this range.

Finally, let's take a look at the options for playing on a webpage. Because it is now an era where flash is dying, if possible, the preferred choice is of course HTML5. If the browser support is not high enough, then fallback to flash.

Let me translate the Markdown content for you:

---

Let's first introduce some commercial licensed players, such as [jwplayer](https://www.jwplayer.com/) or [flowplayer](https://flowplayer.org/), which are both good options. Especially when open source solutions have problems that you can't fix, you will hope that the company can spend money to buy a commercial player to solve all the problems.

The open source solution is probably only [videojs](http://videojs.com) left. I don't know if there are any other emerging players. If there are, please recommend them.

Then, because the browser itself cannot play the hls format, some plugins need to be used. Videojs has an official [videojs-contrib-hls](https://github.com/videojs/videojs-contrib-hls), which can be added to play, but I don't feel it's very good after using it myself.

Finally, I chose the open source solution [hls.js](https://github.com/dailymotion/hls.js/tree/master) provided by the well-known video website [dailymotion](http://www.dailymotion.com/sg).

[This article](http://engineering.dailymotion.com/introducing-hls-js/) is their official blog, which introduces why they wrote their own solution and what problems it solves. It's worth reading and you can learn more about it.
