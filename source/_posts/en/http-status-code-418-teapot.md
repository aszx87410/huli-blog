---
title: 'The Battle to Save the Teapot: 418 I am a teapot'
date: 2019-06-14 20:10
tags: [Web,Others]
categories:
  - Web
---

## Introduction

There are many HTTP Status Codes that we are all familiar with, such as 404 Not Found, 500 Internal Server Error, and 200 OK, among others.

Among the many status codes, there is one that is clearly meant to be humorous: 418 I'm a teapot.

But did you know that it is not part of the HTTP standard, so it is not a standard HTTP status code? You might say, "I've read the RFC, how can it not be?" But that RFC has nothing to do with HTTP, and many people have not noticed this.

I didn't notice this at first either, and I thought 418 was part of the HTTP standard until someone posted an issue on Node.js's GitHub in August 2017: [418 I'm A Teapot](https://github.com/nodejs/node/issues/14644).

The issue mentioned that they wanted to remove support for 418, and when the author of the issue was told that Go was doing the same thing, they also posted an issue on Go.

At the time, the request to remove the 418 status code actually caused quite a stir, and most people were actually against removing this status code. There was even a [save418.com](http://save418.com/) created to try to save 418.

Recently, I spent some time studying the whole thing, and in the process of organizing it, I found that whether you are for or against it, the reasons behind it are worth thinking about, so I summarized it into an article to share with everyone.

<!-- more -->

## The Origin of 418

The origin of 418 can be traced back to April Fool's Day 1998, in this document: [RFC2324, Hyper Text Coffee Pot Control Protocol (HTCPCP/1.0)](https://tools.ietf.org/html/rfc2324). HTCPCP stands for Hyper Text Coffee Pot Control Protocol, and this RFC describes a protocol called HTCPCP, which is built on top of HTTP and can be used to brew coffee using this protocol.

Regarding the 418 part, it is in Section 2.3.2:

> 2.3.2 418 I'm a teapot

>   Any attempt to brew coffee with a teapot should result in the error
   code "418 I'm a teapot". The resulting entity body MAY be short and
   stout.

The meaning is that if someone wants to brew coffee with a teapot, you should return a 418 status code, "I'm a teapot", why are you using me to brew coffee?

The only thing worth noting here is that 418 is in the HTCPCP protocol, not HTTP. So 418 is not a standard HTTP status code.

## The Storm to Remove 418

On August 5, 2017, Mark Nottingham posted an [Issue](https://github.com/nodejs/node/issues/14644) on Node.js's GitHub:

> Node implements the 418 I'm a Teapot status code in a few places.

> Its source is RFC2324, Hyper Text Coffee Pot Control Protocol (HTCPCP/1.0). Note the title - HTCPCP/1.0 is not HTTP/1.x.

> HTCPCP was an April 1 joke by Larry to illustrate how people were abusing HTTP in various ways. Ironically, it's not being used to abuse HTTP itself -- people are implementing parts of HTCPCP in their HTTP stacks.

> In particular, Node's support for the HTCPCP 418 I'm a Teapot status code has been used as an argument in the HTTP Working Group to preclude use of 418 in HTTP for real-world purposes.

> While we have a number of spare 4xx HTTP status codes that are unregistered now, the semantics of HTTP are something that (hopefully) are going to last for a long time, so one day we may need this code point.

> Please consider removing support for 418 from Node, since it's not a HTTP status code (even by its own definition). I know it's amusing, I know that a few people have knocked up implementations for fun, but it shouldn't pollute the core protocol; folks can extend Node easily enough if they want to play with non-standard semantics.

> Thanks,

The author requests Node to remove support for 418, as it is not an HTTP standard status code. Although there are still many 4xx status codes available, if we hope that HTTP can last for a long time, we will eventually need to use this status code.

After some discussion, someone pointed out that Go also implemented 418, so Mark Nottingham went to Go's GitHub and posted a similar issue: [net/http: remove support for status code 418 I'm a Teapot](https://github.com/golang/go/issues/21326).

Both of these issues are actually worth reading, as there are many constructive discussions inside. Below, I summarize several supporting and opposing arguments.

### Opposing removal: 418 is harmless

> 418 is a harmless Easter egg, and it's fun, keep it away from my 418!

I think this argument is quite weak. It is only necessary to prove that 418 is actually harmful.

### Supporting removal: What if someone needs to use 418 in the future?

> You say 418 is harmless, but if we hope that HTTP can last for a long time, then one day we will need to use 418, and it will mean something else on that day. Even if you keep 418, one less status code can be used.

I find this argument quite interesting. Indeed, according to this argument, 418 occupies a position, and one less status code can be used in the future. But is this "one" important? It can be seen together with the opposing argument below.

### Opposing removal: 418 only occupies one space, the problem is not with 418

If the day when 4xx is almost used up really comes, should we review the design of HTTP or review that there are not enough status codes? If there is really only one left that can be used, does it mean that there are bigger problems to be solved?

The reason why I find this point interesting is that it is quite similar to the problems we encounter when writing programs. Sometimes you may worry that you are premature optimization or over-engineering, and you have made optimizations that are completely unnecessary.

> Suppose there is a program that uses the numbers 1 to 100 to represent different states. As time goes by, we will need different numbers to represent different states, so the numbers that can be used will become fewer and fewer, and we hope that this program can last for a long time. In this case, do you agree that we take one of the numbers as an Easter egg?

If you object and think that every number is important and should not be taken out as an Easter egg, it means that you think 418 should be removed.

But my own view of this issue is that a number is completely irrelevant.

The reason is that if you really use up all 99 numbers, even if I return the number I took as an Easter egg to you, you will still use up all the numbers soon. At that time, you still need to find a new solution. So missing one number doesn't make much difference.

### Supporting removal: 418 is not in the HTTP standard

This is the most powerful argument in my opinion.

Everyone knows that 418 is an Easter egg and it is interesting, but it is not part of the HTTP standard. If you want to implement a program that "complies with the HTTP standard" today, you should not include 418 because it is not inside. In [IANA](https://www.iana.org/assignments/http-status-codes/http-status-codes.xhtml), 418 is also an unassigned status.

If you are an ordinary person and want to implement 418 in your own server or app, no one will interfere with you. But for projects like Node.js and Go, they should develop in compliance with the specifications.

This point can also be extended to the problems encountered in product development. If the PM specification is not clear, the engineer will either communicate with PM or ask PM to write the ambiguous part more clearly, preferably without any personal interpretation space, the clearer the better.

Is it reasonable for an engineer to secretly add an extra Easter egg to a specification that has been written super clearly by the PM? This Easter egg may be irrelevant and only the engineer knows how to open it, but it is still beyond the specification.

When considering the issue of whether to keep 418 or not, you may only see 418. But I think the choice you make when encountering the 418 issue is related to the development problems you usually encounter. Interestingly, you may choose A for 418, but choose B for similar development issues, and the two are conflicting.

From my personal point of view, the reason that 418 is not in the standard is very powerful. However, emotionally, I don't want it to be removed, fortunately, there is also a powerful argument against it.

### Against removal: 418 has been misused for too long

When doing version updates, an important point is to maintain backward compatibility. If it is not something important, try not to have a breaking change.

And this argument is that 418 as a "status code mistakenly thought to be HTTP standard" has been more than ten years, so almost every mainstream library supports 418 (you see Node.js and Go both support it), if you remove the support of 418 today, what about the server that used 418 before?

I also think this argument is quite powerful. 418 has been misused for too long, and removing it will cause more problems than maintaining the status quo. From this point of view, it should not be removed.

## Follow-up development and current situation of 418

After Mark Nottingham proposed to remove 418, some people thought he was joking and only had the idea of touching 418 when he was too idle.

But if you click into his GitHub, you can see his self-introduction:

> I work on HTTP specifications and implementations.

He originally participated in various organizations related to HTTP standards and made many contributions in this field.

After the community raised objections, he also decided to change his position from removing 418 to retaining 418:

> So, I poked a couple of implementations to see if they'd remove 418's "teapot" semantics, and there was a reaction (to put it mildly).

> I think we need to reserve 418 to make it clear it can't be used for the foreseeable future

(Source: [http-wg mailing list: Reserving 418](https://lists.w3.org/Archives/Public/ietf-http-wg/2017JulSep/0332.html))

So he drafted a document: [Reserving the 418 HTTP Status Code](https://tools.ietf.org/id/draft-nottingham-thanks-larry-00.html), which explains that the status of 418 should be set as reserved and cannot be registered by others:

> [RFC2324] was an April 1 RFC that lampooned the various ways HTTP was abused; one such abuse was the definition of the application-specific 418 (I’m a Teapot) status code.

> In the intervening years, this status code has been widely implemented as an “easter egg”, and therefore is effectively consumed by this use.

> This document changes 418 to the status of “Reserved” in the IANA HTTP Status Code registry to reflect that.

When I was researching this whole thing, I found that the information in this draft had expired (Expires: February 12, 2018). When I checked the [IANA HTTP Status Code registry](https://www.iana.org/assignments/http-status-codes/http-status-codes.xhtml), I found that 418 was still unassigned.

All the clues end here, so what happened to 418 in the end? Will it be reserved? So I wrote an email to Mark Nottingham himself, and he only gave me a link: https://github.com/httpwg/http-core/issues/43.

From this issue, you can find this PR: [Reserve 418 status code](https://github.com/httpwg/http-core/pull/149/files), which modified the file `draft-ietf-httpbis-semantics-latest.xml`. The latest draft can also be found on the httpwg website: https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html.

In the latest draft, the following section has been added:

> 9.5.19. 418 (Unused)
> 
> [RFC2324] was an April 1 RFC that lampooned the various ways HTTP was abused; one such abuse was the definition of an application-specific 418 status code. In the intervening years, this status code has been widely implemented as an "Easter Egg", and therefore is effectively consumed by this use.

> Therefore, the 418 status code is reserved in the IANA HTTP Status Code registry. This indicates that the status code cannot be assigned to other applications currently. If future circumstances require its use (e.g., exhaustion of 4NN status codes), it can be re-assigned to another use.

It seems that 418 is being reserved for future use, but if the 4XX status codes are exhausted, 418 can be reassigned for another use.

The latest HTTP/1.1 standard can also be found on the httpwg website: [Hypertext Transfer Protocol (HTTP/1.1): Semantics and Content](https://httpwg.org/specs/rfc7231.html), which does not include 418.

Therefore, my guess is that 418 has been added to the latest draft and reserved, but it has not been officially published yet (there are probably many processes behind it, which requires studying the HTTP Working Group's regulations), but it should be visible in the future when the draft is published and becomes an official standard.

## Conclusion

From what we have seen, 418 I am a teapot is still not part of the HTTP standard. After all, some people may think that as long as 418 I am a teapot becomes part of the HTTP standard, the problem will be solved, but I guess there are some issues with doing so (if anyone knows what the issues are, please let me know, thanks).

The final conclusion should be that the 418 status code will continue to exist as I am a teapot in various mainstream HTTP implementations, but it is still not part of the HTTP standard. In the standard, the 418 status code is set to (Unused) and is temporarily reserved and will not be replaced by other uses.

The main purpose of this article is to record the past and present of the 418 status code and let everyone know that it is not part of the HTTP standard. In addition, during the research process, many problems that developers may encounter were also considered, and the core concepts behind them are actually similar.

Actually, I hesitated for a long time when writing this article because I was afraid that I might make a mistake somewhere (there are too many and too rich reference materials), but I remembered a sentence I saw somewhere before: "Instead of asking a question, there is a faster way to get the right answer. That is to tell a wrong answer, and someone will correct you."

Further reading:

1. [HN discussion](https://news.ycombinator.com/item?id=14987460)
2. [HN discussion - 2](https://news.ycombinator.com/item?id=15004907)
