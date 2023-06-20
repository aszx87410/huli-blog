---
title: "CORS Complete Guide (6): Summary, Afterword, and Leftovers"
catalog: true
date: 2021-02-19 00:21:13
tags: [Ajax, JavaScript, Front-end, CORS]
categories:
  - Front-end
---

## Preface

This article has a little less technical content, and I would like to share with you the process of writing this series of articles and some thoughts after finishing it.

If you haven't read this series of articles yet, the links are as follows:

* <a target="_blank" href="/2021/02/19/cors-guide-1">CORS Complete Guide (1): Why CORS Error Occurs?</a>
* <a target="_blank" href="/2021/02/19/cors-guide-2">CORS Complete Guide (2): How to Solve CORS Problems?</a>
* <a target="_blank" href="/2021/02/19/cors-guide-3">CORS Complete Guide (3): CORS Details</a>
* <a target="_blank" href="/2021/02/19/cors-guide-4">CORS Complete Guide (4): Looking at the Specification Together</a>
* <a target="_blank" href="/2021/02/19/cors-guide-5">CORS Complete Guide (5): Security Issues of Cross-Origin</a>
* <a target="_blank" href="/2021/02/19/cors-guide-6">CORS Complete Guide (6): Summary, Afterword, and Leftovers</a>

<!-- more -->

## Origin

In the first article, I mentioned the original intention of writing this series of articles. It's because I have seen too many people asking about CORS issues, and some people don't care about the context and recommend using a proxy or CORS Anywhere. If it is a third-party resource without permission, then this solution is reasonable, but if it is the company's own service, the backend should be called to set it up instead of connecting to the proxy by yourself.

The most common CORS errors are probably:

1. Don't know that CORS blocks response instead of request (except for preflight)
2. Don't know why CORS is needed
3. Don't know how to solve CORS problems (trying everywhere, thinking that `no-cors` is the solution)
4. Don't know how to debug (should look at the console and network tab)
5. Incorrectly solving CORS problems (using proxy instead of asking the backend to change)

In April 2020, I had the idea of writing this series of articles, and then started researching. I planned the five articles that you see at the beginning, and started writing in July 2020. I wrote the first article continuously for about two or three days, wrote about half of the second article, and then stopped.

The reason for stopping was probably because I didn't know how to write the third article: CORS Details, and I didn't have many ideas about looking at the spec together in the fourth article, so I procrastinated and left it there. I didn't continue writing until February 2021, and then finished all the subsequent articles in one go. The reason for starting to write again is that this is a stone in my heart. If I don't finish writing this series, I will feel a little uneasy when I do other things, thinking "Is this series of articles not going to be finished?"

## Afterword

Fortunately, I have finished writing it. Because I have gained a lot from the process of writing articles, I spent a lot of time understanding some details, such as the Spectre attack, which I studied for a while. Although I still don't understand it completely, I need to supplement the knowledge related to the operating system to fully understand it. The COXX headers in the fifth article also took a lot of time. I looked up a lot of information and read the issues proposed by the original proposal. I understand the reasons for these policies.

In the process of research, I also found that many security-related things are actually linked together, such as:

1. Same-origin policy
2. window.open
3. iframe
4. CSP
5. SameSite cookie

In the process of finding information, I can see many overlapping places, especially SameSite cookie. The more I think about it, the more I feel that this thing is really important and can prevent many attacks. By the way, when writing this article, most of the reference materials actually come from Google Chrome, so there are many places in the article that use "browser", which may only be implemented in Chrome now, and other browsers have not followed up yet.

However, Chrome does have the most resources, and often posts some technical articles on the blog, which are very valuable resources.

I think that both front-end and back-end engineers should have a certain understanding of CORS, so that they know how to solve problems when they encounter them. Although CORS is a problem that many novice engineers have encountered, it is not particularly difficult to understand the context after sorting out the logic. It just takes some time to understand the operation mode of CORS. Once you understand it, you will not be afraid of encountering this problem in the future.

Regarding the various COXX things in the fifth article, I think that unless you need to use those sealed functions, or your website needs high security, you can study them when you have time. Just having an impression is enough.

After finishing this series of articles, there are some things I want to talk about that I couldn't find a place for, so the following paragraphs will discuss some of the leftovers.

## CORS Issues That May Not Be CORS Issues

Browser error messages are a great source of information, but they are not always reliable.

Some CORS issues may not be due to improperly set response headers, but rather because a previously improperly set response was cached, or even due to certificate issues! See:

1. [CORS request blocked in Firefox but not other browsers #2803](https://github.com/aws-amplify/amplify-js/issues/2803)
2. [Firefox 'Cross-Origin Request Blocked' despite headers](https://stackoverflow.com/questions/24371734/firefox-cross-origin-request-blocked-despite-headers)
3. [CORS request did not succeed on Firefox but works on Chrome](https://stackoverflow.com/questions/51831652/cors-request-did-not-succeed-on-firefox-but-works-on-chrome)

## Origin Policy

When using CORS, we actually spend a lot of time on the preflight request. Assuming there is no caching and all requests are non-simple requests, cross-origin requests have twice as many requests as same-origin requests because each request has an additional preflight request attached.

However, most website rules for CORS are consistent, so why not write a configuration file for the browser to read? This way, the browser will know if a source is allowed, and there will be no need to keep sending preflight requests.

The idea behind this comes from: [RFC: a mechanism to bypass CORS preflight #210](https://github.com/whatwg/fetch/issues/210), and if you have time, you can take a look at the discussion inside.

In fact, not only CORS, but other headers may also have similar situations, such as CSP. In most cases, the CSP for the entire website is actually the same, but now every HTTP response has to return the same CSP header, which can also be read by the browser through a configuration file, so there is no need to send them individually.

All of the above was expanded into something called [Origin Policy](https://github.com/WICG/origin-policy), which is the idea of writing a file and placing it in `/.well-known/origin-policy` for the browser to read. This can save a lot of response size, but it is currently just a proposal.

## Cross-Origin Image Loading

Usually, when using `img`, it is `<img src=xxx>`, which is a normal way to fetch resources.

But actually, there are some tags in HTML that can fetch resources in a "cross-origin" way, such as `<img>`, and others can be found at: [MDN: HTML attribute: crossorigin
](https://developer.mozilla.org/en-US/docs/Web/HTML/Attributes/crossorigin).

Just do this:

``` html
<img src=xxx crossorigin>
```

In fact, crossorigin has three attributes:

1. Not set/empty string
2. anonymous
3. use-credentials

The first two are the same, and the latter is like the `credentials: 'include'` in fetch. Anyway, as long as you add `crossorigin`, for cross-origin files, the backend must add `Access-Control-Allow-Origin` like CORS, so that the frontend can correctly access the image.

Why do we have to use CORS to load images that are perfectly fine? There are two reasons. The first reason is that in the previous article, I mentioned that "if you set COEP to require-corp, it means telling the browser that 'all resources I load on the page must have the presence of CORP headers (or CORS), and they must be legal'".

Assuming you now set COEP to require-corp, if you use `<img src=xxx>` to load images on your website, this image must have the CORP header. What if it really doesn't?

You can load images using cross-origin method, that is: `<img src=xxx crossorigin>`. Under this method, images do not need to have the CORP header, only the `Access-Control-Allow-Origin` header is required, because this loads the image using the CORS mode.

The second reason, do you remember I mentioned before that if you load a cross-origin image and try to read the image content using JS, will it produce an error? If you load it using cross-origin mode, there will be no such error. For more information, please refer to: [Allowing cross-origin use of images and canvas](https://developer.mozilla.org/en-US/docs/Web/HTML/CORS_enabled_image).

## Chromium's CORS handling code

I haven't looked at it in detail, just taking notes: [chromium/chromium/src/+/master:services/network/public/cpp/cors/cors.cc](https://source.chromium.org/chromium/chromium/src/+/master:services/network/public/cpp/cors/cors.cc?originalUrl=https:%2F%2Fcs.chromium.org%2F)

## Is a URI always the same origin as itself?

The answer is given in [rfc6454](https://tools.ietf.org/html/rfc6454#section-5):

> NOTE: A URI is not necessarily same-origin with itself. For example, a data URI [RFC2397] is not same-origin with itself because data URIs do not use a server-based naming authority and therefore have globally unique identifiers as origins.

Data URI is not the same origin as itself.

However, I couldn't find this section in the new fetch spec.

## How to make the origin "null"

As mentioned earlier, null origin and "null" are different, because the origin can indeed be a string of null, for example, when you open a `file:///` page and send a request, or when you use AJAX in a sandboxed iframe:

``` js
<iframe sandbox='allow-scripts' srcdoc='
  <script>
    fetch("/test");
  </script>
'></iframe>
```

The code is rewritten from: [AppSec EU 2017 Exploiting CORS Misconfigurations For Bitcoins And Bounties by James Kettle](https://youtu.be/wgkj4ZgxI4c?t=979)

## Summary

Finally finished writing this series.

I hope that after reading this series, everyone will have a better understanding of CORS and other related concepts of cross-origin, and will no longer be afraid of CORS errors and know how to solve them. As I said at the beginning of the first article, I hope this series can become a treasure trove of CORS, and everyone who encounters problems can solve them after reading this series.

If there are any errors or omissions, please let me know by private message or comment. Thank you.
