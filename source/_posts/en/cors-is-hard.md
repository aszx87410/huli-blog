---
title: 'CORS is not as simple as I thought'
date: 2018-08-18 22:10
tags: [Front-end]
categories:
  - Front-end
---

# Introduction

CORS (Cross-Origin Resource Sharing) has always been a classic problem in front-end development. Simply put, due to some security considerations of the browser, you will encounter some restrictions when loading resources from other domains. The solution is simple, just add some response headers such as `Access-Control-Allow-Origin` on the server side. With this header, the browser will recognize that you have been verified and there will be no problem.

I have written an article about this problem before: [Understanding Ajax and Cross-Origin Requests](https://blog.techbridge.cc/2017/05/20/api-ajax-cors-and-jsonp/), which details the problems encountered and their solutions.

I thought that since I had delved into this problem last time, CORS would never be a problem for me again, and I would never see the error of "forbidden to access cross-origin" in the console.

But I was wrong.

This time, I stumbled in a specific use case, but I also learned a lot from it. This experience also reminded me of what I wrote before: [The most difficult cookie problem I have ever encountered](https://blog.techbridge.cc/2017/03/24/difficult-problem-of-cookie/).

Great, there is something to share with you again!

<!-- more -->

# The Tragic Beginning

The thing is, a while ago, the company's product redesign entered the final stage. The serious bugs were almost fixed, and the next step was to start adjusting some performance and testing the most important new feature of this redesign: PWA!

For those who don't know what PWA is, let me explain briefly here. PWA stands for Progressive Web App, which is simply to make your Mobile Web more like an App through some browser support. The most important thing is that you can use Service Worker to cache any request (even API requests). If done well, you can even open this webpage offline.

In addition, through the browser, you can add your website to the main screen, just like installing it in your phone, becoming no different from an App.

Below are three screenshots that will give you a better sense of PWA. First, you can add this webpage to the main screen:

![pwa1](https://user-images.githubusercontent.com/2755720/49351821-264d8a80-f6f0-11e8-947b-c7232fec47de.jpg)


The second one is that this PWA will be like other Native Apps, existing in your phone. You can't tell whether it is a Native App or a PWA just by looking at this page.

![pwa2](https://user-images.githubusercontent.com/2755720/49351828-2c436b80-f6f0-11e8-8c46-3f713e2f37cd.jpg)


The last one is that after you open this PWA, it will become full screen. Just by looking at this screenshot, it is no different from a Native App.

![pwa3](https://user-images.githubusercontent.com/2755720/49351830-2ea5c580-f6f0-11e8-8d4b-d5479ebfd16a.jpg)


In short, you can think of PWA as: existing website + new technology (Service Worker, manifest.json...), combined to become PWA.

That's all for the simple introduction to PWA. If you want to learn more, you can refer to what @arvinh wrote: [Will Progressive Web App be the future trend?](https://blog.techbridge.cc/2016/07/23/progressive-web-app/) or [When React web app meets Progressive web app](https://blog.techbridge.cc/2016/09/17/create-react-pwa/).

For PWA, the most important thing is actually this Service Worker (hereinafter referred to as SW). Chrome's built-in Lighthouse can give a PWA score for the webpage. SW is one of the considerations, because you must implement SW to cache files and implement the offline opening App function.

The following figure shows the items that Lighthouse will check:

![lh](https://user-images.githubusercontent.com/2755720/49351838-31a0b600-f6f0-11e8-8a9d-6260a0cdc60d.png)

Okay, here's the translation:

---

Alright, the preface is over, let's get to the point.

We've done everything we need to do for our PWA, including registering the service worker and implementing offline functionality. However, there's one thing that keeps failing in Lighthouse's tests: registering the service worker.

No matter how many times we test it, Lighthouse keeps saying that our website doesn't have a registered service worker.

It's really strange. I tried testing it manually in a clean Chrome window in incognito mode, and I confirmed that the service worker is definitely registered. But no matter how I test it in Lighthouse, it keeps saying that it's not registered.

So what should we do?

Fortunately, Lighthouse is [open source](https://github.com/GoogleChrome/lighthouse) and provides a CLI version that you can run on your own computer.

So I thought, since Lighthouse says it's not registered, let's take a look at how Lighthouse is testing it. I did a little research on the source code of Lighthouse and found that the testing method seemed fine. So I decided to modify Lighthouse to prevent it from closing the window after running the tests, so that I could see if there was any useful information in the console and if the message that should be printed when registration is successful was printed.

I made a few changes:

1. Added a configuration file to only run the service worker test.
2. After running the test, Chrome won't be closed.
3. Added a log in the service worker check.

If you need it, the parts I changed are here: [PR for the changes](https://github.com/aszx87410/lighthouse/pull/1/files)

After making the changes, I ran the tests again. And at that moment, I remembered the fear of being trapped by CORS:

![sw-error](https://user-images.githubusercontent.com/2755720/49351841-35343d00-f6f0-11e8-8661-ae6094c17e41.png)


# Clearing the clouds and seeing the sun

Since we have some clues, we should investigate them thoroughly. From the screenshot, it looks like the service worker is registered successfully, but there are some errors when using the cached files with the service worker, which seems to affect the entire test. Anyway, as long as we solve this CORS problem, everything should be fine.

Let me give you some background information first. We store all our static files on Amazon S3 and use Cloudfront in front of it. We have followed [Amazon's instructions](https://docs.aws.amazon.com/AmazonS3/latest/dev/cors.html) to add what we need to add, so if the request header has an origin, the response will definitely have the CORS header. So there should be no problem.

And when the service worker caches files, it uses fetch, so it will definitely add the origin header, and there is no reason for it to fail.

After being stuck for an hour or two, I decided to take a look at the network tab and found more clues:

The following is a request sent from the service worker. The header does have an origin, but the response does not have `Access-Control-Allow-Origin`!

![sw-r1](https://user-images.githubusercontent.com/2755720/49351843-382f2d80-f6f0-11e8-964e-faeb9e786ff7.png)

In addition, I found an identical request earlier. Since this request was sent by `<script>`, it did not include the origin, so the response did not have the CORS header.

![sw-r2](https://user-images.githubusercontent.com/2755720/49351854-44b38600-f6f0-11e8-8a11-b8b63248c8a8.png)

It's worth noting that the second response is from disk cache (although both are in the screenshot, that's because I didn't clear the cache when taking the screenshot, in fact, only the second one should be).

![sw-tab](https://user-images.githubusercontent.com/2755720/49351857-4715e000-f6f0-11e8-8a25-f597a0aa6ab3.png)

After investigating these clues, I have a rough idea of what's going on.

# In-depth investigation

Alright, let me explain.

The file that the service worker needs to cache is one of the JavaScript files that the page will load. Since the page will load it, we put a `<script>` tag in the HTML to load this file. From the screenshot, it looks like the browser loaded this JavaScript file first, and because it wasn't sent via AJAX, it didn't include the origin. According to S3's rules, there was naturally no `Access-Control-Allow-Origin`.

Next, after successfully registering SW, we started executing the code inside it to cache the list we prepared in advance, one of which is this JavaScript file. However, when we used fetch to retrieve this file, the browser directly used the cached previous response (because the URL and method are the same), and this response did not have `Access-Control-Allow-Origin`! Therefore, the cross-domain error we saw at the beginning occurred.

The truth is revealed here, all due to browser caching issues.

Why couldn't I find this problem when I tested it myself before? As a front-end engineer, it is reasonable to check "Disable cache" in devtool, so no matter how I tried, I couldn't find this problem.

After knowing the cause of the problem, it is relatively simple. I searched on Google and found this Chromium ticket: [CORS Preflight Cache Does not Consider Origin](https://bugs.chromium.org/p/chromium/issues/detail?id=260239)

The problem encountered inside is basically the same as what I encountered. The solution given in the end is to add a `Vary: Origin` to the response, so that the browser knows not to use the cache if the Origin is different. However, I found that we had already added it but didn't know why it didn't work.

In addition, I found several similar problems:

1. [Chrome S3 Cloudfront: No 'Access-Control-Allow-Origin' header on initial XHR request](https://serverfault.com/questions/856904/chrome-s3-cloudfront-no-access-control-allow-origin-header-on-initial-xhr-req)
2. [S3 CORS, always send Vary: Origin](https://stackoverflow.com/questions/31732533/s3-cors-always-send-vary-origin)

Later, I adopted one of the solutions inside: "Since S3 needs an origin header to enable CORS, let's send a fixed origin to it using Cloudfront! This way, every response will definitely have `Access-Control-Allow-Origin`!" 

You can refer to this article: [AWS CloudFront + S3 + Allow all CORS](http://strd6.com/2017/05/aws-cloudfront-s3-allow-all-cors/), which is basically just adjusting a setting.

This trick sounds quite effective, but it is not the best solution. It feels a bit dirty, after all, origin is not used in this way. It doesn't seem too good to do this for the S3 mechanism.

So in the end, I thought of something that also solved a doubt in my mind.

That is to add `crossorigin="anonymous"` to `<script>`, so that the request sent by `<script>` also has an origin header!

I have seen some places add this before, but I still don't understand why it needs to be added, because scripts can be unrestricted by domain. Why do you need to add a tag to make it look like an ajax request?

But unexpectedly, this attribute helped me. Once I added it, the script loading would attach Origin, and S3 would return `Access-Control-Allow-Origin`, so I wouldn't encounter cross-domain issues later!

As for the other functions of this attribute, you can refer to: [Purpose of the crossorigin attribute …?](https://stackoverflow.com/questions/18336789/purpose-of-the-crossorigin-attribute)

# Conclusion

To encounter the problem I encountered, you must meet the following four conditions at the same time:

1. You put the static files on S3
2. You did not check the browser's Disable cache
3. You used script and SW to load the same file
4. The browser uses the cached script response to respond to the SW request

If any of the conditions are not met, this problem will not occur. In other words, it is quite difficult to encounter this problem. 

But the more pits you step on, the stronger you become. Solving one problem means you have one less problem to encounter in the future. After solving this CORS-related problem, I think I won't encounter related problems in the future... I hope.
