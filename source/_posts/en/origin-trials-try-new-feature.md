---
title: Trying out new features with Chrome Origin Trials
catalog: true
date: 2022-02-02 19:27:06
tags: [Front-end]
categories: [Front-end]
---

If your website wants to experience new features that have not yet been officially launched by the browser, what should you do?

Usually, these features are already available, but not yet open. Therefore, browsers provide some flags that can be turned on and off. As long as the switch is turned on, you can experience the new features in advance. However, we usually cannot ask users to turn on the switch themselves.

Therefore, Chrome provides a mechanism called [origin trials](https://developer.chrome.com/blog/origin-trials/). You can register on the website to obtain a set of tokens. After setting it up, if the user visits your website with Chrome, the new feature will be turned on, allowing your website to use it.

This article will briefly introduce how to use this mechanism.

<!-- more -->

## Choosing features

This page lists all the features currently provided by Chrome Origin Trials: https://developer.chrome.com/origintrials/#/trials/active

![feature list](/img/origin-trial/p1-all.png)

After clicking on each feature, there will be detailed explanations. For example, if we click on "App History API", we will see a detailed explanation:

![detail](/img/origin-trial/p2-detail.png)

Above will briefly introduce what this feature does, as well as the open version and end date. Usually, two resources will be provided, such as "Learn More". After clicking it, it may link to an article introducing the basic usage of this feature, like this article: [Modern client-side routing: the App History API](https://web.dev/app-history-api/), which introduces the basic usage of App History API.

The other resource is Chrome Platform Status. After clicking it, a more detailed page will appear, which gives the current status and expected release time, as well as the link to the spec, and whether other browsers will follow this feature:

![status](/img/origin-trial/p3-spec.png)

Most of the features that will be opened to origin trials are new features, but a few will be features that have been deprecated or are about to be deprecated.

Why is this? Because some websites may need more time to update, they can come here to apply for origin trials, and the browser will keep the old features first, allowing the website more time to update. Therefore, origin trials not only provide new features, but also features that have been deprecated.

In short, if you are curious about which new features can be tried out, you can come to this website to find out.

## Trying out features

Next, let's actually try out the App History API feature. This new feature is designed for SPAs, because when the existing History API was born, SPAs had not yet become popular, so many requirements were not met and a new set of APIs was needed.

For detailed introduction, please refer to: [Modern client-side routing: the App History API](https://web.dev/app-history-api/)

In short, if this feature can be used, we should be able to access `appHistory`. Now, because the feature has not been opened, accessing it will only result in the error: `Uncaught ReferenceError: appHistory is not defined`.

After selecting the desired feature on the Chrome Origin Trials page, click REGISTER, and you will be taken to the registration page. Then you need to enter the origin of the website you want to try out, after all, it's called origin trials, which means "specify which origins can try out", like this:

![form](/img/origin-trial/p4-form.png)


After the application is completed, you will be given a set of tokens and an expiration time, which will tell you when you can use it, like this:

![token](/img/origin-trial/p5-token.png)

Next, it's very simple, just add a meta tag to the page you want to try out:

``` html
<meta http-equiv="origin-trial" content="TOKEN">
```

You can also use the HTTP header: `Origin-Trial: TOKEN `

For the convenience of the demo, I have prepared a page with the following content:

``` html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="robots" content="noindex">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="X-UA-Compatible" content="ie=edge">
  <meta http-equiv="origin-trial" content="AnmLpSv09ah5QRsTiszCUGI8WzgiH5OByD2I/kQjnbSSmN2DMnuvRsbPWfqN7QmDJbNH6cUBvsay+UlJBwQyXwcAAABXeyJvcmlnaW4iOiJodHRwczovL2Fzeng4NzQxMC5naXRodWIuaW86NDQzIiwiZmVhdHVyZSI6IkFwcEhpc3RvcnkiLCJleHBpcnkiOjE2NDc5OTM1OTl9">
</head>
<body>
  origin trial demo
  <script>
    if (window.appHistory) {
      document.writeln('appHistory exists!')
    } else {
      document.writeln('appHistory is not defined')
    }
  </script>
</body>
</html>
```

It will detect whether there is an `appHistory` and display the result on the screen.

After setting up, visit this page: https://aszx87410.github.io/demo/misc/origin-trial.html

If you open it with a browser other than Chrome, you will see "appHistory is not defined". If you use Chrome, you should see "appHistory exists!".

Open devtool -> Application -> Frames -> top, and you can see that we have successfully enabled origin trials:

![devtool](/img/origin-trial/p6-devtool.png)

Yes, the whole process is that simple.

## Conclusion

This article briefly introduces the mechanism of Origin Trials. Through this mechanism, you can apply for a set of tokens and put them on the website. Then, Chrome users can try new features in advance.

For example, the three.js example page uses origin trial to enable WebGPU-related functions: [three.js/examples/webgpu_skinning.html](https://github.com/mrdoob/three.js/blob/r137/examples/webgpu_skinning.html#L9)

In addition, even if you don't want to experience new features, you can occasionally come here to take a look. Just by looking at it, you can gain a lot. For example, I saw "App History API", "Private Network Access from non-secure contexts", and "User Agent Reduction" from the list, which I have never heard of before.
