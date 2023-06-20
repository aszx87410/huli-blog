---
title: Why is Vite so fast? Starting with ES modules
catalog: true
date: 2020-08-07 23:21:12
tags: [JavaScript, Front-end]
categories:
  - Front-end
---

## Introduction

Have you ever heard of [vite](https://github.com/vitejs/vite)? With a name starting with "v", you might guess that it's related to Vue. Yes, it's another tool developed by the creator of Vue, Evan You. Originally intended for use with [VuePress](https://vuepress.vuejs.org/), it has proven to be much more versatile.

On the GitHub page for Vite, there are only two sentences:

> Native-ESM powered web dev build tool. It's fast.

If you've tried it, you'll know that it really is fast. Vite is a combination of a build tool and a dev server. In this article, we'll briefly introduce how to use Vite, then talk about ES modules, and finally explore the magic of Vite.

<!-- more -->

## Exploring Vite

Let's start by discussing what Vite does. We can see from its positioning that it is a build tool + dev server. Let's focus on the latter. The dev server is like the webpack dev server + hot module reload that we use with webpack. It provides a local development environment that automatically updates the entire app when we save a file. It's an indispensable tool for front-end development.

Vite's concept is similar. It provides a "faster dev server" for us to use during development.

Let's go through the process.

Although Vite integrates best with Vue, it is not exclusively a Vue tool. In fact, you can use it to develop anything, and Vite also provides a React template.

Let's use React as an example:

``` js
npm init vite-app react-demo --template react
cd react-demo
npm install
npm run dev
```

With just these four lines of code, you can experience the power of Vite. The first line uses Vite's tools to generate a boilerplate, and then you can start developing by entering the folder.

After a successful installation, the terminal will tell you that the dev server is running. Then open: [http://localhost:3000](http://localhost:3000), and you'll see the familiar spinning React logo.

![](/img/vite/vite01.png)

Next, let's try opening `src/App.jsx` and making some changes. You'll see that the React app updates very quickly. Vite is much faster than create-react-app or webpack dev server, both in terms of startup speed and update speed. Some people have compared the two on [Twitter](https://twitter.com/swyx/status/1290410811802804226), and Vite is clearly the winner.

Why is Vite so fast? It's because of Native ES Modules. So next, let's take a look at what Native ES Modules are.

## Native ES Modules

Before we continue, I suggest that you first understand the history of module development in JavaScript. You can refer to my previous article: [A Beginner's Guide to Webpack: An Introduction to Modularity and Snowpack](https://blog.huli.tw/2020/01/21/webpack-newbie-tutorial/).

In the article, I mentioned that there was no native module mechanism in browsers in the early days, so various standards were created, such as CommonJS, AMD, or UMD. However, this changed with ES6, because the ES6 specification finally included modules! We call this ES Modules, or ESM for short.

ESM is a specification that you've probably used before, which looks like this:

```
// a.js
export const PI = 3.14

// b.js
import { PI } from './a'
```

If you see `export` and `import`, it's probably ESM syntax. In addition to the specification, what's even more exciting is that all mainstream browsers now natively support ESM!

I've created a simple demo website here: https://aszx87410.github.io/esm-demo/vanilla/index.html

After opening it, you can open the devtool and switch to the network tab. You'll see that both index.js and utils.js use ESM syntax:

![](/img/vite/vite02.png)

Vite uses the native ESM loading mechanism, which is Native ESM, allowing the browser to handle these import and export things for you.

Wait, I just emphasized the word "native". Does that mean there are other things that are not native? Yes, that's right. The webpack or similar tools you usually use, don't forget that its name is "bundler", which is to bundle your JS files and dependencies together. Although you use import and export correctly when writing code, it may have been converted to CommonJS or other forms by babel or webpack when output, and there is also an outer layer to handle the syntax of `require`.

And this is also the reason why webpack and other bundling tools are slow. They need to statically analyze all files and package dependencies of the app, and then package things together based on this information. When your file becomes larger and larger, the time spent naturally increases because webpack needs to figure out how to package it.

If we can avoid bundling and not package everything together, will it be much faster?

Yes, this is why Vite is so fast.

## Exploring Vite again

In the earlier article, I mentioned snowpack. In fact, the concept of snowpack is quite similar to Vite, both of which use the Native ESM solution. Instead of bundling everything together, it is better to use the browser well and let the browser handle those complex dependencies.

For example, snowpack will put the node_modules you use in a specific place so that you can import them.

Next, let's take a look at Vite. Open the demo project we just installed, turn on devtool, and switch to network. It is clear at a glance:

![](/img/vite/vite03.png)

The principle is quite similar to snowpack, both using ESM to load different packages, which is why there are so many requests in the browser.

Click on `main.jsx` to see the code inside:

``` js
import React from "/@modules/@pika/react/source.development.js";
import ReactDOM from "/@modules/@pika/react-dom/source.development.js";
import "/src/index.css?import";
import App2 from "/src/App.jsx";
ReactDOM.render(/* @__PURE__ */ React.createElement(React.StrictMode, null, /* @__PURE__ */ React.createElement(App2, null)), document.getElementById("root"));
```

On the server side, Vite will help us transform the program a bit. Here, it will replace `import React from 'react'` in the program and change the path to its own prepared React build. This is because React official currently does not have an ESM build! What everyone is using now seems to be a mixture of UMD and CommonJS. There are plans for the future, but it may take some time. For details, please refer to: [#11503 Formalize top-level ES exports](https://github.com/facebook/react/issues/11503).

Although the official version does not exist, someone in the community has already done it, so the community version is used here. By the way, I will add one more thing. The original `import React from 'react'` is called "bare module imports", and "bare" refers to the `react` behind it, which is not a file path. According to Evan You, this is undefined behavior in the ESM standard, so it needs to be handled specially.

If we change the ESM small example we tried earlier, `import { add } from './utils.js'` to `import { add } from 'utils.js'`, this error will appear:

> Uncaught TypeError: Failed to resolve module specifier "utils.js". Relative references must start with either "/", "./", or "../".

So it must start with `/`, `./`, or `../`.

Next, let's take a look at `App.jsx`:

``` jsx
import { createHotContext } from "/vite/client"; import.meta.hot = createHotContext("/src/App.jsx");   import RefreshRuntime from "/@react-refresh";  let prevRefreshReg;  let prevRefreshSig;  if (!window.__vite_plugin_react_preamble_installed__) {    throw new Error(      "vite-plugin-react can't detect preamble. Something is wrong. See https://github.com/vitejs/vite-plugin-react/pull/11#discussion_r430879201"    );  }  if (import.meta.hot) {    prevRefreshReg = window.$RefreshReg$;    prevRefreshSig = window.$RefreshSig$;    window.$RefreshReg$ = (type, id) => {      RefreshRuntime.register(type, "/Users/huli/Documents/lidemy/test/react-demo/src/App.jsx" + " " + id)    };    window.$RefreshSig$ = RefreshRuntime.createSignatureFunctionForTransform;  }var _s = $RefreshSig$();

import React, { useState } from "/@modules/@pika/react/source.development.js";
import logo2 from "/src/logo.svg?import";
import "/src/App.css?import";

function App2() {
  _s();

  const [count, setCount] = useState(0);
  return /* @__PURE__ */React.createElement("div", {
    className: "App"
  }, /* @__PURE__ */React.createElement("header", {
    className: "App-header"
  }, /* @__PURE__ */React.createElement("img", {
    src: logo2,
    className: "App-logo",
    alt: "logo"
  }), /* @__PURE__ */React.createElement("p", null, "Hello Vite + React!wwaaaa"), /* @__PURE__ */React.createElement("p", null, /* @__PURE__ */React.createElement("button", {
    onClick: () => setCount(count2 => count2 + 1)
  }, "count is: ", count)), /* @__PURE__ */React.createElement("p", null, "Edit ", /* @__PURE__ */React.createElement("code", null, "App.jsx"), " and save to test HMR updates."), /* @__PURE__ */React.createElement("a", {
    className: "App-link",
    href: "https://reactjs.org",
    target: "_blank",
    rel: "noopener noreferrer"
  }, "Learn React")));
}

_s(App2, "oDgYfYHkD9Wkv4hrAPCkI/ev3YU=");

_c = App2;
export default App2;

var _c;

$RefreshReg$(_c, "App2");
  if (import.meta.hot) {
    window.$RefreshReg$ = prevRefreshReg;
    window.$RefreshSig$ = prevRefreshSig;

    import.meta.hot.accept();
    RefreshRuntime.performReactRefresh();
  }
```

You can see that the original jsx has been converted to JS on the server, and there is some code related to HMR (Hot Module Reload). If you try to modify the source code and save it, you will find that the URL of the network request has an additional timestamp:

![](/img/vite/vite04.png)

It can be guessed that this should be related to cache invalidation, to avoid loading the old one when reloading the module, so a timestamp is added to force re-fetching.

Finally, let's take a look at how CSS is handled:

``` js
import { updateStyle } from "/vite/client"
const css = ".App {\n  text-align: center;\n}\n\n.App-logo {\n  height: 40vmin;\n  pointer-events: none;\n}\n\n@media (prefers-reduced-motion: no-preference) {\n  .App-logo {\n    animation: App-logo-spin infinite 20s linear;\n  }\n}\n\n.App-header {\n  background-color: #282c34;\n  min-height: 100vh;\n  display: flex;\n  flex-direction: column;\n  align-items: center;\n  justify-content: center;\n  font-size: calc(10px + 2vmin);\n  color: white;\n}\n\n.App-link {\n  color: #61dafb;\n}\n\n@keyframes App-logo-spin {\n  from {\n    transform: rotate(0deg);\n  }\n  to {\n    transform: rotate(360deg);\n  }\n}\n\nbutton {\n  font-size: calc(10px + 2vmin);\n}\n"
updateStyle("\"7ac702d2\"", css)
export default css
```

Turn CSS into a string and then call the `updateStyle` function. As long as Vite is loaded on the client, `/vite/client` utils will be automatically loaded together, which will handle things like HMR or loading CSS. For example, the `updateStyle` above is in this file.

Alright, by now we have a general understanding of what Vite is. Why is it faster? Because webpack needs to bundle, but Vite doesn't, so it doesn't need to package all of your source code together. It only needs to start a local server so that your `import` can fetch the correct files. Without the need for packaging, the speed is naturally much faster, and this is the power of Native ESM.

## How about production?

Just run `npx vite build` to generate a production build, but the resulting file may disappoint you because, like webpack, it's a large package of `index.js` with all the code inside.

This is because production currently uses rollup to build, which is a traditional packaging strategy, no different from webpack. The reason is also stated in [Vite's docs](https://github.com/vitejs/vite#production-build):

> Vite does utilize bundling for production builds, because native ES module imports result in waterfall network requests that are simply too punishing for page load time in production.

Let me explain what this problem is. The problem comes from the dependencies between packages.

Suppose you use a package A that needs to load package B, and package B depends on package C, and so on, creating a long chain of dependencies that extends to the sky. The browser has to wait until all these packages are downloaded before it can start executing JavaScript. This is what the original text refers to as "waterfall network requests," so using this method in production is problematic.

Especially with HTTP/1.1, browsers have a parallel limit, mostly around 5, so if you have 60 dependencies to download, you have to wait for a long time. Although HTTP/2 can improve this problem to some extent, it still can't handle too many things.

So why isn't there a problem locally? Because the download time of the local server is almost 0! So this is an issue that only occurs in production. And this problem has already been addressed by some, such as [pika](https://www.pika.dev/about):

> Pika is building a world where third-party libraries can be loaded, cached, and shared across sites.

As I understand it, it's a bit like if everyone's ESM is downloaded from pika, the browser can cache these packages, and the downloaded ones don't need to be downloaded again, so the speed will be much faster. But of course, there are still other issues to be resolved, such as whether the browser will provide so much space for you to put things, and so on.

## Conclusion

Vite seems to have sparked a small trend recently, with some open-source projects asking if there is a chance to switch to Vite as a dev server. Although snowpack has been out for a while, this use of Native ESM should be better known when Vite becomes popular.

I personally think that when developing locally, ESM can indeed make things much faster, and it's a direction worth trying. I even think that in the future, this may be the standard development method, replacing the original bundler. And if we can solve the waterfall problem I just mentioned in production, we may be able to produce two targets: one is for modern browsers, which directly uses ESM + ES6 output, saving a lot of build time; the other is for older browsers, which uses the old way with webpack or rollup, etc.

Evan You previously recorded a podcast with Adam Wathan (author of Tailwind CSS), talking about why he wanted to make Vite, the future development direction of Vite, and the problems it may encounter in production builds, etc. I highly recommend everyone to listen to it: [140: Evan You - Reimagining the Modern Dev Server with Vite](https://player.fm/series/series-1401837/ep-140-evan-you-reimagining-the-modern-dev-server-with-vite).
