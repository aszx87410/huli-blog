---
title: An interesting styled components bug
date: 2020-07-11 16:06:54
catalog: true
tags: [Front-end]
categories:
  - Front-end
photos: /img/an-interesting-styled-components-bug/cover-en.png
---

## Introduction

While making some performance adjustments at work, I accidentally discovered a strange phenomenon. After investigating further, I found a bug that seemed to have gone unnoticed by anyone, and I found the cause quite interesting. So I thought I'd write a post to share it with everyone.

This post is not very technical, so you can read it with a story-telling mindset, which will make it more interesting.

## The Beginning of the Story

The origin of the story is that I was making some adjustments to a website at work, trying to improve its loading speed. When it comes to performance optimization, there are many things that can be done. For example, with regard to the server, the following are more relevant:

1. Use HTTP/2
2. Use gzip or brotli for compression
3. Use Cache (to speed up revisits)
4. Use CDN
5. Reduce TTFB time

However, all of the above require assistance from the backend or SRE, and are not very relevant to the frontend. With regard to the frontend, there are many aspects to consider. For example, from the perspective of "reducing resources," the following can be done:

1. Image format adjustment (compression + webp or other formats)
2. JS size (ugligy, code splitting, dynamic import)
3. CSS size (minify, remove unnecessary CSS)

From the perspective of "accelerating the loading of important resources," preload or preconnect hints can be added to indicate to the browser which things should be loaded first.

You can also look at it from the perspective of "reducing JS execution time." For example, if you are writing React, you can use shouldComponentUpdate, PureComponent, or memo to reduce unnecessary re-renders.

Since the title of this post is "styled components," the main topic is, of course, centered around CSS.

<!-- more -->

In the CSS part, in order to reduce the first loading time, one trick is to inline critical CSS in the HTML, so that you don't have to make another request to get the CSS back, which saves one round-trip. However, this will also affect the size of the HTML, but not by much.

Anyway, we used this trick on our website and inline CSS in the HTML, which looks like this:

![css1](/img/sc/css1.png)

A lot of dense CSS.

And what caught my attention the most were those vendor prefixes:

![css1](/img/sc/css2.png)

Due to various historical factors, some CSS properties need to be prefixed to work. For example, if you want to use flexbox on an older version of IE, you need to write: `display: -ms-flexbox;`. And I looked at the prefixes we have on our website, which are probably:

1. display: -ms-flexbox
2. display: -webkit-flex
3. -ms-flex-wrap: wrap
4. -webkit-flex-wrap: wrap
5. -ms-transform: rotate(45deg)
6. -webkit-transform: rotate(45deg)
7. -ms-letter-spacing: 0.03em
8. -webkit-letter-spacing: 0.03em
9. ....more

These prefixes are all added by styled components. Here's a brief introduction to styled components. In short, you can use this syntax to add CSS to a component:

``` jsx
import styled from 'styled-components';

const Box = styled.div`
  background: red;
`
// use it like this
<Box />
```

The principle behind it is that styled components will convert the style you write into a className and put it on the component for you. Vendor prefixes are also part of what it handles.

Everything seems fine, but there is room for improvement.

In our project, we have already determined the level of browser support, and we don't need to support IE. Since we don't need to support IE, many prefixes starting with `-ms` are not necessary, and removing them will save space, so it's better to remove them.

But how do we remove them?

## Removing Extra Prefixes

For this need to add the correct prefix to CSS, there is a well-known tool called [Autoprefixer](https://github.com/postcss/autoprefixer):

![autoprefixer](/img/sc/autoprefixer.png)

This tool is very simple. You just need to give it your entire CSS, and it will help you convert it into the correct form, which means:

1. Add necessary prefixes
2. Remove unnecessary prefixes

How does it know what is necessary?

This is the best part. It supports something called [Browserslist](https://github.com/browserslist/browserslist). Simply put, you can write a file that specifies which browsers your project needs to support, like this:

```
# Browsers that we support

defaults
not IE 11
not IE_Mob 11
> 1%
```

You can also use syntax like `> 1%` to let it grab the usage rate of browsers that are used more than 1% and add them to the list. So with this list and Autoprefixer, you can generate streamlined CSS and remove unnecessary vendor prefixes.

How do you use this tool with styled components?

In styled components, there is something called StyleSheetManager, which added two parameters in v5:

1. disableVendorPrefixes
2. stylisPlugins

The first parameter removes all vendor prefixes, so it won't automatically add them:

``` js
// example from official docs
import styled, { StyleSheetManager } from 'styled-components'

const Box = styled.div`
  color: ${props => props.theme.color};
  display: flex;
`

render(
  <StyleSheetManager disableVendorPrefixes>
    <Box>If you inspect me, there are no vendor prefixes for the flexbox style.</Box>
  </StyleSheetManager>
)
```

The second parameter `stylisPlugins` is actually the key point. The official example is like this:

``` js
import styled, { StyleSheetManager } from 'styled-components'
import stylisRTLPlugin from 'stylis-plugin-rtl';

const Box = styled.div`
  background: mediumseagreen;
  border-left: 10px solid red;
`

render(
  <StyleSheetManager stylisPlugins={[stylisRTLPlugin]}>
    <Box>My border is now on the right!</Box>
  </StyleSheetManager>
)
```

Simply put, styled components use a package called stylis in the underlying layer, and this package can pass custom plugins to do some conversion. It sounds like a very promising approach, but the official documentation doesn't cover it much. So I went to study the code of styled components and found out how to write this plugin by looking at [this section](https://github.com/styled-components/styled-components/blob/master/packages/styled-components/src/utils/stylis.js#L69):

``` js
  /**
   * When writing a style like
   *
   * & + & {
   *   color: red;
   * }
   *
   * The second ampersand should be a reference to the static component class. stylis
   * has no knowledge of static class so we have to intelligently replace the base selector.
   *
   * https://github.com/thysultan/stylis.js#plugins <- more info about the context phase values
   * "2" means this plugin is taking effect at the very end after all other processing is complete
   */
  const selfReferenceReplacementPlugin = (context, _, selectors) => {
    if (context === 2 && selectors.length && selectors[0].lastIndexOf(_selector) > 0) {
      // eslint-disable-next-line no-param-reassign
      selectors[0] = selectors[0].replace(_selectorRegexp, selfReferenceReplacer);
    }
```

However, the link attached inside doesn't seem to have any information related to the plugin... So I turned to study the package that appeared in the example: [stylis-plugin-rtl](https://github.com/styled-components/stylis-plugin-rtl/blob/master/src/stylis-rtl.js), and its source code is much more detailed:

``` js
// @flow

import cssjanus from "cssjanus";

// https://github.com/thysultan/stylis.js#plugins
const STYLIS_CONTEXTS = {
  POST_PROCESS: -2,
  PREPARATION: -1,
  NEWLINE: 0,
  PROPERTY: 1,
  SELECTOR_BLOCK: 2,
  AT_RULE: 3
};

export type StylisContextType = $Values<typeof STYLIS_CONTEXTS>;

// We need to apply cssjanus as early as possible to capture the noflip directives if used
// (they are not present at the PROPERTY, SELECTOR_BLOCK, or POST_PROCESS steps)
export const STYLIS_PROPERTY_CONTEXT = STYLIS_CONTEXTS.PREPARATION;

function stylisRTLPlugin(context: StylisContextType, content: string): ?string {
  if (context === STYLIS_PROPERTY_CONTEXT) {
    return cssjanus.transform(content);
  }
}

// stable identifier that will not be dropped by minification unless the whole module
// is unused
/*#__PURE__*/
Object.defineProperty(stylisRTLPlugin, "name", { value: "stylisRTLPlugin" });

export default stylisRTLPlugin;
```

I have seen similar plugin writing methods before, so I can quickly get into the situation. Stylis will provide you with several different contexts and contents. You can decide what to do based on the context and pass back the processed style.

Therefore, our plugin can be written like this:

``` js
import autoprefixer from 'autoprefixer';
import postcss from 'postcss';

const POST_PROCESS_CONTEXT = -2;
function plugin (context, content) {
    if (context !== POST_PROCESS_CONTEXT) {
      return content;
    }

    return postcss([autoprefixer]).process(content).css;
}
```

Call postcss in the post process stage, and use autoprefixer to convert the content. Finally, you can get clean CSS.

## Results

Here's how effective it is. Before using it, I counted the number of prefixes in the CSS (directly using global search):

* -webkit: ~300
* -ms: ~200
* -moz: ~60
* -o: 1

A total of about 560.

After using Autoprefixer, it becomes:

* -webkit: ~300 => 26
* -ms: ~200 => 6
* -moz: ~60 => 13
* -o: 1 => 0

From 560 to about 45, reducing about 90% of unnecessary vendor prefixes!

The size of the entire HTML + inline CSS was 43KB after gzip compression before. You can guess how much it became after making this change.

.  
.  
.  
.  
.  
.  
.  
.  
.  
.  
.  
.  
.  

The answer is: 42KB!

Yes, you read that right, it only reduced by 1KB.

When I saw this result, I learned two things:

1. gzip is powerful
2. Optimization needs to be measured. Sometimes you think you have improved a lot, but you haven't

I guess the reason why it only reduced by 1KB is that after gzip, there is actually not much difference. Although the number of prefixes has been greatly reduced, it won't really save that much space. The information remembered by gzip may have changed from "300 webkits" to "26 webkits", but it's just a reduction in the number, so there is no improvement in file size.

Although the file size has not been reduced much, there are still some improvements. The task has been successfully completed.

## What about the bug?

Okay, you might be thinking at this point: "I learned a trick... wait, isn't this article about bugs? Where's the bug? Why didn't I see anything that looks like a bug?"

In fact, the bug is hidden in a list I compiled earlier:

1. display: -ms-flexbox
2. display: -webkit-flex
3. -ms-flex-wrap: wrap
4. -webkit-flex-wrap: wrap
5. -ms-transform: rotate(45deg)
6. -webkit-transform: rotate(45deg)
7. -ms-letter-spacing: 0.03em
8. -webkit-letter-spacing: 0.03em
9. ....more

If you look closely, you will notice a strange property called `letter-spacing`. When I first saw it, I thought I was not skilled enough. After all, I've been writing CSS for so many years, and I didn't know that `letter-spacing` needed a prefix to work. So I went to caniuse to check it out and found that, as I remembered, it didn't need one.

So why is it here?

Out of curiosity, I looked at the source code of stylis. By the way, I mentioned earlier that there was no introduction to the plugin in the styled components source code link, which was due to version issues. Stylis was updated to v4 in April 2020, while styled components used v3.5.4.

To be more precise, styled components actually depends on `@emotion/stylis v0.8.4` (yes, another library called emotion), and this emotion's stylis depends on the real stylis 3.5.4 version.

So this letter-spacing issue is not just with styled components, but also with emotion. Here's a demo on codesandbox: https://codesandbox.io/s/stylis-bug-6yu6g?file=/src/App.js

When you open it and right-click on the element above, you can see:

![code](/img/sc/code.png)

Now that I know it was a version issue, I can find the correct version of the source code to look at, which is a very large file: https://github.com/thysultan/stylis.js/blob/v3.5.4/stylis.js

I extracted the most essential part, the vendor-prefixed part (with some code omitted):

``` js
function property (input, first, second, third) {
  var index = 0
  var out = input + ';'
  var hash = (first*2) + (second*3) + (third*4)
  var cache

  // animation: a, n, i characters
  if (hash === 944) {
    return animation(out)
  } else if (prefix === 0 || (prefix === 2 && !vendor(out, 1))) {
    return out
  }

  // vendor prefix
  switch (hash) {
    // text-decoration/text-size-adjust/text-shadow/text-align/text-transform: t, e, x
    case 1015: {
      // text-shadow/text-align/text-transform, a
      return out.charCodeAt(10) === 97 ? webkit + out + out : out
    }
    // filter/fill f, i, l
    case 951: {
      // filter, t
      return out.charCodeAt(3) === 116 ? webkit + out + out : out
    }
    // color/column, c, o, l
    case 963: {
      // column, n
      return out.charCodeAt(5) === 110 ? webkit + out + out : out
    }
    // box-decoration-break, b, o, x
    case 1009: {
      if (out.charCodeAt(4) !== 100) {
        break
      }
    }
    // mask, m, a, s
    // clip-path, c, l, i
    case 969:
    case 942: {
      return webkit + out + out
    }
    // appearance: a, p, p
    case 978: {
      return webkit + out + moz + out + out
    }
  }
}
```

It looks like it adds a comment for each prefix, so I searched for `letter-spacing` and found nothing. This made things interesting, as it seems that the behavior of adding a vendor prefix to `letter-spacing` was not intentional.

Next, let's take a look at how it adds prefixes. It first hashes the property through a custom hash: `var hash = (first*2) + (second*3) + (third*4)`, then checks the result of the hash and adds the prefix based on the result.

Let's hash `letter-spacing`:

``` js
function hash(str) {
  return str.charCodeAt(0) * 2 +
    str.charCodeAt(1) * 3 +
    str.charCodeAt(2) * 4
} 

console.log(hash('letter-spacing')) // 983
```

Then search for 983 in the source code:

![hash](/img/sc/hash.png)

The mystery is solved!

It turns out to be a bug caused by hash collision! I've heard many suggestions that hash functions should not be defined by oneself, but I never thought I would see a real-world case of a collision caused by a custom hash function.

The string `user-select` also hashes to 983, just like `letter-spacing`. Therefore, when converting `letter-spacing`, it will run into this case and add a vendor prefix to `letter-spacing`.

So let's correct the title here. It's not a bug in styled components, but a bug in stylis. However, both styled components and emotion use stylis, so they both have this bug.

## Follow-up

I searched through the repos of styled, emotion, and styled components, and it seems that no one has noticed this issue. However, I did find a PR for emotion that updates stylis to v4: [Stylis v4 #1817](https://github.com/emotion-js/emotion/pull/1817), which has already been merged recently. So the next version of emotion (which should be a major version update because it's a breaking change) will not have this issue.

And I also posted an issue to stylis about this: [Redundant css vendor prefix for letter-spacing in v3 #223](https://github.com/thysultan/stylis.js/issues/223). However, it seems that there is nothing they can do about it, and this is a bug in the old version that has been fixed in the new version, so it will not be fixed in the old version.

Finally, I also posted an issue to styled components about this: [Redundant css vendor prefix for letter-spacing #3157](https://github.com/styled-components/styled-components/issues/3157), but no one has responded yet.

I also submitted a PR to update the document URL: [Update stylis plugin docs url #3156](https://github.com/styled-components/styled-components/pull/3156), to avoid others having the same problem finding the plugin documentation.

## Summary

In fact, I learned a lot from this incident.

The first point is that I discovered an interesting bug caused by hash collision.

The second point is that I originally thought that removing those 500+ prefixes would reduce the file size a bit, but after measuring it, it only reduced 1KB. Many times I forget to consider the factor of gzip. After this incident, I won't forget it again.

The third point is that I found that I seem to have a mentality of "must fix the bug", but in the real world, it is not so ideal, after all, there is a priority for doing things.

Although adding prefixes to letter-spacing is indeed a redundant thing, what is the impact? It just increases a little bit of insignificant file size and looks a bit strange. To be honest, it is not a serious bug. Even if it is not fixed, it does not have much impact, and the webpage will not be affected. Therefore, it is a harmless bug.

So through this incident, I have reorganized my mentality when facing bugs.

That's about it for this article. If your website also uses emotion or styled components, why not check if you also have this letter-spacing issue!
