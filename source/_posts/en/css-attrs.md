---
title: Some useful CSS properties that are not easy to remember
catalog: true
date: 2021-04-17 22:27:27
tags: [Front-end]
categories:
  - Front-end
---

## Introduction

After writing CSS for a while, we should all be familiar with common properties such as display, position, padding, margin, border, background, etc. We can write them smoothly without having to look up anything.

These properties are common because they are used in many places. However, some CSS properties can only be used in specific places or under specific circumstances. I often forget these less commonly used properties, but they are actually very important in some cases.

Therefore, in this article, I want to introduce some CSS properties that I think are not easy to remember but are very useful. This is also a note for myself.

<!-- more -->

## The outline and color of the input box

Compared with border, outline is a less common property, but it is particularly useful when applied to input. By default, when you focus on an input, a blue circle appears around it:

![](https://static.coderbridge.com/img/aszx87410/20397c22ae6d44a28b9444b12bea3723.gif)

That blue circle is the outline, which can be confirmed through Chrome devtool:

![](https://static.coderbridge.com/img/aszx87410/83fd44bc13d54182a1deb221ba0d4792.png)

So if you don't want an outline or want to change its color, you can use the outline property to modify it.

The vertical line that keeps flashing after focusing is called the caret. If you want to change its color, you can use the caret-color property:

![](https://static.coderbridge.com/img/aszx87410/7d0fa9146b51406ab481f82cf6b0d113.png)

## The blue box when clicking

I remember that when I clicked on something on my phone, a blue box or something similar appeared. However, I couldn't reproduce it just now. The corresponding property is called `-webkit-tap-highlight-color`, and you can search for other articles and examples using this keyword.

## Movement beyond the range when scrolling

I don't know how to describe this clearly, so let's look at the picture:

![](https://static.coderbridge.com/img/aszx87410/e5f88faa32e84b929f19dd07f4b5f39a.gif)

Sometimes on mobile devices, you can scroll beyond the page and see the white background, or some browsers have a pull-to-refresh function. When you scroll down from the top of the page, it will refresh.

If you want to prevent this behavior, you can use the `overscroll-behavior` property.

For more detailed introduction, please refer to: [Take control of your scroll: customizing pull-to-refresh and overflow effects](https://developers.google.com/web/updates/2017/11/overscroll-behavior)

## Smooth scrolling

Many websites have a function where the headings of each paragraph of an article appear on the right side. Clicking on them will quickly scroll to that paragraph.

If nothing is set, clicking will jump directly to that paragraph. However, there is a thing called smooth scrolling, which has some transitions in the middle and lets the user know where they are scrolling to.

A long time ago, this function may have required JS, but now it can be done with the CSS `scroll-behavior: smooth;` (the example below is from [MDN](https://developer.mozilla.org/zh-CN/docs/Web/CSS/scroll-behavior)):

![](https://static.coderbridge.com/img/aszx87410/3cd94361cae14ac69eeef2a9a20d1406.gif)

## Scroll position when loading new content

Many websites automatically load more content when you scroll to the bottom. When loading more content, you would expect the user to stay in the same position and not automatically scroll down because of the new content.

However, sometimes the default behavior of the browser is not as expected. When you load more elements, the screen may not stay in the position you imagined.

At this time, you can use the `overflow-anchor` CSS property to adjust this behavior. For details, please refer to: [CSS overflow-anchor property and scroll anchoring](https://www.zhangxinxu.com/wordpress/2020/08/css-overflow-anchor/)

## Slide one element at a time

Sometimes we need an effect where the user can slide to the next element with just a light swipe, instead of sliding to anywhere on the page. This can be achieved using `scroll-snap` related properties, like this:

![](https://static.coderbridge.com/img/aszx87410/dbe5f93d8df548d7ac0355638c974060.gif)

This feels quite useful when making a carousel. For more usage examples, you can refer to [Practical CSS Scroll Snapping](https://css-tricks.com/practical-css-scroll-snapping/), where the example above is also from.

## 300ms click delay on mobile

Many people know that there is a delay of about 300ms for click events on mobile devices, which means that you have to wait 300ms after clicking before the click event is triggered. This delay exists because on mobile devices, you can double-tap to zoom in, so when you click for the first time, the browser doesn't know if you want to click twice or just once, so it needs to wait for a period of time.

This delay seems to have been removed before, but if you still encounter it, you can use the `touch-action: manipulation` CSS property to solve it. This property can disable some gestures.

For more details, you can refer to [MDN](https://developer.mozilla.org/zh-CN/docs/Web/CSS/touch-action), or this article: [300ms tap delay, gone away](https://developers.google.com/web/updates/2013/12/300ms-tap-delay-gone-away).

By the way, I saw this CSS property on Facebook's website.

## font-smooth

I saw this property in the default [css](https://github.com/facebook/create-react-app/blob/master/packages/cra-template/template/src/index.css#L6) of Create React App:

```
body {
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
}
```

In fact, these two properties can be found on many websites. I found out that they are related to font rendering. For example, antialiased is actually the "anti-aliasing" that everyone should have heard of. You can decide how to render the font yourself.

For more details, you can refer to:

1. [Understanding CSS properties font-kerning, font-smoothing, font-variant](https://www.zhangxinxu.com/wordpress/2017/02/font-kerning-font-smoothing-font-variant/)
2. [What is font smoothing in CSS?](https://www.educative.io/edpresso/what-is-font-smoothing-in-css)

## Conclusion

This article is a simple note on some CSS properties that I find difficult to remember, because I don't use them frequently, so I easily forget their names when I actually need to use them. If the keywords are not correct, it is difficult to find out what the property is called.

One of the reasons why I wanted to write this article is because a friend asked me how to solve a certain behavior, and I originally thought it was impossible or had to be done with JS, but later I found out that it could be solved with CSS. Because I knew that property, I was able to solve it, so it is very helpful to look at more CSS properties in your spare time. At least when you encounter a problem, you will know that you can use CSS to solve it.

If you also know some CSS properties like this, feel free to share them with me.
