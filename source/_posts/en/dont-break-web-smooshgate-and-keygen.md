---
title: "Don’t break the Web: The Case of SmooshGate and <keygen>"
catalog: true
date: 2019-11-26 14:33:14
tags: [Web, Others]
categories:
  - Web
---

## Introduction

Recently, the second edition of YDKJS (You Don't Know JS) was released, called [YDKJSY](https://twitter.com/ydkjsy), where Y stands for Yet. Although the second edition is not yet complete, some of the initial chapters have already been made available on [GitHub](https://github.com/getify/You-Dont-Know-JS).

I read the first chapter, which talks about the history of JS. It mentioned an interesting issue:

> As such, sometimes the JS engines will refuse to conform to a specification-dictated change because it would break that web content.

> In these cases, often TC39 will backtrack and simply choose to conform the specification to the reality of the web. For example, TC39 planned to add a contains(..) method for Arrays, but it was found that this name conflicted with old JS frameworks still in use on some sites, so they changed the name to a non-conflicting includes(..). The same happened with a comedic/tragic JS community crisis dubbed "smooshgate", where the planned flatten(..) method was eventually renamed flat(..).

In summary, it means that sometimes the JS specification must compromise with reality (existing old implementations). For example, the Array was originally supposed to add a method called contains, but it was changed to includes due to issues. Flatten was also renamed to flat.

There is also a term "smooshgate" that was specially marked above. When searching for this keyword, it was found that it was an event that occurred around March last year, related to the aforementioned flatten. When I saw this, my first reaction was, "Huh, why don't I know anything?" After searching for information in Traditional Chinese, I found only this article that mentioned it: [SmooshGate](https://blog.othree.net/log/2018/05/28/smooshgate/) and this article that only touched on it: [[Note] 3 types of JavaScript object property characteristics](https://medium.com/@liuderchi/%E7%AD%86%E8%A8%98-3-%E7%A8%AE-javascript-%E7%89%A9%E4%BB%B6%E5%B1%AC%E6%80%A7%E7%9A%84%E7%89%B9%E6%80%A7-3b982f4c5695).

After carefully studying the origin and development of the matter, I found it to be an interesting topic, so I wrote this article to share it with everyone.

<!-- more -->

## SmooshGate Event

Most of the inspiration for this article comes from [#SmooshGate FAQ](https://developers.google.com/web/updates/2018/03/smooshgate), which explains the event very well. I recommend that you read it.

But if you're too lazy to read it, I'll briefly explain the origin and development of the matter below.

There is an organization called TC39, which stands for Technical Committee 39. It is responsible for matters related to the ECMAScript specification, such as deciding which proposals can pass and so on. Finally, those proposals will be included in the new ECMAScript standard.

Proposals are divided into five stages, from stage0 to stage4. I won't go into detail, but you can refer to [Championing a proposal at TC39](https://github.com/tc39/how-we-work/blob/master/champion.md) or [The TC39 Process](https://tc39.es/process-document/).

There was a proposal before TC39 called [Array.prototype.{flatten,flatMap}](https://github.com/tc39/proposal-flatMap) (flatten is now changed to flat).

For readers who are not familiar with what flatten does, it basically flattens nested things.

For example, in the following code:

``` js
let arr = [1, 2, [3], [4], [5, 6, 7]]
console.log(arr.flatten()) // [1, 2, 3, 4, 5, 6, 7]
```

The nested array is flattened, which means it is similar to the [flatten](https://lodash.com/docs/4.17.15#flatten) in lodash.

For detailed usage, please refer to [MDN](https://developer.mozilla.org/zh-TW/docs/Web/JavaScript/Reference/Global_Objects/Array/flat), which has an additional parameter called depth that allows you to specify the depth of the expansion.

[flatMap](https://developer.mozilla.org/zh-TW/docs/Web/JavaScript/Reference/Global_Objects/Array/flatMap) is to map first and then flatten, which should be familiar to friends who are familiar with RxJS (also known as mergeMap in RxJS, and mergeMap is more commonly used. Interested friends can also refer to this article: [concatAll and concatMap rather than flatten and flatMap](https://github.com/tc39/proposal-flatMap/issues/60)).

Well, this proposal seems good, but what are the problems?

The problem lies in a tool that a front-end newcomer may not have heard of: [MooTools](https://mootools.net/), which I have only heard of and never used. To quickly understand what it can do, please refer to this comparison article ten years ago: [jQuery vs MooTools](http://www.jqueryvsmootools.com/index_cn.html).

In MooTools, they define their own flatten method and do something similar to the following in the code:

``` js
Array.prototype.flatten = /* ... */;
```

This sounds like no problem, because even if flatten is officially included in the standard and becomes a native method, it will only be overwritten, and there will be no problem.

But the trouble is that MooTools also has a piece of code that copies all Array methods to Elements (MooTools' custom API):

``` js
for (var key in Array.prototype) {
  Elements.prototype[key] = Array.prototype[key];
}
```

The for...in syntax will iterate over all enumerable properties, and native methods are not included.

For example, running the following code in the Chrome devtool console:

``` js
for (var key in Array.prototype) {
  console.log(key)
}
```

Nothing will be printed out.

But if you add a few custom properties:

``` js
Array.prototype.foo = 123
Array.prototype.sort = 456
Array.prototype.you_can_see_me = 789
for (var key in Array.prototype) {
  console.log(key) // foo, you_can_see_me
}
```

Only custom properties will be enumerable, and native methods will not become enumerable even if you overwrite them.

So what is the problem? The problem is that when flatten has not yet become an Array method, it is just a MooTools custom property, which is enumerable, so it will be copied to Elements. However, when flatten is included in the standard and officially supported by browsers, flatten is no longer enumerable.

This means that `Elements.prototype.flatten` will become undefined, and all code that uses this method will fail.

At this point, you may naively think, "Then make flatten enumerable!" But this may cause more problems, because a bunch of old for...in will suddenly have an additional flatten property, which may cause other bugs.

The discussion thread that discovered this bug can be found here: [Implementing array.prototype.flatten broke MooTools' version of it.](https://bugzilla.mozilla.org/show_bug.cgi?id=1443630)

After the issue was raised, discussions began on what to replace "flatten" with. Someone suggested "smoosh" in the Issues section, which sparked a heated debate and led to the origin of the #SmooshGate incident. In addition to discussing the name change, some people even suggested letting those websites break.

The word "smoosh" is similar to "flatten" or other proposed words like "squash," all of which mean to flatten something. However, this word is very rare, and I had never heard of it before this incident. However, this proposal was never officially discussed by TC39.

At the May 2018 TC39 meeting, "flatten" was officially changed to "flat," ending the incident.

The timeline of this proposal is roughly as follows:

1. July 2017: Stage 0
2. July 2017: Stage 1
3. September 2017: Stage 2
4. November 2017: Stage 3
5. March 2018: Discovered that "flatten" would break MooTools
6. March 2018: Someone suggested renaming it to "smoosh"
7. May 2018: "flatten" was renamed to "flat"
8. January 2019: Stage 4

Out of curiosity, I looked up V8's commit and found that they implemented this feature in March 2018: [[esnext] Implement Array.prototype.{flatten,flatMap}](https://github.com/v8/v8/commit/697d39abff90510523f297bb8577d5c64322229f). The most noteworthy part of this is actually the testing section:

``` js
const elements = new Set([
  -Infinity,
  -1,
  -0,
  +0,
  +1,
  Infinity,
  null,
  undefined,
  true,
  false,
  '',
  'foo',
  /./,
  [],
  {},
  Object.create(null),
  new Proxy({}, {}),
  Symbol(),
  x => x ** 2,
  String
]);

for (const value of elements) {
  assertEquals(
    [value].flatMap((element) => [element, element]),
    [value, value]
  );
}
```

They threw all sorts of weird things in to test it.

The day after "flatten" was changed to "flat," V8 immediately made corrections: [[esnext] Rename `Array#flatten` to `flat`](https://github.com/v8/v8/commit/72f1abfbec0b8c798bc4cf150c774b5411d522ae).

In summary, the #SmooshGate incident is:

1. Someone proposed a new method: `Array.prototype.flatten`
2. It was discovered that it would break MooTools, so it had to be renamed
3. Someone suggested renaming it "smoosh," while others thought it shouldn't be renamed, leading to a discussion
4. TC39 decided to change it to "flat," and the matter was resolved

Some people may be confused about the second point and wonder why MooTools, which is so old, couldn't just break. This is where the principle of "Don't break the web" comes in.

This website, [Space Jam](https://www.spacejam.com/archive/spacejam/movie/jam.htm), has been running smoothly for 22 years because when developing new web standards, the principle of "Don't break the web" is always taken into account.

If you think about it carefully, you may realize that there are no breaking changes in the web domain. The JS syntax you could use before is still available, with some new additions, rather than changing or removing old things.

Because once a breaking change occurs, websites may suffer, with bugs or even complete breakdowns. In fact, many websites have not been maintained for years, but we should not let them break. If a new standard with breaking changes is established today, the users will be the ones who suffer. They will only know that the website is broken, but not why.

Therefore, in the SmooshGate incident, TC39 ultimately chose "to rename 'flatten' to 'flat,' even though it is not the most ideal naming, we cannot let those web pages break" over "flatten is the most semantically appropriate, so what if those old websites using MooTools break!"

However, this does not mean that once bad design appears, it cannot be removed.

In fact, some things have quietly been removed, but because they are too obscure, you and I may not have noticed.

The [WHATWG FAQ](https://whatwg.org/faq#removing-bad-ideas) states:

> That said, we do sometimes remove things from the platform! This is usually a very tricky effort, involving the coordination among multiple implementations and extensive telemetry to quantify how many web pages would have their behavior changed. But when the feature is sufficiently insecure, harmful to users, or is used very rarely, this can be done. And once implementers have agreed to remove the feature from their browsers, we can work together to remove it from the standard.

There are two examples mentioned below: `<applet>` and `<keygen>`.

Out of curiosity, I looked up some related information.

## Deprecated HTML tags

Raise your hand if you've heard of `<keygen>`? Those who raised their hands, please give them a round of applause. You're amazing and are now crowned the king of obscure HTML tags.

Even after looking at the examples on [MDN](https://developer.mozilla.org/en-US/docs/Web/HTML/Element/keygen), I still don't really understand what this tag does. I only know that it is a tag that can be used in forms and, as its name suggests, is used to generate keys related to certificates.

From the information provided by MDN in [Non-conforming features](https://html.spec.whatwg.org/multipage/obsolete.html#non-conforming-features), we can find other deprecated tags, such as:

1. applet
2. acronym
3. bgsound
4. dir
5. isindex
6. keygen
7. nextid

However, being marked as obsolete does not mean that they are useless. It simply means that you should not use these tags anymore. According to the "don't break the web" principle, some of these tags may still work. For example, the marquee tag that I used to love using when I was younger is also listed in Non-conforming features.

In another [DOM-related standard](https://html.spec.whatwg.org/multipage/dom.html#elements-in-the-dom), it explains how to handle HTML tags. I guess these are the tags that are really deprecated and have no effect:

> If name is applet, bgsound, blink, isindex, keygen, multicol, nextid, or spacer, then return HTMLUnknownElement.

If you try these tags on Chrome, for example:

``` html
<!DOCTYPE html>
<html>
  <head>
    <meta charset="UTF-8">
  </head>
  <body>
    <bgsound>123</bgsound>
    <isindex>123</isindex>
    <multicol>123</multicol>
    <foo>123</foo>
  </body>
</html>
```

You will find that they behave similarly to `<span>`. I guess Chrome treats these unrecognized tags as spans.

Out of curiosity, I also looked up the relevant code in Chromium. I used to search for code content directly on GitHub, but because the keywords I was searching for were too repetitive this time, I changed to searching for commit messages. This is where the importance of commit messages is fully highlighted. I found that Chromium's commit messages were well written.

For example, this commit: [Remove support for the obsolete <isindex> tag.](https://github.com/chromium/chromium/commit/dfd5125a0002df42aa6c6133b3aa591953880f4e)

```
This patch removes all special-casing for the <isindex> tag; it
now behaves exactly like <foo> in all respects. This additionally
means that we can remove the special-casing for forms containing
<input name="isindex"> as their first element.

The various tests for <isindex> have been deleted, with the
exception of the imported HTML5Lib tests. It's not clear that
we should send them patches to remove the <isindex> tests, at
least not while the element is (an obsolete) part of HTML5, and
supported by other vendors.

I've just landed failing test results here. That seems like
the right thing to do.

"Intent to Remove" discussion: https://groups.google.com/a/chromium.org/d/msg/blink-dev/14q_I06gwg8/0a3JI0kjbC0J
```

It includes the original discussion thread, and the information provided is very detailed. The only code changes, except for the testing part, are to delete all the places related to this tag and treat it as an unrecognized tag. That's why the message says, "it now behaves exactly like `<foo>` in all respects."

Next, let's look at another commit: [Remove support for the keygen tag](https://github.com/chromium/chromium/commit/5d916f6c6b47472770e03cb483f06a18ca79a0c2)

```
This removes support for <keygen> by updating it
to be an HTMLUnknownElement. As a result, it's
no longer a form-associated element and no
longer has IDL-assigned properties.

The <keygen> tag is still left in the parser,
similar to <applet>, so that it maintains the
document parse behaviours (such as self-closing),
but is otherwise a neutered element.

Tests that were relying on <keygen> having its
own browser-created shadow root (for its custom
select element) have been updated to use
progress bars, while other tests (such as
<keygen>-related crash tests) have been
fully removed.

As Blink no longer treats this tag as special,
all the related IPC infrastructure is removed,
including preferences and enterprise flags,
and all localized strings, as they're all now
unreachable.

This concludes the "Intent to Remove" thread
for <keygen> at
https://groups.google.com/a/chromium.org/d/msg/blink-dev/z_qEpmzzKh8/BH-lkwdgBAAJ
```

Because the processing of the `<keygen>` tag was more complicated than that of `<isindex>`, there were many more files modified. It seems that everything related to it has been removed.

Finally, let's look at this one: [bgsound must use the HTMLUnknownElement interface](https://github.com/chromium/chromium/commit/98bc944d07152ab42d41eca79de79c207f7f0f29)

```
As specified here:
https://html.spec.whatwg.org/#bgsound

This causes one less fail on:
http://w3c-test.org/html/semantics/interfaces.html
```

The test link provided inside is quite interesting. It tests whether a large number of element interfaces are correct. You can see the list of interfaces it tests in [interfaces.js](http://w3c-test.org/html/semantics/interfaces.js).

``` js
var elements = [
  ["a", "Anchor"],
  ["abbr", ""],
  ["acronym", ""],
  ["address", ""],
  ["applet", "Unknown"],
  ["area", "Area"],
  ["article", ""],
  ["aside", ""],
  ["audio", "Audio"],
  ["b", ""],
  ["base", "Base"],
  ["basefont", ""],
  ["bdi", ""],
  ["bdo", ""],
  ["bgsound", "Unknown"],
  ["big", ""],
  ["blink", "Unknown"],
  ["blockquote", "Quote"],
  ["body", "Body"],
  ["br", "BR"],
  ["button", "Button"],
  ["canvas", "Canvas"],
  ["caption", "TableCaption"],
  ["center", ""],
  ["cite", ""],
  ["code", ""],
  ["col", "TableCol"],
  ["colgroup", "TableCol"],
  ["command", "Unknown"],
  ["data", "Data"],
  ["datalist", "DataList"],
  ["dd", ""],
  ["del", "Mod"],
  ["details", "Details"],
  ["dfn", ""],
  ["dialog", "Dialog"],
  ["dir", "Directory"],
  ["directory", "Unknown"],
  ["div", "Div"],
  ["dl", "DList"],
  ["dt", ""],
  ["em", ""],
  ["embed", "Embed"],
  ["fieldset", "FieldSet"],
  ["figcaption", ""],
  ["figure", ""],
  ["font", "Font"],
  ["foo-BAR", "Unknown"], // not a valid custom element name
  ["foo-bar", ""], // valid custom element name
  ["foo", "Unknown"],
  ["footer", ""],
  ["form", "Form"],
  ["frame", "Frame"],
  ["frameset", "FrameSet"],
  ["h1", "Heading"],
  ["h2", "Heading"],
  ["h3", "Heading"],
  ["h4", "Heading"],
  ["h5", "Heading"],
  ["h6", "Heading"],
  ["head", "Head"],
  ["header", ""],
  ["hgroup", ""],
  ["hr", "HR"],
  ["html", "Html"],
  ["i", ""],
  ["iframe", "IFrame"],
  ["image", "Unknown"],
  ["img", "Image"],
  ["input", "Input"],
  ["ins", "Mod"],
  ["isindex", "Unknown"],
  ["kbd", ""],
  ["keygen", "Unknown"],
  ["label", "Label"],
  ["legend", "Legend"],
  ["li", "LI"],
  ["link", "Link"],
  ["listing", "Pre"],
  ["main", ""],
  ["map", "Map"],
  ["mark", ""],
  ["marquee", "Marquee"],
  ["menu", "Menu"],
  ["meta", "Meta"],
  ["meter", "Meter"],
  ["mod", "Unknown"],
  ["multicol", "Unknown"],
  ["nav", ""],
  ["nextid", "Unknown"],
  ["nobr", ""],
  ["noembed", ""],
  ["noframes", ""],
  ["noscript", ""],
  ["object", "Object"],
  ["ol", "OList"],
  ["optgroup", "OptGroup"],
  ["option", "Option"],
  ["output", "Output"],
  ["p", "Paragraph"],
  ["param", "Param"],
  ["picture", "Picture"],
  ["plaintext", ""],
  ["pre", "Pre"],
  ["progress", "Progress"],
  ["q", "Quote"],
  ["quasit", "Unknown"],
  ["rb", ""],
  ["rp", ""],
  ["rt", ""],
  ["rtc", ""],
  ["ruby", ""],
  ["s", ""],
  ["samp", ""],
  ["script", "Script"],
  ["section", ""],
  ["select", "Select"],
  ["slot", "Slot"],
  ["small", ""],
  ["source", "Source"],
  ["spacer", "Unknown"],
  ["span", "Span"],
  ["strike", ""],
  ["strong", ""],
  ["style", "Style"],
  ["sub", ""],
  ["summary", ""],
  ["sup", ""],
  ["table", "Table"],
  ["tbody", "TableSection"],
  ["td", "TableCell"],
  ["textarea", "TextArea"],
  ["tfoot", "TableSection"],
  ["th", "TableCell"],
  ["thead", "TableSection"],
  ["time", "Time"],
  ["title", "Title"],
  ["tr", "TableRow"],
  ["track", "Track"],
  ["tt", ""],
  ["u", ""],
  ["ul", "UList"],
  ["var", ""],
  ["video", "Video"],
  ["wbr", ""],
  ["xmp", "Pre"],
  ["\u00E5-bar", "Unknown"], // not a valid custom element name
];
```

For elements like applet, bgsound, blink, etc., [HTMLUnknownElement](https://developer.mozilla.org/zh-TW/docs/Web/API/HTMLUnknownElement) should be returned.

## Conclusion

This journey was full of gains. By continuously expanding on a topic, we can discover more interesting things.

For example, from the SmooshGate incident, we learned about the TC39's operating process, the reason why flatten broke, the commit where V8 originally implemented flatten, and how to write tests. We also learned about the principle of "don't break the web", and from this principle, we looked at the HTML specification, saw the deprecated tags, and finally looked at how they are handled in Chromium.

There are really many aspects that the people who develop standards need to pay attention to and consider, because once they start, it's hard to turn back; the specification also needs to be written clearly and unambiguously, and cannot contain errors.

I truly admire those who develop standards.

References:

1. [You Don't Know JS Yet: Get Started - 2nd Edition Chapter 1: What Is JavaScript?](https://github.com/getify/You-Dont-Know-JS/blob/2nd-ed/get-started/ch1.md)
2. [SmooshGate](https://blog.othree.net/log/2018/05/28/smooshgate/)
3. [#SmooshGate FAQ](https://developers.google.com/web/updates/2018/03/smooshgate)
4. [Non-conforming features](https://html.spec.whatwg.org/multipage/obsolete.html#non-conforming-features)
5. [3.2.2 Elements in the DOM](https://html.spec.whatwg.org/multipage/dom.html#elements-in-the-dom)
