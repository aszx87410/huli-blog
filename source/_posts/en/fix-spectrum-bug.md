---
title: 'My Experience Fixing a Bug in the Open Source Project Spectrum'
date: 2019-04-19 20:10
tags: [Others]
categories:
  - Others
---

## Preface

Recently, I started my teaching project again. In the first phase, I wrote this article: [Using Github Classroom and Travis CI to Build a Homework Submission System](https://github.com/aszx87410/blog/issues/27). In the second phase, I wrote this article: [AWS Lambda + GitHub API + Google Sheet = Automatic Sign-in System](https://github.com/aszx87410/blog/issues/32). Both of them use existing tools to quickly create systems that meet my needs.

Before the third phase, I hoped that the course could have a discussion forum where students could easily ask questions. I have always used Slack, but the biggest disadvantage of Slack is that the free version eats messages, and many good information is washed away, which is a pity. I hope there is a forum or discussion forum that would be better.

Two years ago, I also wrote an article: [Self-hosted Forum Solutions: Flarum, Github Issue, NodeBB, Discourse](http://huli.logdown.com/posts/1989995-the-forums-solution-flarum-discourse-github-issue), studied several solutions, and finally chose GitHub Issue. Because it is the simplest and most convenient, but the biggest disadvantage is that students don't seem to be used to it, because it doesn't look like a forum when you look left, right, up, and down.

<!-- more -->

Recently, I came across this platform by chance: [spectrum](https://spectrum.chat/). The slogan on the homepage is very clear:

> The community platform for the future.

After being acquired by GitHub last year, it became completely free, and the paid version's features became free. In my opinion, it is actually Slack that is "more like a forum". Let me show you a screenshot:

<img width="1221" alt="sc" src="https://user-images.githubusercontent.com/2755720/56428306-791b8d80-62f1-11e9-9cad-ac46ddc8052c.png">

The leftmost is different workspaces, which is the same as Slack. Then you can see various channels, which is also the same as Slack. The only difference is on the right side. The original Slack message became a discussion thread with a title and content.

So you can probably understand what I'm talking about. This set is similar to Slack, but more suitable as a forum.

Free, backed by GitHub, can have private forums, open source, this is a perfect solution. Except for the lack of a mobile app, there is nothing to pick on, so I decided to use this set!

## Things are not so smooth...

After trying it out for a few days, I found a huge problem. Although there is no problem in terms of functionality, the experience is extremely poor. This one small flaw is enough for me to give up this platform.

What is the problem? Typesetting.

Spectrum natively supports Markdown, which is very handy to use, but line breaks are a problem. In some places, only blank lines are not useful, and two spaces need to be added at the end to line break. Although I think this is very inconvenient, I can reluctantly accept it.

However! On spectrum, you need two line breaks to really line break.

Here is an example. Line1 and Line2 at the bottom should line break:

![layout1](https://user-images.githubusercontent.com/2755720/56428318-85074f80-62f1-11e9-9134-4f9138eeb035.png)

But after posting, it becomes like this:

![layout2](https://user-images.githubusercontent.com/2755720/56428324-8a649a00-62f1-11e9-88d2-f95f8c39b66d.png)

Line breaks become spaces. If it is English, it is okay, but if it is Chinese, the typesetting becomes super strange and unacceptable.

I went to the official discussion forum [to post](https://spectrum.chat/spectrum/general/how-to-input-new-line-when-creating-a-new-post~2e53fc58-990a-433c-8f86-d2e28cdeaf87), thinking that there might be other ways to line break that I don't know.

The result of the official reply to me was: "Yes, now you have to line break twice to really line break."

Originally, I was discouraged and wanted to give up, and studied whether there were other solutions. I even thought about whether to write one myself, but when I thought about supporting a lot of functions, I felt it was troublesome and couldn't make up my mind.

After several days of contemplation, I think Spectrum is a great platform, but the only drawback is the formatting issue. If this issue is resolved, there is no reason not to use it.

If the official team is too busy to fix the bugs, we can fix them ourselves! This is the benefit of open source.

## Journey of Bug Fixing

The first step to fixing bugs for an open source project is to figure out how to run the entire environment. You need to be able to run it locally to verify whether you have successfully fixed the issue, so the official documentation is very important.

The [spectrum](https://github.com/withspectrum/spectrum) documentation is very comprehensive and provides a series of instructions on what to do. By following these instructions, you can run both the front-end and back-end on your local machine.

While waiting for the installation of these packages, you can try to guess where the problem might be. At that time, I guessed that there might be a problem with the markdown editor, perhaps when converting markdown to HTML, the line breaks were not handled properly, resulting in missing line breaks.

Guessing alone is not enough. The first step is to narrow down the problem and locate it. Find out what happened to the most important part of the post.

In Chrome, we can use React Devtool to see that the post interface is a component called composer. Then in [composer/index.js](https://github.com/withspectrum/spectrum/blob/0cef471b45779adcdfbb22dcc57884712c015e91/src/components/composer/index.js#L500), we can see that it is handled by a component called Inputs.

In [Inputs.js](https://github.com/withspectrum/spectrum/blob/0cef471b45779adcdfbb22dcc57884712c015e91/src/components/composer/inputs.js#L54), I discovered something amazing. When you press Preview, it sends a request directly to a hardcoded path and displays the result:

``` js
const onClick = (show: boolean) => {
  setShowPreview(show);
  
  if (show) {
    setPreviewBody(null);
    fetch('https://convert.spectrum.chat/from', {
      method: 'POST',
      body,
    })
      .then(res => {
        if (res.status < 200 || res.status >= 300)
          throw new Error('Oops, something went wrong');
        return res.json();
      })
      .then(json => {
        setPreviewBody(json);
      });
  }
};
```

Since the conversion is done by the server, the next step is to find out what the server is doing.

But I don't know where `https://convert.spectrum.chat/from` corresponds to on the server, and how to find out how the server handles it?

Here, we can change our thinking. Although it is true that the preview is sent here, the server must also handle this format conversion when posting, so we can first find out what the server is doing when posting, and there should be some clues.

Then, after posting on the front end, check the Network tab because the backend is GraphQL, so it's pretty easy to see, and it's called `publushThread`.

Immediately go to the server part, and found this file: [publishThread.js](https://github.com/withspectrum/spectrum/blob/0cef471b45779adcdfbb22dcc57884712c015e91/api/mutations/thread/publishThread.js#L76), and found that it calls `processThreadContent` to do the conversion.

Follow this function down, and after [looking at the code](https://github.com/withspectrum/spectrum/blob/0cef471b45779adcdfbb22dcc57884712c015e91/shared/draft-utils/process-thread-content.js#L12), I found that this should be the bottom layer:

``` js
// @flow
import { stateFromMarkdown } from 'draft-js-import-markdown';
import { convertFromRaw, convertToRaw, EditorState } from 'draft-js';
import { addEmbedsToEditorState } from './add-embeds-to-draft-js';
  
export default (type: 'TEXT' | 'DRAFTJS', body: ?string): string => {
  let newBody = body;
  if (type === 'TEXT') {
    // workaround react-mentions bug by replacing @[username] with @username
    // @see withspectrum/spectrum#4587
    newBody = newBody ? newBody.replace(/@\[([a-z0-9_-]+)\]/g, '@$1') : '';
    newBody = JSON.stringify(
      convertToRaw(
        stateFromMarkdown(newBody, {
          customBlockFn: elem => {
            if (elem.nodeName !== 'PRE') return;
  
            const code = elem.childNodes.find(node => node.nodeName === 'CODE');
            if (!code) return;
  
            const className = code.attributes.find(
              ({ name }) => name === 'class'
            );
            if (!className) return;
  
            const lang = className.value.replace('lang-', '');
  
            return {
              type: null,
              data: {
                language: lang,
              },
            };
          },
          parserOptions: {
            atomicImages: true,
            breaks: true,
          },
        })
      )
    );
  }
  
  // Add automatic embeds to body
  try {
    return JSON.stringify(addEmbedsToEditorState(JSON.parse(newBody || '')));
    // Ignore errors during automatic embed detection
  } catch (err) {
    console.error(err);
    return newBody || '';
  }
};
```

And I didn't see any signs of anything wrong. It seemed like everything was normal. At this point, I thought: Do I have to trace down to draft-js or other libraries?

But since I found this, I should first see what it will convert to, and then decide what to do next. So I added a log to this function to print out what it finally converted.

My input was:

```
oneline
newline  
thirdline
  
fourline
  
fiveline
```

The output was:

``` js
{
  "blocks":[
    {
      "key":"bq56i",
      "text":"oneline\nnewline\nthirdline",
      "type":"unstyled",
      "depth":0,
      "inlineStyleRanges":[],
      "entityRanges":[],
      "data":{}
    },
    {
      "key":"9h38b",
      "text":"fourline",
      "type":"unstyled",
      "depth":0,
      "inlineStyleRanges":[],
      "entityRanges":[],
      "data":{}
    },
    {
      "key":"fuprm",
      "text":"fiveline",
      "type":"unstyled",
      "depth":0,
      "inlineStyleRanges":[],
      "entityRanges":[],
      "data":{}
    }
  ],
  "entityMap":{}
}
```

Without printing, it's nothing, but when I printed it out, it was amazing!

I didn't expect the above test data to be converted to: `"text":"oneline\nnewline\nthirdline"`. It seems that the server's conversion is completely normal, and the line breaks are converted to `\n`, and two line breaks are converted to a new block. It seems that the problem is that the front end did not output these line breaks properly.

Then, using a similar method, I used React Devtool to see that the front end display is handled by [threadDetail.js](https://github.com/withspectrum/spectrum/blob/be3d7cc2b2bafec6715c7623db59c897902073ff/src/views/thread/components/threadDetail.js#L359), and it calls threadRenderer.js, which seems to be the real rendering place.

After finding [threadRenderer.js](https://github.com/withspectrum/spectrum/blob/c34bb1fa4b9957bcfcc6ff0165582e2f635bf5e7/src/components/threadRenderer/index.js#L4), it was discovered that it simply calls the library [redraft](https://github.com/lokiuz/redraft).

Okay, although there is something new to study, the answer is getting closer.

After carefully reading the redraft documentation, it seems that it is possible to customize what the output of each type should look like. Further down, in the [Common issues](https://github.com/lokiuz/redraft#common-issues) section, it says:

> Can the multiple spaces between text be persisted?
>    
> Add white-space: pre-wrap to a parent div, this way it will preserve spaces and wrap to new lines (as editor js does)

At this point, the answer is already very clear. The front-end display forgot to add `white-space: pre-wrap`, so the default behavior treats line breaks as spaces.

When the truth was revealed, I cursed myself in my heart, but it was my own fault. Because this problem is actually quite common on the front-end, and I have used this property many times. However, when I saw this problem, my first thought was to suspect the back-end, and I never thought that it might be a front-end problem, let alone that it could be solved by adding a line of CSS.

Then I posted an [Issue](https://github.com/withspectrum/spectrum/issues/4885) to record the investigation process and cause, and then submitted a [PR](https://github.com/withspectrum/spectrum/issues/4885). Although it was only one line, it was significant to me. Because once this bug is fixed, this set can immediately be used for other ready-made forum systems.

Their speed is very fast. After submitting the PR, it was merged the next day, and then deployed to production in just one week. They are really efficient.

## Not satisfied, let's fix another one!

Although it was only one line, the exploration process was very rewarding, and I was happy that the PR was merged. Since one was fixed, let's see if there are any other easy ones to fix, so we can fix them together.

I looked through the official Issues and found one that looked easy: [Weird image failed rendering in thread body](https://github.com/withspectrum/spectrum/issues/4812). This Issue is very simple, it's just that the following bug appears for no reason:

<img width="716" alt="alt" src="https://user-images.githubusercontent.com/2755720/56428342-97818900-62f1-11e9-9771-d8f85426e079.png">

The text covers the image behind it.

The original URL was attached in the Issue, and after clicking it and using devtool to check, it was found that the problem was caused when the browser could not load the image tag. 

I had never encountered this problem before, but after trying it myself, I found that the img originally had a margin, but it would fail when the image could not be loaded. My intuition told me that this might be related to [margin collapsing](https://developer.mozilla.org/en-US/docs/Web/CSS/CSS_Box_Model/Mastering_margin_collapsing).

Later, I tried it myself and found that when the image could not be loaded, the height of the img would become 0, and then the margin would fail. Because of some layout and CSS elements, the text below would cover it, resulting in the image below.

<img width="1306" alt="height" src="https://user-images.githubusercontent.com/2755720/56428348-9cded380-62f1-11e9-9136-0c3283be8505.png">

So is there a good solution?

I found the simplest solution was to add the `alt` attribute. When the image cannot be loaded, this text will be displayed, and the img will maintain its height, and the margin will work.

<img width="1324" alt="height2" src="https://user-images.githubusercontent.com/2755720/56428350-a1a38780-62f1-11e9-9bf0-884030c56f93.png">

After finding a solution, I first replied to the [Issue](https://github.com/withspectrum/spectrum/issues/4812) and discussed with them to see what they thought.

Later, I found that the alt attribute was actually set when uploading the image, but it might be empty under some boundary conditions, or the user manually removed the alt attribute.

So the final solution was also very simple, just add a default value to alt, [PR: Add default alt text to img](https://github.com/withspectrum/spectrum/pull/4887):

```
-  <img key={key} src={data.src} alt={data.alt} />,
+  <img key={key} src={data.src} alt={data.alt || 'Image'} />
```

## Summary

Although I only contributed two lines, I was still happy to see my account appear in the release log:

<img width="849" alt="re" src="https://user-images.githubusercontent.com/2755720/56428356-a7996880-62f1-11e9-98fd-7670bf8b38fa.png">

If it were me before, I would never have done such a thing. I would have stopped after finding the bug and waited for the official team to fix it.

But in recent years, I have gradually become familiar with reading other people's code. Sometimes when I have nothing to do at work, I can take a look at the source code of redux-form or redux, etc. As I read more, I feel that it's not that scary. Moreover, GitHub has a super useful feature called "Search", which often allows me to find related source code directly by searching for keywords, saving a lot of time.

When looking at other people's projects, I think the hardest part is locating the problem. Once you locate the problem, everything else is not that difficult, because you already know which file and which code segment has the problem, and you just need to study in that direction. As for how to locate the problem, here are a few suggestions:

1. Search the code directly to see if you can find the relevant paragraph
2. Use devtool to find the relevant component
3. Look at the documentation to see if there are any attached structures

When you want to fix a bug, the direction is very clear, and there is no need to look through the entire project. Just find the place you want to fix. This article hopes to share my experience with everyone.

Finally, it's great to be an engineer, it's great to have an open source project, and it's great to be able to fix bugs yourself.
