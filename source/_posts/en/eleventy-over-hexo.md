---
title: Consider Using Eleventy to Write Technical Blog Posts Besides Hexo
catalog: true
date: 2021-08-22 15:43:37
tags: [Others]
categories: [Others]
---

## Introduction

When it comes to writing technical blog posts, most people's first choice is still the combination of [hexo](https://hexo.io/zh-tw/) and GitHub Pages. In fact, the blog you are currently reading is also built using this technology stack.

However, I recently built two other technical blogs, not using hexo, but another static site generator called [eleventy](https://www.11ty.dev/). I am extremely satisfied with the results, so I wrote this article to recommend it to everyone.

If you want to check out the two blogs I built, here they are:

1. [ErrorBaker Technical Blog](https://blog.errorbaker.tw/)
2. [Cymetrics Tech Blog](https://tech-blog.cymetrics.io/)

<!-- more -->

## Why Eleventy?

I first learned about eleventy from this article: [Why I Leave Medium and Build Blog with Eleventy](https://jason-memo.dev/posts/why-i-leave-medium-and-build-blog-with-eleventy/). From the article, one of the advantages of eleventy is its simplicity and lightweightness, which I think is an important part of a blog.

For example, hexo is still okay, and most theme performance is not too bad, at most a little bloated. For my current huli blog, the Lighthouse score on the homepage is 81 in terms of performance, and the First Contentful Paint is 3.4 seconds, which is not too bad, but there is room for improvement. And my blog looks very simple but took so much time to build, indicating that there are many areas for improvement.

However, I have seen some self-built blogs with poor performance, taking several seconds to load content, which is completely unacceptable.

The article mentioned above introduces a template called [eleventy-high-performance-blog](https://github.com/google/eleventy-high-performance-blog) developed by a Google AMP tech lead. Since the title is already named like this, it means that it is performance-oriented.

Recently, I happened to help my former students build a technical blog, and I thought of this solution and tried it out. The results were amazing, and I immediately fell in love with it. I give it a five-star rating for overall satisfaction.

If you are interested in the blog I mentioned, here is the link: [ErrorBaker Technical Blog](https://blog.errorbaker.tw/)

The advantages of this eleventy-high-performance-blog template are that it is really fast in terms of performance and has processed many things for you, including:

1. Optimizing images, automatically compressing, converting formats, and loading with `<picture>`, as well as native lazy loading
2. There is almost no CSS and JS, so the file size is very small
3. Basic SEO is done
4. a11y is taken into consideration
5. The layout is simple, the files are few, and it is easy to modify

In addition to the advantages of the template, eleventy (hereinafter referred to as 11ty) also has some advantages as an SSG, including:

1. Simple syntax and easy to get started
2. Easy to customize
3. Detailed documentation

It is worth mentioning that these blogs are actually for one person to use, but the blog I am building is by default for multiple authors, so some customization is required. I spent about half a day to a day to make these modifications and turned a single-person blog into a multi-author blog.

Both the eleventy-high-performance-blog template and 11ty are very simple, so customization is very easy, and the advantage of having few files is that you don't have to spend too much time looking for where to make changes.

As a front-end engineer, I think it is very nice to have a blog that can be easily customized, because it is much easier to try new technologies or do performance optimization, and you can quickly find out how to make changes.

After building the shared blog, the company's blog happened to want to move, so I used the one I had previously built and made some adjustments to create a new blog: [Cymetrics Tech Blog](https://tech-blog.cymetrics.io/)

In summary, I think the advantages of 11ty and eleventy-high-performance-blog are:

1. The layout is simple, suitable for people who don't like too many things
2. Easy to modify, more convenient for customization
3. Good performance, fast loading of the blog

## Some Disadvantages and Issues I Have Encountered

In addition to the advantages, let me also talk about some disadvantages to balance it out.

The first disadvantage is that the CSS part is not easy to modify. Some of the original CSS rules will definitely be overwritten, but for some reason, they were not deleted, and the overall CSS looks a bit messy.

The second issue is related to image optimization. During build time, images are directly converted into webp and avif formats, and only local cache is available. Therefore, if it is run on CI, it will be very slow. In the past, it took 7 minutes to build.

There are two solutions. One is to commit the cache image together, and the other is to remove the conversion of avif because it takes the most time.

The third issue is a small bug when using the [utterances](https://utteranc.es/) comment system. After logging in, the token is verified using the URL in the address bar. However, this template has a function that removes the query string, so the token cannot be obtained and login is not possible. The temporary workaround is to set it to clear the query string after one second.

The fourth issue is pagination. The pagination navigation of this template needs to be done manually, but fortunately, the official website has a detailed example: [PAGINATION NAVIGATION](https://www.11ty.dev/docs/pagination/nav/).

The fifth issue is that some optimizations seem to have a problem. For example, the `<head>` tag may disappear, which may be mistaken for an optional tag and cause the consequence that if you use GA or search console, you will not be able to verify it by adding something to the head. Currently, I have removed [removeOptionalTags](https://github.com/google/eleventy-high-performance-blog/blob/main/_11ty/optimize-html.js#L99).

The sixth issue is that some tags for SEO are incomplete, such as `twitter:title`, `og:site_name`, and `og:type`. Although some things can still be automatically captured, it is better to write them clearly.

Actually, I think these are all small issues, more detailed areas.

## Conclusion

I have studied which blog template to use before. At that time, there were no good options except hexo. Hugo or the old-fashioned jekyll were not as familiar as hexo. As for the template, I found that the template used by [Askie](https://askie.today/about/) was very good, so I chose the same template.

However, after using it for a while, I found some shortcomings, such as the website being a bit too heavy (I just found out that most of them are disqus things, and I found the culprit. It is not a template problem but disqus. I will take a closer look later), but there are no other problems.

This time, because of the need to set up a new blog, I started looking at other templates and found that 11ty is really good, and the performance is indeed very good. However, compared with hexo, the high-performance template is relatively simple. If you don't like it to be so simple, you have to spend more effort to adjust it.

In short, I feel pretty good about using it, and fixing bugs or adding features by myself will make me more involved.

If you like a simple and fast blog template and don't mind adding new features or adjusting the layout by yourself, I sincerely recommend [eleventy-high-performance-blog](https://github.com/google/eleventy-high-performance-blog).
