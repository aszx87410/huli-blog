---
title: TIL:img src also supports mp4 (Safari only)
date: 2023-09-11 21:10:00
catalog: true
tags: [Front-end]
categories: [Front-end]
photos: /img/mp4-in-img-src/cover-en.png
---

Some websites use GIFs for certain images because they are animated and appear more impressive than static images. Sometimes, the need for an animated image arises, such as in the case of stickers where animation is expected.

However, one of the well-known drawbacks of GIFs is their large file size. Especially on mobile devices with higher resolutions, larger images are required. Even if only a 52px image is displayed, a 156px image needs to be prepared, resulting in increased file size. In terms of web development, it is always better to have fewer and smaller resources to load.

<!-- more -->

Therefore, many websites have started using the `<video>` tag to display these animated images. By converting them to the mp4 format, the file size can be significantly reduced. However, there are some downsides to using the `<video>` tag instead of `<img>`, such as the lack of native support for lazy loading and other inconveniences.

During my research, I unexpectedly discovered that Safari actually supports mp4 in the `<img>` tag! This means you can do the following:

``` html
<img src="test.mp4">
```

This feature has been available since 2017: [Bug 176825 - [Cocoa] Add an ImageDecoder subclass backed by AVFoundation](https://bugs.webkit.org/show_bug.cgi?id=176825)

I found out about this in the following article: [Evolution of &lt;img>: Gif without the GIF](https://calendar.perfplanet.com/2017/animated-gif-without-the-gif/)

If `<img>` can also support mp4, we can take advantage of the benefits of both tags without having to switch tags. We can have lazy loading support and significantly reduce the file size.

Unfortunately, this feature is only supported in Safari. Even after six years, I haven't seen this functionality in Chromium or Firefox, and it seems unlikely to be implemented in the future.

Chromium has explicitly stated that it will not support this feature. The discussion thread can be found here: [Issue 791658: Support &lt;img src="*.mp4">](https://bugs.chromium.org/p/chromium/issues/detail?id=791658). It was marked as "Wont fix" in 2018, with the following reason:

```
Closing as WontFix per c#35, due to the following:
- The widespread adoption of WebP (addresses CDN use case)
- Forthcoming AV1 based image formats (ditto).
- Memory inefficiency with allowing arbitrary video in image.
- Most sites have already switched to &lt;video muted> now that autoplay is allowed.
```

The first point mentioned that WebP actually has an Animated WebP format that can be used within the `<img src>` tag and is also animated. It has even smaller file sizes. For more information on the pros and cons, you can refer to Google's own documentation: [What are the benefits of using animated WebP?](https://developers.google.com/speed/webp/faq?hl=en#why_should_i_use_animated_webp)

The second point mentions that the newer image format AVIF also has Animated AVIF, which also supports animated images.

If these new image formats can replace GIFs, it seems that there is no real need to use mp4.

As for Firefox, although they haven't explicitly stated that they won't implement this feature, the issue hasn't seen much activity for a long time: [Add support for video formats in &lt;img>, behaving like animated gif](https://bugzilla.mozilla.org/show_bug.cgi?id=895131)

Some people hope to add this feature to the specification, but there hasn't been much progress for a while: [Require img to be able to load the same video formats as video supports #7141](https://github.com/whatwg/html/issues/7141)

In conclusion, it seems that this feature will only be available in Safari.

Unfortunately, the image service I am using only supports converting GIFs to mp4 and does not support converting to animated WebP or animated AVIF, which would have been very convenient.

## Summary

If you want to continue using `<img>` for animated images, the most comprehensive approach would be to use the `<picture>` tag with multiple file formats, like this:

``` html
<picture>
  <source type="image/avif" srcset="test.avif">
  <source type="video/mp4" srcset="test.mp4">
  <source type="image/webp" srcset="test.webp">
  <img src="test.gif">
</picture>
```

This ensures that the results are displayed correctly on every browser and selects the image with usually smaller file size.

I tried it out myself with a simple gif that had an original size of 75 KB:

![gif](/img/mp4-in-img-src/test.gif)

After converting it to WebP, it became 58 KB (-22.6%):

![webp](/img/mp4-in-img-src/test.webp)

Converting it to mp4 reduced the size to 17 KB (-77.3%):

![Only supported by Safari, may not display properly](/img/mp4-in-img-src/test.mp4)

Converting it to AVIF reduced the size to 11 KB (-85.3%):

![AVIF format, may not be supported by newer browsers](/img/mp4-in-img-src/test.avif)

It seems that the latest file formats are quite impressive, reducing the size significantly.
