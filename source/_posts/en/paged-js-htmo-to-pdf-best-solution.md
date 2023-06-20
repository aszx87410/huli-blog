---
title: Creating HTML Web Pages Suitable for Printing as PDFs with Paged.js
catalog: true
date: 2021-06-12 15:10:26
tags: [Front-end]
categories: [Front-end]
---

## Introduction

I was recently tasked with generating a PDF report. There are many ways to create a PDF, such as using Word and then converting it to PDF. However, my first thought was to write it as a web page and then use the print function to convert it to PDF.

At my previous company, I saw a project that used JS to generate PDFs using [PDFKit](https://pdfkit.org/). While it had a high degree of flexibility, I found it difficult to maintain. The reason is that using this tool is like drawing a PDF, and you have to specify (x, y) coordinates to draw something. Changing a small part may require changing many lines of code.

At the time, I thought, why not just use the simplest HTML + CSS, cut the layout, and then convert it to PDF? If you don't want to convert it manually, you can also use headless chrome to convert it. Because it is a web page, it should be easy to maintain. Moreover, because the layout is done using HTML and CSS, it should be much simpler than drawing.

It wasn't until I later encountered web-to-PDF conversion that I realized things weren't as simple as I thought.

<!-- more -->

## Objective

It is important to know what the final report will look like so that you can evaluate whether each technology can meet this requirement.

First, there must be a cover page without headers, footers, or page numbers, and the content must be centered.

Second, you should be able to customize the header and page number format for each page and set the footer, like this:

![](/img/print_pdf/p1.png)

Third, if a table spans multiple pages, the table head should be automatically repeated:

![](/img/print_pdf/p2.png)

Or you can directly see what the final PDF looks like: https://aszx87410.github.io/demo/print/print_demo.pdf

Once you know the objective, you can study how to achieve these functions.

## HTML Web Page to PDF - Using Native Functionality @media print

Because I am not familiar with this area, I first Googled some Chinese articles, including:

1. [CSS - Web Page Printing and Style](https://ithelp.ithome.com.tw/articles/10232006)
2. [Actually, the Heart of CSS Still Lives in Print](https://ithelp.ithome.com.tw/articles/10198913)
3. [It turns out that front-end web page printing is not just window.print()](https://medium.com/unalai/%E5%8E%9F%E4%BE%86%E5%89%8D%E7%AB%AF%E7%B6%B2%E9%A0%81%E5%88%97%E5%8D%B0-%E4%B8%8D%E6%98%AF%E5%8F%AA%E8%A6%81-window-print-%E5%B0%B1%E5%A5%BD%E4%BA%86-7af44cacf43e)
4. [@media print, who are you?](https://tsengbatty.medium.com/media-print-%E4%BD%A0%E6%98%AF%E8%AA%B0-ae093fab85b8)
5. [About @media print](https://kakadodo.github.io/2018/03/13/css-media-print-setting/)
6. [Setting Web Page Printing Styles via CSS Print](https://penghuachen.github.io/2020/12/10/%E9%80%8F%E9%81%8E-CSS-%E5%88%97%E5%8D%B0-print-%E8%A8%AD%E5%AE%9A%E7%B6%B2%E9%A0%81%E5%88%97%E5%8D%B0%E6%99%82%E7%9A%84%E6%A8%A3%E5%BC%8F/)

The key is to use CSS `@media print` to do the settings, and then you can set when to change pages, and remember to check some settings to display the background.

I tried these methods myself and found that they can handle basic requirements, but if the requirements are a bit more complex, they won't work.

For example, how do I customize the header and footer for each page? The header and footer of each page may be different. If I can plan how much content per page in advance, there may be a chance to solve it, but what if I can't? For example, if I have a long list, I don't know how many pages there will be, what should I do?

Regarding the header and footer, I found this article: [The Ultimate Print HTML Template with Header & Footer](https://medium.com/@Idan_Co/the-ultimate-print-html-template-with-header-footer-568f415f6d2a), which was helpful, but it couldn't solve the page number problem.

The above practices rely on selecting the default page numbers when printing, and the title is the webpage's title or URL. How can I customize these styles? For example, if I want to change the position of the page numbers, is it possible?

Later, I searched the internet and found that these situations cannot be solved by native CSS. So I changed my approach to "first print a PDF without page numbers using HTML, and then process it from the backend." Since there is already a PDF, it is natural to know how many pages there are, and then you can use PDFKit or other libraries as mentioned earlier. This means that you first convert it to PDF, then process it, and you need two programs.

I also found a set of [WeasyPrint](https://github.com/Kozea/WeasyPrint/tree/master), which seems to be able to customize headers, footers, and page numbers, but it is still not an ideal solution.

Just when I started to think, "It seems that these cannot be done with only front-end web pages," the savior appeared.

## Paged.js, the best solution for webpage printing layout

[Paged.js](https://www.pagedjs.org/) introduces itself as:

> Paged.js is a free and open source JavaScript library that paginates content in the browser to create PDF output from any HTML content. This means you can design works for print (eg. books) using HTML and CSS!

> Paged.js follows the Paged Media standards published by the W3C (ie the Paged Media Module, and the Generated Content for Paged Media Module). In effect Paged.js acts as a polyfill for the CSS modules to print content using features that are not yet natively supported by browsers.

In short, Paged.js is an open-source JavaScript library used to help you print PDFs. Strictly speaking, many parts of it are polyfills. In fact, W3C already has some CSS properties responsible for printing, but they are still in the draft stage, so browsers have not implemented them yet, so they need to rely on Paged.js to polyfill.

Let me show you what can be achieved with Paged.js:

1. Demo website: https://aszx87410.github.io/demo/print/print.html
2. Generated PDF: https://aszx87410.github.io/demo/print/print_demo.pdf

If you want to learn how to use Paged.js, I highly recommend reading the official documentation because all the features are written there. This article just wants to let everyone know that there is this solution, so I won't talk too much about it. Below, I will briefly explain how I implemented each feature I wanted.

It's a bit difficult to explain these features with just pictures and text, so I suggest that after reading this, go directly to the source code of the demo website above. I think it will be easier to understand.

## Customize each page

Native CSS seems to only adjust the pages uniformly, but Paged.js supports various pages, such as:

``` css
@page {
  size: A4;
  margin-top: 20mm;
  margin-bottom: 20mm;
  margin-left: 20mm;
  margin-right: 20mm;
  padding-top: 2rem;
}

@page:nth(1) {
  padding-top: 0;
}
```

I first adjusted the margin and padding uniformly for all pages, but canceled the padding-top for the first page because the first page is the cover and does not need padding.

If you don't want to use page numbers as selectors, you can also directly name the pages, like this:

``` html
<div class="page-cover">
    ...
</div>
```

``` css
.page-cover {
  page: coverPage;
}

@page coverPage {
  padding-top: 0;
}
```

By doing this, you can control the page style for specific types of pages.

## Customize headers and footers

Paged.js will automatically paginate your content and add default layout and CSS to each page. After modification, each page will look like this (image from the official website):

![](/img/print_pdf/p3.png)

The page area is your content, and other areas are block names. You can use CSS to decide what to put in these blocks. For example:

```  css
@page {
  @top-center {
    content: "hello";
  }
}
```

If you write it like this, the word "hello" will appear in the middle of the top of each page.

Therefore, through this CSS, it is very easy to achieve the function of customizing headers and footers. However, this is only the most basic function, and the exciting part is coming up.

Many times, text alone is not enough. We also want to add some styles or even images. Moreover, the headers and footers of each page may be different. For example, the title of this page may be A, and the next page may be B. How do we handle this?

In Paged.js, there is a concept called "running headers/footers", which can be used to achieve dynamic headers and footers.

The CSS we just wrote originally had fixed content, but now we can change it:

``` css
@page {
  @top-center {
    content: element(title);
  }
}
```

If we write it like this, the content in the middle will be an element called "title". What is this element? Just specify it with CSS:

``` css
.title {
  position: running(title);
  color: white;
  font-size: 1.25rem;
}
```

Here is a position value that you may not have seen before, called `running(title)`, which means that the `.title` element is set as a running title, corresponding to the `element(title)` we just wrote.

Therefore, as long as the title of each page is placed in the HTML, it will automatically fetch its content and place it where you want it.

``` html
<div class="page">
    <div class="title">這是第一頁標題</div>
    第一頁內容
</div>
<div class="page">
    <div class="title">這是第二頁標題</div>
    第二頁內容
</div>
```

The divs with the title class above will not appear in the content of the document, but will be pulled to the top center position. The content of the title will also change with the page, which is a super convenient feature!

The footer in the example is done like this:

``` css
@page {
  @bottom-left {
    content: element(footer);
  }
}

.footer {
  position: running(footer);
  font-size: 1rem;
  color: #999;
  border-top: 2px solid #ccc;
}
```

``` html
<div class="footer">
  <p>本文件僅供教學使用，請勿用於商業之用途</p>
</div>
```

In addition to customizing the content, the style of those cells can also be customized. For example, in the example, I changed the background color of the entire header, because these cells actually have default classes, so you can use CSS to do it:

``` css
.pagedjs_page:not([data-page-number="1"]) .pagedjs_margin-top-left-corner-holder,
.pagedjs_page:not([data-page-number="1"]) .pagedjs_margin-top,
.pagedjs_page:not([data-page-number="1"]) .pagedjs_margin-top-right-corner-holder {
  background: #658db4;
  outline: 2px #658db4;
}
```

The reason why `.pagedjs_page:not([data-page-number="1"])` is added at the front is because I don't want to touch the first page, so I used this selector to exclude the first page. The outline is because I found that sometimes the header seems to have a white line, and I guess it may be a rendering problem, so I want to see if I can cover it up:

![](/img/print_pdf/p4.png)

## Custom page numbers

Regarding the page number, Paged.js provides two CSS counters that can be used: `counter(page)` and `counter(pages)`.

If you want to add page numbers in the upper right corner like the example, you can write it like this:

``` css
@page {
  @top-right {
    color: white;
    content: "第 " counter(page) " 頁，共 " counter(pages) " 頁";
  }
}
```

This way you can add page numbers anywhere! And you can customize the format, and if you want to adjust the style, you can do it directly.

## Automatic continuation of table head

In fact, when using the native HTML table tag, there is already a function that the table head will automatically continue. It's just that Paged.js may have some problems in processing, so this function is gone.

But it is not difficult to add it back. I found a simple piece of code that can solve this problem, source: [Repeat table header on subsequent pages](https://gitlab.pagedmedia.org/tools/pagedjs/issues/84#note_535)

``` html
<script>
  // @see: https://gitlab.pagedmedia.org/tools/pagedjs/issues/84#note_535
  class RepeatingTableHeaders extends Paged.Handler {
    constructor(chunker, polisher, caller) {
      super(chunker, polisher, caller);
    }

    afterPageLayout(pageElement, page, breakToken, chunker) {
      // Find all split table elements
      let tables = pageElement.querySelectorAll("table[data-split-from]");

      tables.forEach((table) => {
        // Get the reference UUID of the node
        let ref = table.dataset.ref;
        // Find the node in the original source
        let sourceTable = chunker.source.querySelector("[data-ref='" + ref + "']");
        // Find if there is a header
        let header = sourceTable.querySelector("thead");
        if (header) {
          // Clone the header element
          let clonedHeader = header.cloneNode(true);
          // Insert the header at the start of the split table
          table.insertBefore(clonedHeader, table.firstChild);
        }
      });

    }
  }

  Paged.registerHandlers(RepeatingTableHeaders);
</script>
```

Remember to use the table tag in HTML, like this:

``` html
<table>
  <thead>
    <tr>
      <th>網址</th>
      <th>文章名稱</th>
      <th>瀏覽次數</th>
      <th>跳出率</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>blog.huli.tw</td>
      <td>CORS 完全手冊（一）：為什麼會發生 CORS 錯誤？</td>
      <td>34532</td>
      <td>52.3%</td>
    </tr>
  </tbody>
</table>
```

## Conclusion

The sample code above is quite short, and most of it is CSS. Before using this set, I really didn't think that so many things could be adjusted through CSS.

I am very satisfied with Paged.js myself. It is currently the best solution I think for front-end HTML to PDF layout. One of the reasons is what I said before. Except for it, I have not found any other libraries that can support custom headers, footers, and page numbers. It is really amazing to use, because it provides solutions to all the needs I want to solve, and it is actually quite easy to use.

The only downside may be the white line of about 1px that can be seen in some screenshots above. I guess it may be a rendering problem of the browser or something related to the PDF viewer. But it should not be difficult to cover it up, and the most troublesome thing is to draw a line to cover it up.

The functions I need are all in the example code. If you want to see the complete example code, I put it here: https://github.com/aszx87410/demo/blob/master/print/print.html

If you want more functions, you can refer to the documentation and official website of Paged.js: https://www.pagedjs.org/

I recommend this to anyone with similar needs as mine. I hope Paged.js can also solve your problems. Or if you know of any pure front-end packages that are better than Paged.js, please recommend them to me.
