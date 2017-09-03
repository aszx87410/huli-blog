# Blog
source code of the blog

不知道為何右邊的 table of content 載入不了  
自己在 toc helper 裡面加上這段：

```
if (!id) {
      var temp = $(this).html().match(/id="(.*)">/);
      if (temp && temp[1]) {
        id = temp[1];
      }
    }
```
