---
title: '[Corona] 檢查檔案是否存在'
date: 2014-05-14 17:47
catalog: true
header-img: "/img/header_img/article-bg.png"
tags: [corona]
---
在[Corona Docs](http://docs.coronalabs.com/api/library/system/pathForFile.html)裡面有提供了sample code

``` lua
local path = system.pathForFile(  "data.txt", system.DocumentsDirectory )
local fhd = io.open( path )

-- Determine if file exists
if fhd then
   print( "File exists" )
   fhd:close()
else
    print( "File does not exist!" )
end
```

用來檢查一個檔案是否存在
但是要特別注意的是，「你沒辦法檢查ResourceDirectory裡面的東西存不存在」
把上面的範例改一下就知道了，如果你把第一行改成
`local path = system.pathForFile(  "does_not_exist.txt", system.ResourceDirectory )`
程式就會出錯

而corona的討論區裡面有一篇 [Android - system.pathForFile - bugged implementation?](http://forums.coronalabs.com/topic/43850-android-systempathforfile-bugged-implementation/)

有官方的人出來回應，大意就是說開發者應該要知道Resource資料夾裡面有什麼東西
原文：
> But why this shouldn't be an issue is you should know what all is in your resource bundle.