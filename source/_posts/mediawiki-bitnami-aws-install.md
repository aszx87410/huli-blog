---
title: '[心得] mediawiki binami版 安裝心得'
date: 2016-05-14 11:05
catalog: true
header-img: "/img/header_img/article-bg.png"
tags: [other]
---
最近在研究自己架 wiki 系統，發現了 mediawiki 這一套
發現在 [aws marketplace](https://aws.amazon.com/marketplace/pp/B00NNZTQWC)上面有別人已經做好的 image
原本以為很方便，但實際開起來之後發現很多東西要調整

https://bitnami.com/stack/mediawiki/README.txt
這個是滿重要的使用手冊

https://wiki.bitnami.com/Amazon_cloud/Where_can_I_find_my_AWS_Marketplace_credentials%253f
你可以在這邊找到你的 mediawiki 密碼，帳號是 user
但我找不到，所以直接重置
```
cd /opt/bitnami/apps/your_application
sudo ./bnconfig --userpassword mypassword
```

弄好之後可以先調設定，到
`/opt/bitnami/apps/mediawiki/htdocs/LocalSettings.php`
這絕對是最重要的路徑，務必記得

可以先把語言調成中文：`$wgLanguageCode = "zh-tw";`
然後預設居然沒開程式碼highlight，可以自己開啟：`wfLoadExtension( 'SyntaxHighlight_GeSHi' );`

因為是自己用的，為了方便 dubug，可以開啟錯誤輸出功能（沒開的話只會寫 500）
```
error_reporting( -1 );
ini_set( 'display_errors', 1 );
```

接著看到 [VisualEditor](https://www.mediawiki.org/wiki/Extension:VisualEditor) 這個套件很帥
跟著官方說明裝其實就差不多了
裝之前要先裝 [parsoid](https://www.mediawiki.org/wiki/Parsoid/Setup)

這篇是少數幾篇中文的筆記
[安装MediaWiki的Visual Editor插件](http://blog.itb.name/2016/01/19/12.html)

`/var/log/parsoid/parsoid.log` 可以看到 log，可以用 `curl` 測一下有沒有安裝成功
`/etc/mediawiki/parsoid/settings.js` 的設定要記得改，我改成`http://localhost/api.php` 就可以了

筆記一下相關連結
http://codex.wordpress.org.cn/Mediawiki%E4%BF%AE%E6%94%B9%E5%B7%A6%E4%BE%A7%E5%AF%BC%E8%88%AA%E6%9D%A1
https://wiki.moztw.org/MozTW_wiki_%E6%96%87%E4%BB%B6%E5%AF%AB%E4%BD%9C%E8%A6%8F%E7%AF%84
https://www.mediawiki.org/wiki/Suggestions_for_extensions_to_be_integrated
http://www.mediawikibootstrapskin.co.uk/index.php/Top_10_Must_Have_Mediawiki_Extensions
