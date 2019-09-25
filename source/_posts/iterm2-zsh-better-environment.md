---
title: '[心得] iTerm2 + zsh，打造更好的工作環境'
date: 2016-01-03 14:21
catalog: true
header-img: "/img/header_img/article-bg.png"
tags: [Tool]
categories:
  - Others
---
平常有在寫 code 的，無論是寫哪一種程式語言、或是哪一種開發環境，都會有一定的時間需要執行一些命令
這時候就會開啟 terminal 開始鍵入指令，最常用的像是`cd`, `ls`, `git`, `ssh`, `rsync`之類的
可是系統內建的終端機其實滿難用的，今天要跟大家推薦一套比較好的選擇

<!-- more -->

[iTerm2](https://www.iterm2.com/)可以取代你的終端機，裝了以後保證你每次都不會想要打開內建的，而是打開這個應用程式。
用這個有什麼好處呢？第一就是很多設定可以調、可以個人化；第二就是介面比較好看，也比較好操作；第三則是可以開很多個分頁，就跟你用瀏覽器一樣，如果要分割畫面的話也是很容易的。

裝好以後可以先來挑個自己中意的佈景主題，很多人都用 [solarized](http://ethanschoonover.com/solarized)，但我自己是比較喜歡 [dracula](https://zenorocha.github.io/dracula-theme/iterm/)。這邊純粹看你自己覺得哪套比較好看就裝哪個。

外觀都弄的差不多之後，可以開始來裝 zsh 了
zsh 是什麼呢？這個就要先從 bash 開始講了，你現在無論是打開 iTerm2 或是內建的終端機，出現的畫面都是在執行 bash 的畫面，所以 bash 也是一個程式，那當然也可以被取代掉。
我自己用過的兩套一套就是 zsh，另一套是 [fish](http://fishshell.com/)
其實 fish 我用的滿不錯的，但看到 zsh 好像外掛比較多、佈景主題也比較多所以就跳過來了，fish 我覺得內建的功能就滿夠用了，尤其是自動提示的功能超 OP，每次都覺得很厲害

至於 zsh 的話，其實 mac 就有內建了，但除了這個以外，推薦必裝的東西叫做：[oh-my-zsh](https://github.com/robbyrussell/oh-my-zsh)，他先幫你載好一些主題、外掛跟設定，簡單來說可以看成是 zsh 的懶人包版本，裝了之後有一堆東西可以用。

`~/.zshrc`是你的設定檔，要調什麼都來這邊調就對了

裝好以後第一件事情當然還是[換主題](https://github.com/robbyrussell/oh-my-zsh/wiki/themes)，或是也可用`random`，每次開啟的時候都會用不同的主題，也是滿特別的。
`agnoster`是一套滿 fancy 的主題，要裝之前記得先 [安裝字型](https://github.com/powerline/fonts)，並且在 `iTerm2`裡面的 Preference -> Profile -> Text 調整好字型，才能夠正確看到一些特殊符號。

我自己是用 `tonotdo`這個主題然後再改了一下，他原本時間在最右邊，我把它調到最左邊然後上色
這個主題還滿容易改的，檔案在`~/.oh-my-zsh/themes/tonotdo.zsh-theme`，我把前三行改成：
```
PROMPT='%{$fg_no_bold[yellow]%}[%*] %{$fg_no_bold[cyan]%}%n%{$fg_no_bold[red]%} ➜ %{$fg_no_bold[green]%}%3~$(git_prompt_info)%{$reset_color%}» '
```
大家可以自己試著改改看，滿容易的

裝好佈景主題以後開始來裝外掛，[oh-my-zsh wiki](https://github.com/robbyrussell/oh-my-zsh/wiki/Plugins)裡面有介紹了一下每個內建外掛是在做什麼，只要在設定檔加一些字就可以使用了，預設只會幫你啟用`git`。
如果想裝更多的，在[awesome-zsh-plugins](https://github.com/unixorn/awesome-zsh-plugins)可以找到，我自己就多裝了[zsh-autosuggestions](https://github.com/tarruda/zsh-autosuggestions)。

介紹到這邊就差不多了，剩下都是個人設定微調的部份，或是裝一些自己覺得實用的 plugin
附上一張我的 iTerm2 截圖當做結尾
![螢幕快照 2016-01-03 下午2.59.15.jpg](http://user-image.logdown.io/user/7013/blog/6977/post/402147/fEGlo1qnSLOxyKl8Lcv0_%E8%9E%A2%E5%B9%95%E5%BF%AB%E7%85%A7%202016-01-03%20%E4%B8%8B%E5%8D%882.59.15.jpg)



參考資料：
1. [認識與學習BASH](http://linux.vbird.org/linux_basic/0320bash.php#bash)
2. [iTerm - 让你的命令行也能丰富多彩](http://swiftcafe.io/2015/07/25/iterm)
3. [ Mac OS X 的 Command Line 環境設定](http://blog.littlelin.info/posts/2014/01/05/mac-os-x-command-line-environment-setup)
4. [[iTerm2] 美化你的Terminal](http://ucheng.logdown.com/posts/2013/10/30/spruce-up-your-terminal)
5. [bash 轉移 zsh (oh-my-zsh) 設定心得](http://icarus4.logdown.com/posts/177661-from-bash-to-zsh-setup-tips)
6. [Oh-My-Zsh 讓你的終端機更強大更美觀](http://iphone4.tw/forums/showthread.php?t=206652)