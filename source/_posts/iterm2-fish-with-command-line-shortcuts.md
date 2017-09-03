---
title: 'iTerm2 + fish 與 command line快捷鍵'
date: 2015-07-14 11:35
catalog: true
header-img: "/img/header_img/article-bg.png"
tags: [tool]
---

用[iTerm2](https://www.iterm2.com/)有一段時間了，雖然我還不是很會用，但光是介面比原本的好看就值得換掉
最近開始用一套之前看很久的commnad line shell，名字很可愛，叫做[fish](http://fishshell.com/)

於是就把原生的shell換成fish
基本上是參考[這一篇](http://stackoverflow.com/questions/453236/how-can-i-set-fish-shell-as-my-default-shell-on-mac)
1. `sudo nano /etc/shells `
2. add `/usr/local/bin/fish` to your list of shells 
3. `chsh -s /usr/local/bin/fish`

這樣你的預設shell就變成fish，無論是開內建的終端機或是iTerm2都會直接看到fish
但用了以後碰到的第一個問題是環境變數，有些你之前寫在`~/.bash_profile`寫好的設定都失效
上網找解法看到這篇：[re-use '~/.profile` for Fish?](http://superuser.com/questions/446925/re-use-profile-for-fish)

先建立一個檔案叫做`~/.config/fish/config.fish`
再把它提供的這段code
```
egrep "^export " ~/.profile | while read e
	set var (echo $e | sed -E "s/^export ([A-Z_]+)=(.*)\$/\1/")
	set value (echo $e | sed -E "s/^export ([A-Z_]+)=(.*)\$/\2/")
	
	# remove surrounding quotes if existing
	set value (echo $value | sed -E "s/^\"(.*)\"\$/\1/")

	if test $var = "PATH"
		# replace ":" by spaces. this is how PATH looks for Fish
		set value (echo $value | sed -E "s/:/ /g")
	
		# use eval because we need to expand the value
		eval set -xg $var $value

		continue
	end

	# evaluate variables. we can use eval because we most likely just used "$var"
	set value (eval echo $value)

	#echo "set -xg '$var' '$value' (via '$e')"
	set -xg $var $value
end
```

複製貼上，儲存，重開一下command line
應該就會把之前的設定移到這裡來了，真是輕鬆方便

接著是介紹一些command line在使用時的快捷鍵
[Shortcuts to Move Faster in Bash Command Line](http://teohm.com/blog/2012/01/04/shortcuts-to-move-faster-in-bash-command-line/)
這超重要，因為很多時候我可能指令打錯一個字，像是 `giy commit -am "hello world"`
我以前都用鍵盤按左然後一直按直到把y改成t

但是上面那篇介紹一堆方便的快捷鍵，從此以後不必再那麼累
在這邊筆記一下我會用到的
`Ctrl+A` 移到開頭
`Ctrl+E` 移到結尾
`Alt+左或右` 移動一個字(這超方便)
`Ctrl+W` 刪除直到碰到空白，例如說你現在是`git commit -am "edit"`，游標在最尾端
按一次就可以把"edit"刪掉，再按一次刪掉-am，很實用
`Ctrl+K` 把游標之後的都剪下，你可以用`Ctrl+A`然後`Ctrl+K`，剪下這整行指令

我覺得記這五個就超級夠用了
