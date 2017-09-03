---
title: '[Corona] 播放在網路上的音樂檔'
date: 2014-03-21 22:50
catalog: true
header-img: "/img/header_img/article-bg.png"
tags: [corona]
---
在網路上google了一下資料以後
發現Corona好像沒有能夠直接播放網路上的音樂檔案（例如http://aaa.com/a.mp3 ） 的API
要播放影片是有啦，但是音樂就沒有
要直接放音樂也是可以，只是畫面會整個被蓋掉
``` lua
media.playVideo("http://aaa.com/a.mp3", media.RemoteSource, true) 
```
參考資料：Play streaming Internet Radio
http://forums.coronalabs.com/topic/29612-play-streaming-internet-radio/

所以目前我知道的方法，就是把音樂下載下來以後再播放
先附上參考資料
how to play web url audio files corona sdk?
http://stackoverflow.com/questions/12833681/how-to-play-web-url-audio-files-corona-sdk

Corona docs:network.download()
http://docs.coronalabs.com/api/library/network/download.html

code差不多長這樣：
``` lua

    local function networkListener( event )
            if ( event.isError ) then
                    print( "Network error - download failed" )
            elseif ( event.phase == "began" ) then
                    print( "Progress Phase: began" )
            elseif ( event.phase == "ended" ) then
                    print( "download" )
                    local music=audio.loadSound(event.response.filename,system.TemporaryDirectory)
                    local music_play = audio.play(music)
            end
    end

    local filename = "aaa.mp3"
    local weburl = "http://aaa.com/" .. filename
	network.download(weburl,"GET",networkListener,filename,system.TemporaryDirectory)

```