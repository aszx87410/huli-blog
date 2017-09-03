---
title: '[教學] "今晚九點電影"快速開發'
date: 2014-06-21 19:10
catalog: true
header-img: "/img/header_img/article-bg.png"
tags: [turorial]
---
先來一張瀏覽圖
![](https://www.dropbox.com/s/xm7juaxfw4d3jm9/%E8%9E%A2%E5%B9%95%E5%BF%AB%E7%85%A7%202014-06-13%20%E4%B8%8B%E5%8D%884.47.20.jpg?dl=1)

有關這個app的介紹可以參考以前寫過的：[今晚九點電影開發日誌](http://huli.logdown.com/posts/194808-at-nine-oclock-in-the-evening-the-film-development-log)

當初是用Google App Engine(JAVA) + Android開發出這個app
如今過了幾年，會的技術也變多了，於是決定用php + corona 再做一次app
順便寫下教學文讓其他人可以參考

<!-- more -->
先附上code
server的code在[這邊](https://github.com/aszx87410/movie_to_nine_server)
app的code在[這裡](https://github.com/aszx87410/movie_to_nine_app)

此教學文章分為兩個部分，server端跟mobile端
server端是用php去抓取[開眼電影網](http://tv.atmovies.com.tw/tv/attv.cfm?action=todaytime)的資料
在這部份可以學會兩件事
1. 利用curl去抓特定網址的資料
2. 利用regexp解析資料

mobile端則是使用corona打造一個app去抓取server端的資料
並且填入List裡面
你可以學會的有
1. 去抓取特定網址的資料
2. tableView的使用方法
3. 字串的解析

#server端
因為會用到抓取html這個功能很多次，所以先寫成一個函式
``` ruby
function getHtml($url){
  //用curl發送request
  $ch = curl_init();
  curl_setopt($ch, CURLOPT_URL, $url); 
  curl_setopt($ch, CURLOPT_REFERER, "http://tv.atmovies.com.tw/tv/attv.cfm?action=todaytime");
  curl_setopt($ch, CURLOPT_RETURNTRANSFER, true); 
  $result = curl_exec($ch); 
  curl_close($ch);
  return $result;
}
```
`curl`的用法很簡單，首先先把一個變數利用`curl_init()`初始化
接著再針對這個變數利用`curl_setopt()`去設定一些選項
最後利用`curl_exec($ch)`去執行
在選項的部份，`CURLOPT_URL`就是URL的意思
`CURLOPT_RETURNTRANSFER`這個選項如果沒有指定的話，在執行`curl_exec($ch)`以後會自動輸出結果
而我們想要的是把結果保存在一個變數中，所以設成`true`，就可以利用一個變數去接收
`CURLOPT_REFERER`的話，就要先了解什麼是`Referer`
可以先請大家先做一個測試，先去[開眼的節目表](http://tv.atmovies.com.tw/tv/attv.cfm?action=todaytime)
接著隨便找一個電影節目點下去，就到了這部電影的介紹
然後把網址列的網址複製，開一個新的分頁再貼上然後按下enter
神奇的事情發生了，居然顯示了 **no tv data**
明明就是同一個網址，怎麼會這樣呢？
這是因為，從節目表到電影介紹的這個過程中，`request`會帶著一個`referer`的參數
跟下一個頁面說：我是從這邊來的
於是在電影介紹的這個頁面就可以藉由判斷`referer`，擋掉不是從開眼連過來的`request`
其實在「抓取電影列表」的這個功能中並不需要這個也可以正常使用
至於在什麼時候會用到？等等在另外一個功能就知道了

函式寫好以後，就實際來抓資料吧
先來抓電視台的名稱
``` ruby
	//抓取資料
	$result = getHtml("http://tv.atmovies.com.tw/tv/attv.cfm?action=todaytime");
	$domain = "http://tv.atmovies.com.tw";

	$number_to_channel = array();
	preg_match_all('/<a class=.*at15b.*href="(.+)">(.+)<\/a>/',$result,$match,PREG_PATTERN_ORDER);
	$channels = array();
	for($i=0;$i<count($match[1]);$i++){
		$channels[$i] = array();
		$channels[$i]["program"] = array();
		$channels[$i]["link"] = $domain.$match[1][$i];
		$channels[$i]["name"] = $match[2][$i];

		//取得編號
		preg_match('/channel_id=CH(\d.)/',$channels[$i]["link"],$match_number);
		$number_to_channel[$match_number[1]] = $i;
	}
```
`preg_match_all`這個函式可以用`regexp`去匹配字串，並且儲存結果
`regexp`看過有人翻成正規表達式或是正則表達式之類的，至於匹配的`pattern`隨便google都可以找到一堆
因為這個我也滿不熟的，所以試了有點久才試出來
基本上就是`.`可以代表任何字元，但是要注意的是不包括**換行、空白、tab**
後面加上`*`表示可以出現任意次，`+`代表出現一次以上
用括弧括起來的地方表示**記憶集結**，就是要保存結果的地方
上面的code基本上就是取出節目名稱、連結、編號這三項東西
編號是因為等等要抓的節目要看編號才能知道是屬於哪一個電視台的
不清楚的話就去看一下網頁的source code稍微了解一下結構即可

再來是抓節目的部份
``` ruby
	//配對連結，片名
	preg_match_all('/<a.+href="(.+)">[\s]*<font class=.*at11.*>(.*)<\/font><\/a><font color=.*#606060>(.*)<\/font><\/font>/',$result,$match,PREG_PATTERN_ORDER);
	
	//配對時間
	preg_match_all('/<td.*align=.*class=.*at9.*>(.*)<\/td>/',$result,$time,PREG_PATTERN_ORDER);
	
	for($i=0;$i<count($match[1]);$i++){

		$temp=array();

		$temp["name"] = $match[2][$i].$match[3][$i];
		$temp["link"] = $domain.$match[1][$i];
		$temp["time"] = $time[1][$i];

		//取得編號
		preg_match('/channel_id=CH(\d.)/',$temp["link"],$match_number);
		$number = $match_number[1];

		array_push($channels[$number_to_channel[$number]]["program"],$temp);
	}
```
這段其實也就只是透過`regexp`去抓出配對的部份
不過我對`regexp`其實滿不熟的，很多的`pattern`其實應該都可以寫的更好
只是既然跑起來可以跑的出結果，我就暫時懶得修了XD

抓完資料以後只要加上一行
``` ruby
echo json_encode($channels);
```
把結果輸出成json的格式即可

到這邊，抓取節目表的功能就完成了，但是還欠缺一個功能
那就是，我想要讓使用者在mobile端點下item的時候，可以連結到影片介紹
但是前面已經說過了，如果不是從開眼連過去的不會顯示出資料，那怎麼辦呢？
仔細觀察可以注意到在節目表點下去出現的網頁裡面，會有個「更多影片介紹」的連結
而那個連結是不需要`referer`的，於是我們要做的事情就是抓到那個連接
但若是在抓取節目表的時候一併去抓取這個連結，會造成執行速度過慢

所以我決定新開一個頁面是`redirect.php`，讓使用者帶一個參數進來，回傳正確的頁面
使用者在app裡面點擊item的時候，就先連到這個網頁去抓正確的網址
``` ruby
	if(!isset($_GET["url"])){
		exit();
	}

	$result = getHtml($_GET["url"]);
	preg_match('/<a href=.*(http:.*action=filmdat.*)">更多/',$result,$intro_link);
	echo $intro_link[1];
```
這就是上面那個`referer`的功用了
因為加上`referer`之後，我們才能正確的連結到這個網頁，進而抓取想要的資料

這樣子，server端就完成了。

#mobile端
先介紹一下app需要有的功能，等等會比較容易講解code
1. 顯示節目表
2. 點下去可以開啟介紹網頁
3. 會自動儲存結果，同天以內不需要網路也可以看到節目表
4. 現在在播的節目會用黃字顯示

再來介紹一下等等會用的函式
首先是[Lua-Preference-Library](https://github.com/SatheeshJM/Lua-Preference-Library)
裡面有附使用說明，基本上就是讓你可以很方便的存取資料
因為我們要存的東西很少，所以很適合用這個而不是使用`sqlite`

再來是兩個函式
``` lua
local function trim( s )
   return string.match( s,"^()%s*$") and "" or string.match(s,"^%s*(.*%S)" )
end

local function parseTime(s)
    return tonumber(s:sub(1,2)*60) + tonumber(s:sub(4,5))
end
```
第一個是從官方blog直接copy下來的，就是把頭尾兩端的空白切掉
第二個是為了要判斷現在在播哪個節目，所以把`14:25`這種格式的時間轉成數字

接著進入到主程式的部份，因為上網抓資料需要時間
所以在程式的一開頭用`native.setActivityIndicator( true )`
會有一個圈圈一直跑一直跑，等抓到資料的時候我們再取消

然後需要一個整個畫面的`tableView`
``` lua
-- Create the widget
local tableView = widget.newTableView{
    left = display.screenOriginX,
    top = display.screenOriginY,
    height = display.actualContentHeight,
    width = display.actualContentWidth,
    onRowRender = onRowRender,
    onRowTouch = onRowTouch,
    backgroundColor = {0,0,0}
}
```
`onRowTouch`就是點擊row會發生的事件
`onRowRender`則是很重要的函式，決定了row的內容

再來我習慣用一個`main`函式當做入口，所以先宣告一下main function然後呼叫
``` lua
local function main()
    local date = os.date("%m-%d")
    value = preference.getValue("date")

    --檢查時間
    if(value and value==date)then
        appendRow(preference.getValue("list"))
        native.setActivityIndicator( false )
    else
        network.request("http://huli.tw/movietonine/index.php?type=mobile", 'GET', listener)
    end
end

main()
```
首先先看`date`裡面存的資料跟今天的日期是否一致
一致的話去直接從`preference`裡面拿資料，並且利用`appendRow`方法新增進List裡面
反之，則利用`network.request`去抓資料
`network.request`接三個參數，網址、方法、listener
方法基本上就是`POST`跟`GET`，在這邊用`GET`即可
istener很重要，直接來看code
``` lua
local function listener(event)
    if ( event.isError ) then
        print( "Network error!")
    else
        --取得在body間的text
        local str = event.response

        --json decode
        local list = json.decode(str)
        local date = os.date("%m-%d")
        preference.save{
            date=date,list=list
        }
        appendRow(list)
    end
    native.setActivityIndicator( false )
end
```
`event.response`就是抓到的資料
接著用`json.decode`解析資料，然後把日期跟list都保存起來
這樣下次在同一天開app，就不用上網抓了

`appendRow`的code有點長我就不完全附上了
其中重點是
``` lua
tableView:insertRow{
  rowColor = { default={0,0,0}, over={ 1, 0, 0,0.5} },
  lineColor = { 0 },
  rowHeight = 60,
  params = {
    text = list[i].program[j].name,
    time = list[i].program[j].time,
    link = list[i].program[j].link,
    now = is_now
  }
}
```
前面三個是corona內建的參數
就是row的底色、分隔線的顏色還有row的高度
params則是可以自己帶參數進去
在`onRowRender`事件裡就是憑著這些參數去決定要怎麼顯示
``` lua
local function onRowRender( event )

    local row = event.row

    local rowTitle = display.newText( row,row.params.text, 10, 10, nil, 20 )
    rowTitle:setFillColor(1)
    rowTitle.anchorX = 0
    rowTitle.anchorY = 0

    local rowTime
    if(row.params.time)then
        rowTime = display.newText( row,row.params.time, 10,30, nil, 16 )
        rowTime:setFillColor(1)
        rowTime.anchorX = 0
        rowTime.anchorY = 0
    end

    --看是不是現在在播的
    if(row.params.now==true)then
        rowTitle:setFillColor(1,1,0)
        if(row.params.time)then
            rowTime:setFillColor(1,1,0)
        end
    end
end
```
再來看點擊row的事件
先連到redirect.php去抓取正確的網址
然後再利用內建瀏覽器開啟網頁，` system.openURL`可以幫我們做到這件事
``` lua
local function listener_link(event)
    native.setActivityIndicator( false )

    if ( event.isError ) then
        print( "Network error!")
    else
        local str = (string.match(event.response,"<body>(.*)</body>"))
        str = trim(str)
        system.openURL(str)
    end
end

local function onRowTouch( event )
    if(event.phase=="release")then
        local link = event.target.params.link
        network.request("http://huli.tw/movietonine/redirect.php?url="..url.escape(link), 'GET', listener_link)
        native.setActivityIndicator( true )
    end
end
```
做到這邊，整個app就差不多完成了

#總結
server + app大概花了我一個晚上+一個早上的時間
如果熟悉regexp的pattern的話應該還可以更快一點
主要碰到比較難解決的就是那個`referer`比較麻煩一點，其他地方都還好
還有，在corona的`build.settings`裡面記得把使用網路的權限打開不然會出錯

這支程式還有許多地方可以改進
例如說判斷現在在播哪個節目的地方其實就有bug
在某些情形會顯示錯誤或是顯示不出來
等我以後有時間再來修吧！

-------

後記：
我在某天晚上花了半小時把這個地方做修正
有興趣的人可以直接看code，我有commit新的上去
只是那邊寫的很粗糙

server也有可以改進的地方
那就是像app那樣把結果存起來，畢竟同一天裡面抓到的資料應該會是一樣的
存起來的話可以大幅改進效率

後記2：
我一開始天真的在php頁面中嵌入google analytics的code
後來想到說那段code必須要被執行才有用，所以純粹只是抓資料是完全沒用的
所以在github裡面的code，server端會有輸出google analytics的部分
app端會有抓取`<body>`到`</body>`資料的部份，這兩個部分都是可以忽略的
但是考慮到我如果一改，舊版app的使用者就會出錯
所以我先只把部分code移除


最後重申一次，server的code在[這邊](https://github.com/aszx87410/movie_to_nine_server)
app的code在[這裡](https://github.com/aszx87410/movie_to_nine_app)
感謝您的觀看
