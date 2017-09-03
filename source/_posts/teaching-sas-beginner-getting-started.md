---
title: '[教學] SAS超新手入門'
date: 2014-11-03 22:20
catalog: true
header-img: "/img/header_img/article-bg.png"
tags: [tutorial,sas] 
---
相隔快一個月沒有發文，沒想到一發文又是另外一個跟我原本文章類型很不一樣的東西。

這是因為最近一陣子沒有什麼在寫程式，所以一時也想不到要寫什麼主題的文章，而湊巧有同學跑來問我SAS（他們覺得寫程式的人會一項應該其他都會，一樣通樣樣通），而我因為閒來無事加上以前也有同學問過我，我有參考他們的講義稍微學了一點，想說把心得記在這邊，一方面以後如果碰到相似問題可以自己跑回來看，另外一方面說不定也可以造福一些被SAS弄的頭昏腦脹的人。

<!-- more -->


基本上只要Google: SAS 教學，就會有一大堆的SAS入門資料，排在很前面又不錯的像是
http://www.statedu.ntu.edu.tw/lab/SAS%E8%AA%9E%E6%B3%95%E8%AA%AA%E6%98%8E.asp
裡面就已經介紹很多比較簡單的題目會用到的語法

這篇文章沒有打算要講多複雜，就簡單教你怎麼用SAS算出那六項指標：平均數、標準差、變異數、眾數、全距、中位數

#資料輸入
首先你必須知道你的資料要如何輸入進去SAS，並且以什麼方式呈現
在SAS裡面的資料都是透過一個叫做Data Set的東西儲存的，也就是資料集
如果大家在國高中有學過一點程式設計，應該會知道"變數"這個概念，你必須宣告一個變數去儲存你想要的資料，而在這邊資料集也是同樣的意思，像是：
```
DATA score;
INPUT chinese english math;
CARDS;
80 90 70
60 50 40
30 20 10
;
```
第一行`DATA score`就是宣告一個資料集叫做score，所以這score你可以取任何你想取的名稱（不過應該其他程式語言一樣會有些許限制，例如說開頭不能用數字之類的），下一行的INPUT後面接的是你的資料欄位，就好像Excel的欄位那樣，這邊用三個空白隔開三個單字，所以就是說有三個欄位，而這欄位名稱當然也可以自己取，你想取a b c也沒關係，但建議用比較有辨識度的命名方式，後續的工作會比較輕鬆。接著`CARDS;`就是跟電腦說：我下一行要輸入資料了喔！就是這樣子而已，從下一行開始每一行就是一筆資料，輸入完以後以一個分號做結尾。

這邊比較有變化的第一點是INPUT的部份，後面接的欄位名稱如果要輸入的值是"文字"的話，必須加上$字號，例如說
```
DATA score;
INPUT gender $ chinese english math;
CARDS;
Female 80 90 70
Male 60 50 40
Female 30 20 10
;
```
第一個欄位gender所輸入的值不是數字而是文字，所以後面必須加上$字號。

第二個要注意的地方是在INPUT最後面可以加上`@@`，代表連續輸入的意思。
一般來說，每筆資料的分隔是用換行區分，但如果你覺得這樣很麻煩，加上`@@`以後就可以不必加換行
```
DATA score;
INPUT gender $ chinese english math @@;
CARDS;
Female 80 90 70 Male 60 50 40 Female 30 20 10
;
```
輸入資料的部份其實差不多就是這樣，如果要從檔案輸入資料的話也大同小異，上網找一下範例即可

#初步處理資料
像是有些題目會給你五科的分數，叫你算出總分，那這種題目要怎麼做呢？
首先，我們需要一個新的資料集，而這個新的跟原本的差別只有在於新的有總分的欄位，而SAS也提供滿直覺的語法
（這邊的score就是上面的那個輸入三科分數的score）
```
DATA score_sum;
  SET score;
    sum=chinese+english+math;
RUN;
```
第一行就是說這個資料集叫做"score_sum"你想取叫更有意義的"data_with_sum"或是"ihatehomework"也都可以
接著`SET`就是說我要利用`score`這個資料集，在這上面添加東西，添加什麼呢？就是下一行的`sum=chinese+english+math;`，新增一個欄位叫做sum，而這個值就是那三科的分數加起來。

###練習1：建立一個data set，可以儲存國文、數學、英文、物理、化學五科的分數
###練習2：建立一個data set，除了練習1的欄位以外新增一個總分的欄位
###練習3：由於物理統一加五分，新增一個data set儲存舊的五科的分數跟新的物理分數

解答：
```
DATA hw1
INPUT chi,mat,eng,phy,che;
CARDS;
...(資料略過)
;

DATA hw2
  SET hw1;
    sum=chi+mat+eng+phy+che;
RUN;
...(資料略過)
;

DATA hw3
  SET hw1;
    new_phy=phy+5;
RUN;
...(資料略過)
;
```

#資料輸出
其實資料輸出很簡單，一個在SAS很重要的概念就是`PROC`，指的就是`Procedure`，你可以想成是一個小程式，或對程式語言有點概念的可以想成是一個function，一個函式。
```
PROC PRINT;
RUN;
```
就是去呼叫一個叫做`PRINT`的函式，但是他怎麼知道要印出什麼呢？我們又沒有跟他說要印什麼。這我有點懶得查，反正應該是印出最近一次使用到的data set之類的，更完整的呼叫應該是
```
PROC PRINT DATA=hw2;
RUN;
```
利用`DATA=資料集名稱`指定要印出哪個資料集。

#分析資料
前面一些基礎講完了，終於來到重點部分，該如何從這些資料得出他的平均數或是其他資訊呢？
很簡單，SAS身為一套專業的統計軟體，很理所當然的一定會內建好一些東西幫你做這些事情，畢竟連Excel都有了，SAS沒有理由沒有。而這個分析的函式就叫做`UNIVARIATE`，直接附上範例
```
PROC UNIVARIATE DATA=score_sum;
	VAR chinese math sum;
RUN;
```

`VAR`後面接的是你要分析哪幾個欄位，在這邊就是分析國文、數學跟總分三個欄位
執行以後你就可以看到SAS多出一些報表，裡面就會有很多你需要的資訊
但有時候你不會想看整份報表，你只想要看到你想知道的數據，例如說你只想知道平均數跟標準差這兩項資料
那該怎麼辦呢？

```
PROC UNIVARIATE DATA=score_sum;
	VAR chinese math sum;
	OUTPUT OUT=result MEANS= STD= /AUTONAME;
RUN;

PROC PRINT DATA=result;
RUN;
```

利用`OUTPUT`指令，後面的`OUT=新的資料集名稱`，代表把你想要的數據輸出到新的資料集，你想要哪些數據呢？我想要`MEANS（平均數）`跟`STD（標準差）`，這些代號都可以在網路上查到，而後面接`/AUTONAME`代表輸出的這些欄位會自動幫你取名字，那自動跟非自動差在哪邊呢？

```
PROC UNIVARIATE DATA=score_sum;
	VAR chinese math sum;
	OUTPUT OUT=result MEANS=chinese_mean math_mean sum_mean STD=chinese_std math_std sum_std;
RUN;

PROC PRINT DATA=result;
RUN;
```
這就是自己取名稱的範例，因為你`VAR`填了三個欄位，代表你要分析三個，所以你得出的結果也會有三項資料，而你要幫這三項個別取欄位名稱，最後就會出來一張只有這幾個欄位的報表。

#排序
如果你知道排序的英文是sort，你就可以大概猜想出要怎麼排序
```
PROC SORT DATA=score OUT=result;
	BY chinese;
RUN;
```
要排序的資料集叫做`score`，排序後輸出的資料集叫做`result`，用`chinese`這個欄位來排。
簡單易懂，沒什麼好講的，如果要更麻煩的排序我就不會了，請自行google XD

#排名
排名就比排序更複雜一點了，原因等等會講，先直接來個範例
```
PROC RANK DATA=score_sum OUT=result;
	VAR sum;
	RANKS rank;
RUN;
```
乍看之下跟之前的函式其實有些類似，`VAR`後面放的是要用什麼欄位來排名（為什麼不跟sort一樣用BY，這我就不知道了），`RANKS`後面接的是排名的欄位要叫什麼名稱。而排名比較複雜的原因有兩個，第一個是有兩種排名依據，一個是數字越大越前面，一個是相反，而只要在後面加上`DESCENDING`即可顛倒預設的順序。（至於預設是哪個我忘了，兩個都試試看就知道了）
```
PROC RANK DATA=score_sum OUT=result DESCENDING;
	VAR sum;
	RANKS rank;
RUN;
```

第二個麻煩的地方是，我第一次用這個函式的時候，名次居然出現小數點！這是因為在分數相同的時候，他會把名次平均，例如說90分 50分 50分 40分，名次會是1 2.5 2.5 3之類的，變成很奇怪的現象，而強大的SAS在這方面當然也有東西可以控制。

```
PROC RANK DATA=score_sum OUT=result DESCENDING TIES=LOW;
	VAR sum;
	RANKS rank;
RUN;
```
更詳細的用法可參考：http://blog.sina.com.cn/s/blog_5d6632e70100ddqe.html

簡單來說，SAS裡面預設好的這些PROC可以達成幾乎任何跟統計有關的事情，你幾乎不用自己去寫算式，例如說算標準差你不用把標準差公式寫出來，你只要用預設好的執行即可，這就是SAS厲害的地方。

#分類
最常見的範例就是除了給你分數，還給你性別，要你算出男生的平均數、標準差跟女生的平均數、標準差
這類題目跟之前的其實很像，只是多了分類這個概念。這個時候我們要介紹一個新的函式：`MEANS`，我也不知道為什麼要取一個這麼容易混淆的名字，而用法跟`UNIVARIATE`幾乎一樣，差別在於`UNIVARIATE`沒有分類的功能。
```
PROC MEANS DATA=score_sum;
	CLASS gender;
	VAR chinese math sum;
	OUTPUT OUT=result MEAN= STD= /AUTONAME;
RUN;
```
`CLASS`就是要用什麼分群去計算，其餘語法都跟`UNIVARIATE`很像，就不再介紹了

#其他小細節
要記得加上分號，還有`RUN`有時候也會忘記加，總之除了輸入資料的時候，每一行的結尾都會有`;`，而只要有`PROC`的地方最後也都會有`RUN`，你可以想成你要讓程式去執行所以要加RUN。

而SAS你只要掌握兩大原則：資料集、內建函式（PROC），其實就不會很難，就只是每個函式要傳入的參數不太一樣，可以用的指令不太一樣而已，其他格式跟語法其實都大同小異。

因為我也只會這些，如果要畫圖或是更複雜的操作可以參考前面附的參考資料，或是上網google。
這篇的SAS程式碼基本上都有測試過，但難免有時候還是會有小錯誤，如果有錯的話麻煩留言糾正我一下，感謝。

