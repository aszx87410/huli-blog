---
title: 從歷史開始認識 JavaScript
catalog: true
date: 2022-01-15 10:29:19
tags: [JavaScript,Front-end]
categories: [JavaScript]
---

我認為想要真正認識 JavaScript 的話，要從歷史開始。為什麼？因為從它的歷史，可以知道為什麼某些部分是這樣子設計，為什麼會有這些看似奇怪的行為。雖然有些古早的知識可能沒什麼實際用途，但對我來說是很有趣的。

學習它的歷史，並不是死背它出現的年代或是當初花了幾天開發設計，而是要去理解它出現的脈絡，去理解為什麼需要它，又為什麼它是這樣子被設計的。

想了解 JavaScript 的歷史，我最推薦的是這個資源：[JavaScript: The First 20 Years](http://www.wirfs-brock.com/allen/posts/866)，因為 JavaScript 之父 Brendan Eich 也是作者之一，想看中譯版的話在這邊：[JavaScript 二十年](https://cn.history.js.org/)。

這本書紀錄了從 1995 年到 2015 年，一共二十年的 JavaScript 歷史，如果有時間的話我強烈建議你把它全部看完，會對 JavaScript 有不同的體會（還會知道很多冷知識）。

底下我會挑一些我覺得比較重要的東西來寫，資料來源沒有特別講的話，都是來自於上面提到的那本書，所以若是覺得似曾相似是正常的。

由於我跟 JavaScript 差不多時候出生，因此這些早期的歷史我並沒有親身體會過，若是寫得好像我有親身參與的話，全都是想像而已。

<!-- more -->

## JavaScript 的誕生

我覺得在讀歷史的時候，講到年代有個重點，那就是要讓大家感同身受，否則就只是冷冰冰的文字而已。

1993 年，知名的圖形瀏覽器 Mosaic 誕生（是知名的，但不是第一個）。你可能會疑惑為什麼我要強調「圖形」這兩個字，難道有瀏覽器是純文字的嗎？還真的有。

像是 1992 年出現的 [Lynx](https://zh.wikipedia.org/wiki/Lynx)，或者是 2011 年推出的 [w3m](https://zh.wikipedia.org/wiki/W3m)，都是純文字的瀏覽器。

用 w3m 看我的部落格的話，會長得像這樣：

![w3m](/img/js-history/w3m.png)

有興趣想玩玩看的，可以在 Linux 系統上把 w3m 裝起來：`apt-get install w3m`，然後 `w3m https://blog.huli.tw`，就可以看到了。

接著 1994 年年底，網景（Netscape）的 Netscape Navigator 推出了，並且迅速的擴張，在幾個月後就成為了瀏覽器中的霸主。

1994 年是什麼樣的年代？是 iPhone 第一代誕生前 13 年，Windows 95 誕生的前一年，那時候還沒有「手機」這個名稱，而是叫做大哥大。神機 Nokia 3310 是在 2000 年推出的，這也是六年以後的事情了。

台灣的網路是從 1985 年學術網路開始，在 1991 才正式連接全球，1994 年 HiNet 才成立，1995 年才有蕃薯藤與 Ptt。

在 1994 年的時候，這些都還不存在，可見那是一個相對早期的時代，也是網路正要開始蓬勃發展的年代。

而這樣一個正要興起的市場，自然人人都想要來分一杯羹。微軟在 1994 年年底時提出了收購 Netscape 的計畫，但是被拒絕了，而 Netscape 的管理層在那時便意識到未來很有可能會面臨到來自微軟的競爭——大名鼎鼎的 IE，就是在不久後的 1995 年 8 月所推出的。

那時的 Netscape 原本就想在瀏覽器上加入一個腳本語言，正好在 1995 年年初時 Sun 帶著還沒正式發佈的 Java 找上了 Netscape，並且達成了合作，同意把 Java 整合進 Netscape 2 中，兩間公司手牽手一起擊敗微軟，這就是後來的 Java Applet。

我相信有很多跟我一樣年輕的人，都不知道 Java Applet 是什麼。總之呢，你可以用 Java 寫一個應用程式，編譯過後放到網頁上面去，讓瀏覽器幫你開啟 Java 來執行，這樣的好處是使用者不需要主動下載 Java application，都靠瀏覽器幫你搞定就好。

從[維基百科](https://zh.wikipedia.org/wiki/Java_applet)上可以看到 Java Applet 的寫法：

``` java
import java.applet.Applet;
import java.awt.*;

// Applet code for the "Hello, world!" example.
// This should be saved in a file named as "HelloWorld.java".
public class HelloWorld extends Applet {
  // This method is mandatory, but can be empty (i.e., have no actual code).
  public void init() { }

  // This method is mandatory, but can be empty.(i.e.,have no actual code).
  public void stop() { }

  // Print a message on the screen (x=20, y=10).
  public void paint(Graphics g) {
    g.drawString("Hello, world!", 20,10);
  
  // Draws a circle on the screen (x=40, y=30).
    g.drawArc(40,30,20,20,0,360);
  }
}
```

這樣的程式碼會在畫面上畫出一個 Hello, World 來。把上面的 Java 編譯過後產生 class 檔，就可以嵌入到網頁中了：

``` html
<!DOCTYPE HTML PUBLIC 
  "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd"> 
<HTML>
<HEAD>
<TITLE>HelloWorld_example.html</TITLE>
</HEAD>
<BODY>
<H1>A Java applet example</H1>
<P>Here it is: <APPLET code="HelloWorld.class" WIDTH="200" HEIGHT="40">
This is where HelloWorld.class runs.</APPLET></P>
</BODY>
</HTML>
```

那既然有了這麼強大的網頁應用程式，為什麼還需要一個腳本語言呢？不能也用 Java 嗎？

原因是有些簡單的應用如果用 Java 來寫會顯得太笨重，例如說你可能只是想要做個 input 的欄位檢查，但如果用 Java 你還要先學會物件導向 Class 的概念，還要熟悉整個 Java 生態系，寫了 10 幾行的 boilerplate 後才能開始寫你想要的功能。

因此，在 1995 年加入 Netscape 的 Brendan Eich，接到的任務就是要開發出一個在瀏覽器上執行的程式語言，要輕量，而且要長得像 Java。為什麼要長得像 Java？因為一開始，它就是做為 Java 的輔助語言而誕生的，而這個語言暫時命名為 Mocha。

因為時間緊迫的關係，Brendan Eich 花了十天打造出了 Mocha 的 prototype。而「長得像 Java」這個來自上層的需求，也影響了 JavaScript 的設計，不過除了 Java，JavaScript 也參考了 C、AWK、Scheme 以及 Self 等程式語言。

許多人都聽過一句話，「Java 跟 JavaScript 的關係，就像狗跟熱狗一樣」，但實際上，或許他們的淵源比你想得還要深，並不只是跟風或是名字類似而已。

舉例來說，有許多人應該都碰過一個莫名其妙的設計：

``` js
console.log(new Date())
// Thu Aug 19 2021 22:55:22 GMT+0800 (台北標準時間)

console.log(new Date().getMonth())
7
```

明明是八月，為什麼 log 出來卻是 7？這個設計你以為是 JavaScript 獨創的嗎？不是，其實是從 JDK 1.0 的 `java.util.Date` 抄來的，這是[當時的文件](https://web.archive.org/web/20111203213751/http://docs.oracle.com/javase/1.3/docs/api/java/util/Date.html)

![Java docs](/img/js-history/java1.png)

那為什麼 Java 要這樣做呢？有人指出可能是因為在更古老的 C 的 [localtime](https://linux.die.net/man/3/localtime) 中，month 就是從 0 開始的。

更多相關資源可以參考：

1. [Why does the month argument range from 0 to 11 in JavaScript's Date constructor?](https://stackoverflow.com/questions/2552483/why-does-the-month-argument-range-from-0-to-11-in-javascripts-date-constructor)
2. [Javascript Date method inconsistency - getDate vs getMonth](https://stackoverflow.com/questions/9687521/javascript-date-method-inconsistency-getdate-vs-getmonth/9688617#9688617)

而有關於 JavaScript 之父對於這些討論的[回覆](https://twitter.com/BrendanEich/status/771006397886533632)中，也可以再次看出「JavaScript 要長得像 Java」這個需求：

![twitter js](/img/js-history/twitter-js.png)

在 1995 年 5 月一篇由 Netscape 所發布的[新聞稿](https://web.archive.org/web/19970614002809/http://home.netscape.com:80/newsref/pr/newsrelease67.html)中，正式推出了 JavaScript，副標題就是：

> 28 INDUSTRY-LEADING COMPANIES TO ENDORSE JAVASCRIPT AS A COMPLEMENT TO JAVA FOR EASY ONLINE APPLICATION DEVELOPMENT

說明了 JavaScript 是為了輔助 Java 而存在。

在這篇新聞稿中其實也可以看到許多 JavaScript 的特性，像是：

>  JavaScript is analogous to Visual Basic in that it can be used by people with little or no programming experience to quickly construct complex applications. JavaScript's design represents the next generation of software designed specifically for the Internet and is:
> 
> 1.designed for creating network-centric applications  
> 2.complementary to and integrated with Java  
> 3.complementary to and integrated with HTML  
> 4.open and cross-platform.  

他們把 JavaScript 比喻成 Visual Basic，簡單容易上手，而 JavaScript 更是 Java Applet 與 HTML 的橋樑。你可以把 Java Applet 想成是一個獨立的應用程式，脫離網頁而存在，如果想要改變網頁上的內容，需要透過 JavaScript 這個橋樑來輔助，如同下面這一段所說：

> With JavaScript, an HTML page might contain an intelligent form that performs loan payment or currency exchange calculations right on the client in response to user input. A multimedia weather forecast applet written in Java can be scripted by JavaScript to display appropriate images and sounds based on the current weather readings in a region

JavaScript 可以獨立存在，做為 HTML 的輔助，處理一些基本邏輯，也可以跟 Java Applet 一起使用。在早期的文件中，有提到 Java 跟 JavaScript 彼此之間如何溝通（參考自 [Java-to-Javascript Communication](http://www.gedlc.ulpgc.es/docencia/lp/documentacion/javadocs/guide/plugin/developer_guide/java_js.html)） 

``` js
import netscape.javascript.*;
import java.applet.*;
import java.awt.*;
class MyApplet extends Applet {
     public void init() {
         JSObject win = JSObject.getWindow(this);
         JSObject doc = (JSObject) win.getMember("document");
         JSObject loc = (JSObject) doc.getMember("location");

         String s = (String) loc.getMember("href");  // document.location.href
         win.call("f", null);                      // Call f() in HTML page
     }
}
```

會利用 `JSObject` 這個物件來取得 DOM。在另一個[教學網頁](http://www.java2s.com/Code/JavaScript/Development/UsingJavaScriptinanApplet.htm)裡面有著更完整的範例：

``` js
/*
Mastering JavaScript, Premium Edition
by James Jaworski 

ISBN:078212819X
Publisher Sybex CopyRight 2001
*/
<title>Accessing JavaScript from an applet</TITLE>
<form NAME="textForm">
<P>Enter some text and then click Display Text:
 <INPUT TYPE="text" NAME="textField" SIZE="20"></P>
</FORM>
<APPLET CODE="ReadForm.class" WIDTH=400 HEIGHT=100
 NAME="readApp" MAYSCRIPT>
[The ReadForm Applet]
</APPLET>

//Reading a JavaScript Form (ReadForm.java)
import java.applet.*;
import java.awt.*;
import java.awt.event.*;
import netscape.javascript.JSObject;
import netscape.javascript.JSException;
public class ReadForm extends Applet {
 String text="Enter some text for me to display!";
 Font font = new Font("TimesRoman",Font.BOLD+Font.ITALIC,24);
 JSObject win, doc, form, textField;
 public void init() {
  win = JSObject.getWindow(this);
  doc = (JSObject) win.getMember("document");
  form = (JSObject) doc.getMember("textForm");
  textField = (JSObject) form.getMember("textField");
  setLayout(new BorderLayout());
  Panel buttons = new Panel();
  Button displayTextButton = new Button("Display Text");
  displayTextButton.addActionListener(new ButtonEventHandler());
  buttons.add(displayTextButton);
  add("South",buttons);
 }
 public void paint(Graphics g) {
  g.setFont(font);
  g.drawString(text,30,30);
 }
 class ButtonEventHandler implements ActionListener {
  public void actionPerformed(ActionEvent e){
   String s = e.getActionCommand();
   if("Display Text".equals(s)) {
    text= (String) textField.getMember("value");
    win.eval("alert(\"This alert comes from Java!\")");
    repaint();
   }
  }
 }
}
```

新聞稿中還有另一段更有趣的：

> A server-side JavaScript script might pull data out of a relational database and format it in HTML on the fly. A page might contain JavaScript scripts that run on both the client and the server. On the server, the scripts might dynamically compose and format HTML content based on user preferences stored in a relational database, and on the client, the scripts would glue together an assortment of Java applets and HTML form elements into a live interactive user interface for specifying a net-wide search for information.

懶得看的話，關鍵字是「A page might contain JavaScript scripts that run on both the client and the server.」，我沒看錯吧，在 1995 年的時候，JavaScript 就可以跑在 server side 了嗎？

對，就是這麼神奇，我大 JavaScript 早在 25 年前就已經稱霸全端，程式碼長得像這樣：

![Server side JavaScript](/img/js-history/js-server.png)

看起來有點像是 PHP，可以嵌入會在後端執行的程式碼，並且輸出結果。

如果你對這個有興趣，當初的歷史文件還保留著，底下這些文件會教你一步步用 JavaScript 寫出一個後端的應用程式：

1. [Server-Side JavaScript Reference](https://docs.oracle.com/cd/E19957-01/816-6410-10/816-6410-10.pdf)
2. [Writing Server-Side JavaScript Applications](https://docs.oracle.com/cd/E19957-01/816-5653-10/816-5653-10.pdf)

若是想了解更多這段歷史，可以參考 [Server-side JavaScript a decade before Node.js with Netscape LiveWire](https://dev.to/macargnelutti/server-side-javascript-a-decade-before-node-js-with-netscape-livewire-l72)

想要查資料的話可以用 `Netscape LiveWire` 當作關鍵字，不能只用 `LiveWire JS`，因為你會找到 [Laravel Livewire](https://laravel-livewire.com/)，一個基於 Laravel 的全端框架。

## 結語

Java 與 JavaScript 確實是兩個不同的程式語言，雖然當初採用 JavaScript 這個名字有更多是基於行銷上的考量，但不可否認地，JavaScript 的一些特性確實受到了 Java 的影響。

在 [JavaScript creator Brendan Eich | True Technologist Ep 1](https://www.youtube.com/watch?v=WqMbzVWIAjY&t=1326s&ab_channel=InfoWorld) 這支影片中，JavaScript 之父 Brendan Eich 也有稍微提到當年的一些歷史；除此之外，還有對於 TypeScript 跟 WebAssembly 的看法，有興趣的話也可以聽聽看。

這篇文章只有提到歷史長河中的一小段而已，在這之後其實還有許多有趣的歷史，但我覺得我目前再怎麼寫也不會比《JavaScript: The First 20 Years》寫得好，因此歷史的部分就先在這裡打住吧。

如果你有興趣了解更多 JavaScript 早期的設計跟歷史，那我再次推薦這本書。

參考資料：

1. [Wikipedia: Java applet](https://zh.wikipedia.org/wiki/Java_applet)
2. [Wikipedia: JavaScript](https://zh.wikipedia.org/wiki/JavaScript)
3. [台灣網路發展大事記總表(1985~2014)](http://www.myhome.net.tw/timeline/images/internet_timeline02.pdf)
4. [Re: applet 即將走入歷史？](https://www.ptt.cc/bbs/java/M.1366527781.A.869.html)
5. [用十分鐘瞭解 《JavaScript的程式世界》](https://www.slideshare.net/ccckmit/javascript-65883956)
6. [js 简史](https://www.jianshu.com/p/208019383aa2)
7. [新时代新潮流 WebOS【17】需要不需要 JavaScript](https://www.ifanr.com/17760)
8. [技術應用的艱辛探索](https://www.ithome.com.tw/voice/134976)
9. [Java-to-Javascript Communication](http://www.gedlc.ulpgc.es/docencia/lp/documentacion/javadocs/guide/plugin/developer_guide/java_js.html)
10. [Using JavaScript in an Applet : Applet Jar « Development « JavaScript DHTML](http://www.java2s.com/Code/JavaScript/Development/UsingJavaScriptinanApplet.htm)
11. [NETSCAPE AND SUN ANNOUNCE JAVASCRIPT, THE OPEN, CROSS-PLATFORM OBJECT SCRIPTING LANGUAGE FOR ENTERPRISE NETWORKS AND THE INTERNET](https://web.archive.org/web/19970614002809/http://home.netscape.com:80/newsref/pr/newsrelease67.html)
12. [JavaScript: The First 20 Years](http://www.wirfs-brock.com/allen/posts/866)
