---
title: '[Ruby] 類別初探'
date: 2014-04-19 21:45
catalog: true
header-img: "/img/header_img/article-bg.png"
tags: [ruby]
---
用這篇筆記一下跟ruby的物件導向有關的東西

一個最簡單的類別

``` ruby
class HelloWorld
  def initialize(myname="aaa")
    @name = name
  end
  
  def hello
    puts("hello",@name)
  end

  def name
    return @name
  end
  
  def name=(value)
    @name = value
  end
  
end

bob = HelloWorld.new("bob")
bob.hello
bob.name
bob.name = "cool"

```

`@name`代表是實體變數的意思
根據我自己的理解，應該就是像
```
Class hello{
  String name;
  String email;
  
  String getName(){
  	return name;
  }
}
```

裡面的那些name跟email一樣
（太久沒寫c++跟java 我都忘記語法是怎樣了...沒關係，意思有到就好）

但是這樣自己寫getter跟setter無敵麻煩
所以可以
``` ruby
class HelloWorld
  attr_accessor :name
  ...
end
```
一行搞定
如果想要只提供讀/寫
就 `attr_reader` or `attr_writer`

如果要寫類別方法的話，有三種寫法
``` ruby
class Hello
  def Hello.hello
  end
  
  def self.hello
  end
end

class << Hello
  def hello...
end
```

類別變數的話則是用`@@`開頭
常數則是直接定義在開頭，用::存取

``` ruby
class Hello
  @@count = 0
  Version = 1
  
  def Hello.count
    @@count
  end
  
  def hello
    @@count+=1
    print("hello")
  end
end

Hello::Version   #=>1
```

