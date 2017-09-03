---
title: '[RoR] 初次見面心得'
date: 2014-04-18 20:06
catalog: true
header-img: "/img/header_img/article-bg.png"
tags: [backend,rails]
---
感人感人
想學RoR這句話已經說了三年以上，今天終於一口氣照著書上的指示弄出一個頁面（無功能）然後build到heroku上面去
以前的學習曲線太陡，沒有其他後端語言的基礎要入門真的滿困難
但是我現在有php當基礎，之後應該會比較好學一點XD

筆記一下ruby的語法：

``` ruby
if a==true then
....
end

unless a==false then
...
end

#elseif是寫成elsif

if a==1 then
...
elsif a==2
....
end

#把變數塞到字串
name = "huli"
puts "hello,#{name}"

name = "a"
name ||= "abc"
num||=123

# @代表實例變數的意思

# "跟' 的差別是 ''裡面的內容會直接被輸出

#陣列
x = [1,2,3,4,5,6]
x.first #x[0]
x.last  #x[x.length-1] or x[-1]

x.each do |i|
	puts i
end

#hash
user = {
	"name"=>"huli",
  "email"=>"huli@huli.tw"
}

user["name"] = "hey"
user["email"]

#date

s = 30.days.ago.to_date
e = Date.today
(s..e).each do |day|
	puts "day: #{day}"
end

puts "*" * 10

5.times{
	puts("a")
}

5.times{ |i|
	puts(i)
}

5.times do |i|
	puts(i)
end

for i in 0..4
	puts(i)
end

(1..5).each{ |i|
	puts(i)
}

(1..5).each do |i|
  puts(i)
end
```