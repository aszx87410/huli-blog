---
title: '[Rails] RailsBridge心得'
date: 2014-08-02 16:20
catalog: true
header-img: "/img/header_img/article-bg.png"
tags: [backend,rails]
---
最近在看[railsbridge](http://zh-tw.railsbridge.org/)練rails基本功
這系列教學寫的很不錯，第一階段用scaffold讓你體驗rails，第二階段讓你自己generate model, controller
第三階段只給你要求、參考資料、提示，你要自己寫code把這些需求實現出來

這邊記下一些心得

1. 要連接兩個model時，在model裡面做完has_many, belongs_to以後記得要
`rails g migration AddUserIdToPosts user_id:integer`
` add_column :posts, :user_id, :integer`

2. rails的命名慣例一直不是很熟練
哪邊要用單數，哪邊要用複數不是很清楚
RESTful也不是記得很熟
要找個時間記清楚（或是會越做越熟練?）

這邊筆記一下
resources :jobs
rails g controller jobs
rails g model job

之後再詳細寫一篇文章筆記好了
