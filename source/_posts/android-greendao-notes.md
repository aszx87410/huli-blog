---
title: '[Android] greenDAO 筆記'
date: 2015-07-16 14:10
catalog: true
header-img: "/img/header_img/article-bg.png"
tags: [Android]
---
之前在找一套在android上面好用的db library，最後找到greenDAO這一套
看了看文件跟使用方法覺得還不錯，滿喜歡的
但是真正開始以後才知道原來前置作業有點麻煩...

首先要把官方的project clone下來，然後用eclipse引入幾個project
但是我在這邊就碰到問題了，因為eclipse跟我說沒有project可以引入.....

最後幸好找到這套 [GreenDaoForAndroidStudio](https://github.com/SureCase/GreenDaoForAndroidStudio)
就是在你的Android Studio裡面import module，接著改一改檔案就可以生成那些java檔案了
其實只要能完成這步，就沒有什麼問題了

一般的CURD看官方文件即可
但有時候那些方法不夠用，有時候會需要自己執行query
這個時候就參考這篇 [How do I execute “select distinct ename from emp” using GreenDao](http://stackoverflow.com/questions/23445174/how-do-i-execute-select-distinct-ename-from-emp-using-greendao)

``` java
private static final String SQL_DISTINCT_ENAME = "SELECT DISTINCT "+EmpDao.Properties.EName.columnName+" FROM "+EmpDao.TABLENAME;

public static List<String> listEName(DaoSession session) {
    ArrayList<String> result = new ArrayList<String>();
    Cursor c = session.getDatabase().rawQuery(SQL_DISTINCT_ENAME, null);
    if (c.moveToFirst()) {
        do {
            result.add(c.getString(0));
        } while (c.moveToNext());
    }
    c.close();
    return result;
}
```

直接用SQLite之前那樣的方法，執行rawQuery然後用cursor拿結果就好
table的名稱跟欄位名稱可以直接去看`...Dao.java`這些檔案，`...`就是你model的名稱
這樣就可以按照自己的需求執行了

ref:
[GreenDAO早期佈置記錄](http://www.cncoders.net/article/4817/)
[Queries](http://greendao-orm.com/documentation/queries/)
[Android ORM lib: greeDao](http://blog.kenyang.net/2014/09/android-orm-lib-greedao.html)

