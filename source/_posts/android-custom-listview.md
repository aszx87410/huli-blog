---
title: '[Android] 自訂ListView'
date: 2015-06-12 11:06
catalog: true
header-img: "/img/header_img/article-bg.png"
tags: [Android]
---
在android裡面最常用的功能自訂ListView絕對榜上有名
在一個app裡面看不到任何ListView絕對是非常稀有的事情
所以怎麼快速的打造一個custom listview是很重要的
最近要做一個app，大概要五六個自訂ListView，幸好依靠著我之前自己寫的文章找回記憶
順利的完成

在這邊直接轉貼一下我之前寫的兩篇文章
[簡單易學 自訂ListView](https://www.ptt.cc/bbs/AndroidDev/M.1356579180.A.F98.html)

<!-- more -->


程式截圖:http://ppt.cc/YaGO

首先，有一個重點知道以後自訂ListView就不再那麼神秘
那就是List的每一列可以看成都是一個view
所以第一步就是就是決定每一列到底要長什麼樣子
以我想要達成的效果來說
我的item需要有兩個TextView
一個放電影名稱或是電影台的名稱
另外一個則放時間
所以建立一個 list_item.xml 來達成這個layout


``` xml
<?xml version="1.0" encoding="utf-8"?>
<RelativeLayout xmlns:android="http://schemas.android.com/apk/res/android"
    android:layout_width="match_parent"
    android:layout_height="match_parent" >

    <TextView
        android:id="@+id/title"
        android:layout_width="match_parent"
        android:layout_height="wrap_content"
        android:layout_alignParentLeft="true"
        android:layout_alignParentTop="true"  />
    <TextView
        android:id="@+id/time"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:layout_alignParentLeft="true"
        android:layout_below="@+id/title" />

</RelativeLayout>
```
上面的id叫做title 下面的則叫做time


接著，你要決定你的每一個item需要哪些資料
為了以後的方便，我們要自己建一個class來放這些資料
以這篇為例子
我要傳入的資料有:電影台名稱 電影標題 電影時間
其實我的case比較特殊啦
因為可以很明顯看到每個list item長的並不是很相同
所以我加了一個type的參數

type 0 = 這個item是電影 顏色是白色
type 1 = 這個item是電影台
type 2 = 這個item是電影 顏色是黃色

所以我的參數有 type , title(電影or電影台名稱),time(電影時間)
class叫做Movie.class 內容很簡單的長這樣

``` java
public class Movie {
        private int type;
        private String name;
        private String time;
        public Movie(int type,String name,String time) {
                this.type = type;
                this.name = name;
                this.time = time;
        }
        public int getType(){
                return type;
        }
        public void setType(int type){
                this.type = type;
        }
        public String getName(){
                return name;
        }
        public void setName(String name){
                this.name = name;
        }
        public String getTime(){
                return time;
        }
        public void setTime(String time){
                this.time = time;
        }
}
```
再來先回到需要ListView的地方
假設ListView的id叫做ListView01好了
我們先宣告三個東西

``` java
    private ListView listV;
    List<Movie> movie_list = new ArrayList<Movie>();
    private MyAdapter adapter;
```

MyAdapter是什麼呢? 是我們等一下會講到的東西

接著

``` java
listV=(ListView)findViewById(R.id.ListView01);
```

movie_list就是你要傳入的東西

以本篇為例 就是

``` java
movie_list.add(new Movie(1,"HBO電影台",""));
movie_list.add(new Movie(0,"綠光戰警","7:00"));
movie_list.add(new Movie(2,"鋼鐵人","9:00"));
movie_list.add(new Movie(0,"蝙蝠俠:開戰時刻","11:00"));

movie_list.add(new Movie(1,"衛視電影台",""));
movie_list.add(new Movie(0,"海角七號","7:00"));
movie_list.add(new Movie(2,"陣頭","9:00"));
movie_list.add(new Movie(0,"星空","11:00"));
```

這樣movie_list就是你想要的資料了

而且因為是把自訂的class放進去
所以很適合重複利用
例如說你今天想呈現的是一組聯絡人資料(姓名 手機 地址...)
你就依照上面的步驟自訂一個class Userinfo
然後改成 user_list.add(new Userinfo(...));就好了

接著設定一下adapter

``` java
adapter = new MyAdapter(Main.this,movie_list);
                        ^^^^你的activity的class

listV.setAdapter(adapter);
```

這樣就只剩下最後一個部份了
那就是MyAdapter這個class
最一開始長這樣

``` java
public class MyAdapter extends BaseAdapter{

}
```

接下來我們一步一步加進幾個必要的東西進來

首先我們需要
``` java
        private LayoutInflater myInflater;
        private List<Movie> movies;
```
然後我們在MyAdapter建立的時候順便傳入兩個東西
``` java
        public MyAdapter(Context context,List<Movie> movie){
                myInflater = LayoutInflater.from(context);
                this.movies = movie;
        }
```
movies就是你傳入的整個list

也就是你想要建立的東西

接著我們再加入幾個method 程式碼應該不難理解我就不多做說明
``` java
        @Override
        public int getCount() {
                return movies.size();
        }

        @Override
        public Object getItem(int arg0) {
                return movies.get(arg0);
        }

        @Override
        public long getItemId(int position) {
                return movies.indexOf(getItem(position));
        }
```
最後重點就是getView了

在這之前我們先宣告一下inner class
``` java
    private class ViewHolder {
        TextView txtTitle;
        TextView txtTime;
        public ViewHolder(TextView txtTitle, TextView txtTime){
                this.txtTitle = txtTitle;
                this.txtTime = txtTime;
        }
    }
```
方便我們之後設定每一列的資料

getView一開始長這樣
``` java
@Override
public View getView(int position, View convertView, ViewGroup parent) {

}
```
接著我們一步一步添加東西
``` java
ViewHolder holder = null;
if(convertView==null){
        convertView = myInflater.inflate(R.layout.list_item, null);
        holder = new ViewHolder(
                (TextView) convertView.findViewById(R.id.title),
                (TextView) convertView.findViewById(R.id.time)
                );
        convertView.setTag(holder);
}else{
        holder = (ViewHolder) convertView.getTag();
}
```
有關tag的功用 請參考這篇

http://www.cnblogs.com/qingblog/archive/2012/07/03/2575145.html


接著先取得現在要做的的資料
``` java
Movie movie = (Movie)getItem(position);
```
然後開始設定

``` java
//標題的顏色
int color_title[] = {Color.WHITE,Color.WHITE,Color.YELLOW};
//時間的顏色
int color_time[] = {Color.WHITE,Color.WHITE,Color.YELLOW};
//背景的顏色
int color_back[] = {Color.BLACK,Color.BLUE,Color.BLACK};
//時間是否顯示
int time_vis[] = {View.VISIBLE,View.GONE,View.VISIBLE};

int type_num = movie.getType();
holder.txtTitle.setText(movie.getName());
holder.txtTitle.setTextColor(color_title[type_num]);
holder.txtTitle.setBackgroundColor(color_back[type_num]);
holder.txtTime.setText(movie.getTime());
holder.txtTime.setTextColor(color_time[type_num]);
holder.txtTime.setVisibility(time_vis[type_num]);
```

因為我的list並不是每一個item都長一樣所以才需要這樣設定
像是如果type是1 代表只需要顯示一個電影台名稱而已
就要把背景設成藍色 時間也不需要顯示所以設成View.GONE
如果你的每個item都長一樣就不需要那麼大費周章了

最後記得 `return convertView;`

完整程式碼在這裡: MyAdapter.java http://pastebin.com/GxBfpdCB

如此一來就大功告成了 順利顯示出我們想要的結果
使用自訂class的好處就是當我們以後有不同需求的時候
就像一個範本可以自己隨意修改
這篇也提供了一個固定的建立自訂ListView的流程

1.建一個list_item.xml 在res/layout下 看你每一列想要長怎樣
2.寫一個[   ].java 裡面說明你的資料結構為何
 (例:Movie.java http://pastebin.com/DWDx3EqW )
3.寫一個MyAdapter.java

其實程式的結構無須修改
只要一些細節需要調整而已


這篇的作法基本上是參考 http://tinyurl.com/clen3tn
步驟清晰易懂也有附上完整的code


ListView有個很方便的功能叫做setTextFilterEnabled
可以很方便的做到搜尋的功能
但是自從我們自訂ListView的內容以後
顯然這個方法不能直接套用 所以要自己override一些東西
下一篇將延續這一篇的作法，說明如何針對自訂的ListView做搜尋

第二篇：
[自訂ListView的搜尋功能](https://www.ptt.cc/bbs/AndroidDev/M.1356581041.A.242.html)
像是內建的通訊錄那樣
有一個editText可以輸入,當你輸入a的時候
底下的list就自動跑出a開頭的聯絡人名單

對於普通的ArrayAdapter來說 這件事情非常簡單可以達成
最近研究了一下自訂的ListView如何達成這件事
跟大家分享一下心得
建議先看過普通的ListView如何做出這樣的東西再來看這篇文章
http://tinyurl.com/borkabs


由於這篇直接從上一篇的code拿來修改 所以建議先看過上一篇
首先先在你的activity加入一個editText

``` java
EditText edt;
edt = (EditText) findViewById(R.id.EditText01);
```
然後記得設定ListView

``` java
listV.setTextFilterEnabled(true);
```

接著就像普通的搜尋那樣 建立一個TextWatcher

``` java
edt.addTextChangedListener(new TextWatcher(){
    @Override
    public void onTextChanged( CharSequence arg0, int arg1, int arg2, int
arg3){}
    @Override
    public void beforeTextChanged(CharSequence arg0, int arg1, int arg2, int
arg3){}
    @Override
    public void afterTextChanged(Editable arg0)
    {
        Main.this.adapter.getFilter().filter(arg0);
    }
 });
```

接著我們只要修改上一篇中寫得MyAdapter.java就可以了
原本是

``` java
public class MyAdapter extends BaseAdapter
```
由於我們要做filter的功能 所以需要

``` java
public class MyAdapter extends BaseAdapter implements Filterable
```
接著宣告

``` java
private List<Movie> mOriginalValues;
private MyFilter filter;
```
mOriginalValues是拿來保存你最原本傳進來的list
MyFilter這之後會講到
然後加入一個method

``` java
        @Override
        public Filter getFilter() {
                if (filter == null){
                        filter  = new MyFilter();
                }
                        return filter;
        }

```
接著就是開始本篇文章的重點了
就是MyFilter的部份

``` java
private class MyFilter extends Filter{
```
有兩個方法需要繼承
``` java
protected FilterResults performFiltering(CharSequence constraint)

protected void publishResults(CharSequence constraint, FilterResults results)
```

performFiltering是實際需要做篩選的code 好像是在不同的thread進行
publishResults則是用來把篩選結果publish出去的函式
先來看後者

``` java
@Override
protected void publishResults(CharSequence constraint, FilterResults results)
{
    movies = (ArrayList<Movie>)results.values;
    if(results.count>0){
        notifyDataSetChanged();
    }
    else{
        notifyDataSetInvalidated();
    }
}
```

記得嗎? movies是我們存放資料的List
而results.values就是篩選過後的結果
我們讓movies = results.values
notifyDataSetChanged之後會自動更新List


再來是

``` java
protected FilterResults performFiltering(CharSequence constraint) {

constraint = constraint.toString();
FilterResults result = new FilterResults();
if (mOriginalValues == null) {
        synchronized (this) {
                mOriginalValues = new ArrayList<Movie>(movies);
        }
}
```

先判斷mOriginalValues是不是null
如果是的話把movies的值整個複製過去
第一次執行的話一定是null 所以mOriginalValues就會是一開始的值

``` java
if(constraint != null && constraint.toString().length() > 0){
        ArrayList<Movie> filteredItems = new ArrayList<Movie>();
        for(int i = 0, l = mOriginalValues.size(); i < l; i++){
                Movie m = mOriginalValues.get(i);
                if(m.getName().contains(constraint)){
                        filteredItems.add(m);
                }
        }
        result.count = filteredItems.size();
        result.values = filteredItems;
}else{
        synchronized(this){
        ArrayList<Movie> list = new ArrayList<Movie>(mOriginalValues);
                result.values = list;
                result.count = list.size();
    }
}
return result;
```

先看else的部份
會執行到這邊就表示傳進來的參數(要搜尋的字串)是不合格的
所以就直接把一開始的mOriginalValues return回去
至於另一個部份就是搜尋整個mOriginalValues
看看是否包含要搜尋的字串
最值得注意的是

``` java
                Movie m = mOriginalValues.get(i);
                if(m.getName().contains(constraint)){
                        filteredItems.add(m);
                }
```
這邊換成你自己的自訂class
比如說我有一個class叫做Userinfo 要搜尋聯絡人
那就
``` java
Userinfo u = mOriginalValues.get(i)
if(u.getName().contains(constraint)){
        filteredItems.add(u)
}
```

總之filteredItems就是你最後要顯示的資料
完整的code在這邊 http://pastebin.com/pdPeAC7K
好處就是你剛剛寫得有關自訂的ListView的code完全不需要修改
只需要加入一些東西就可以達成搜尋的功能


參考資料:
http://blog.csdn.net/jiahui524/article/details/7802033
http://tinyurl.com/cu3pst4

可伸縮ListView:
http://www.javacodegeeks.com/2013/06/android-expandablelistview-with-custom-adapter-baseexpandablelistadapter.html
http://www.androidhive.info/2013/07/android-expandable-list-view-tutorial/

聊天視窗：
http://blog.csdn.net/ryantang03/article/details/8001599