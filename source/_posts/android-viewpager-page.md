---
title: '[Android] ViewPager與介紹頁面'
date: 2015-07-06 17:44
catalog: true
header-img: "/img/header_img/article-bg.png"
tags: [Android]
---

現在很多app一打開就是一個ViewPager，然後可以用手指滑
每滑一次就換一張圖，底下還會有圈圈表示說現在滑到第幾章
通常這些圖片都是放功能簡介或是使用教學之類的

我的需求很簡單，就是上面提到的那樣而已
有兩種做法，一種是找現有套件，查了一堆資料每個都跟我推薦[ViewPagerIndicator](https://github.com/JakeWharton/ViewPagerIndicator)這套，我之前也看過這套，只是看起來需要有fragment再加上google play範例好像載不到了，所以只好自己實做一個。

<!-- more -->


Viewpager的實作可參考[Android ViewPager使用详解](http://blog.csdn.net/wangjinyu501/article/details/8169924)裡面的程式碼

``` java
@Override
protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    setContentView(R.layout.activity_intro);

    mViewPager = (ViewPager) findViewById(R.id.viewpager);

    final LayoutInflater mInflater = getLayoutInflater().from(this);

    View v1 = mInflater.inflate(R.layout.intro_layout_1, null);
    View v2 = mInflater.inflate(R.layout.intro_layout_2, null);
    View v3 = mInflater.inflate(R.layout.intro_layout_3, null);
    View v4 = mInflater.inflate(R.layout.intro_layout_4, null);

    viewList = new ArrayList<View>();
    viewList.add(v1);
    viewList.add(v2);
    viewList.add(v3);
    viewList.add(v4);

    mViewPager.setAdapter(new MyViewPagerAdapter(viewList));
    mViewPager.setCurrentItem(0);
}
```

``` java MyViewPagerAdapter
public class MyViewPagerAdapter extends PagerAdapter {
    private List<View> mListViews;

    public MyViewPagerAdapter(List<View> mListViews) {
        this.mListViews = mListViews;
    }

    @Override
    public void destroyItem(ViewGroup container, int position, Object object)   {
        container.removeView((View) object);
    }


    @Override
    public Object instantiateItem(ViewGroup container, int position) {
        View view = mListViews.get(position);
        container.addView(view);
        return view;
    }

    @Override
    public int getCount() {
        return  mListViews.size();
    }

    @Override
    public boolean isViewFromObject(View arg0, Object arg1) {
        return arg0==arg1;
    }
}
```

這樣子你就有一個ViewPager了
這邊特別提一個點，我原本做到這裏想說跑一下試試看
結果一跑在手機上，超級無敵Lag，超明顯
我一直想說是不是這個做法效能會很差，但又覺得沒什麼道理
最後google到[Android ViewPager Lag](http://stackoverflow.com/questions/15763407/android-viewpager-lag)
原來是因為我把圖片放在`drawable`裡面，移到`drawable-hdpi`裡面就真的沒事了
奉勸大家沒事不要亂把圖片放那裡

現在就剩下底下的圈圈了，我是參考[Android view pager with page indicator](http://stackoverflow.com/a/28107089/1568088)
直接用內建的RadioGroup搭配RadioButton做這個功能
唯一要做的事情就是把它的樣式改變一下

設定一下RadioButton的背景
`android:button="@drawable/radio_background"`

``` xml radio_background.xml 
<?xml version="1.0" encoding="utf-8"?>
<selector xmlns:android="http://schemas.android.com/apk/res/android" >
    <item
        android:drawable="@drawable/dot_blue"
        android:state_checked="true"
        android:state_pressed="true" />
    <item
        android:drawable="@drawable/dot_blue"
        android:state_pressed="true" />
    <item
        android:drawable="@drawable/dot_blue"
        android:state_checked="true" />
    <item
        android:drawable="@drawable/dot_grey" />
</selector>
```

```  xml dot_grey.xml
<?xml version="1.0" encoding="utf-8"?>
<shape
    xmlns:android="http://schemas.android.com/apk/res/android"
    android:shape="oval">

    <solid
        android:color="@color/grey"/>

    <size
        android:width="15dp"
        android:height="15dp"/>
</shape>
```

`dot_blue.xml`就是把顏色改成藍色而已，這邊就不附了
值得注意的是調整完以後發現點跟點的距離有點近，記得自己加上`margin`
然後把這個radioGroup加入layout裡面

``` xml activity_intro.xml
<?xml version="1.0" encoding="utf-8"?>
<FrameLayout xmlns:android="http://schemas.android.com/apk/res/android"
    android:orientation="vertical" android:layout_width="match_parent"
    android:layout_height="match_parent">

    <android.support.v4.view.ViewPager
        android:id="@+id/viewpager"
        android:layout_width="match_parent"
        android:layout_height="match_parent" />


    <RadioGroup
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:layout_gravity="center_horizontal|bottom"
        android:orientation="horizontal"
        android:layout_marginBottom="10dp"
        android:id="@+id/radiogroup">

        <RadioButton
            style="@style/radioButton"
            android:id="@+id/radioButton"
            android:checked="true"
            />

        <RadioButton
            style="@style/radioButton"
            android:id="@+id/radioButton2"
            />

        <RadioButton
            style="@style/radioButton"
            android:id="@+id/radioButton3" />

        <RadioButton
            style="@style/radioButton"
            android:id="@+id/radioButton4" />
    </RadioGroup>
</FrameLayout>
```

最後在ViewPager滑動的時候偵測一下，點擊相對應的按鈕，就大功告成了
``` java
mViewPager.setOnPageChangeListener(new ViewPager.OnPageChangeListener() {
    @Override
    public void onPageScrolled(int position, float positionOffset, int positionOffsetPixels) {

    }

    @Override
    public void onPageSelected(int position) {
        switch (position){
            case 0:
                mRadio.check(R.id.radioButton);
                break;
            case 1:
                mRadio.check(R.id.radioButton2);
                break;
            case 2:
                mRadio.check(R.id.radioButton3);
                break;
            case 3:
                mRadio.check(R.id.radioButton4);
                break;
        }
    }

    @Override
    public void onPageScrollStateChanged(int state) {

    }
});
```




