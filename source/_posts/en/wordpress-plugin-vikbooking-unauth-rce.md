---
title: WordPress Plugin VikBooking <= 1.5.3 Unauthorized RCE Vulnerability Details
catalog: true
date: 2022-05-20 12:00:00
tags: [Security]
categories: [Security]
photos: /img/wordpress-plugin-vikbooking-unauth-rce/cover-en.png
---

Recently, I was looking at some WordPress plugins and found that it was a good place to practice because there are many plugins there, and each one has source code that can be viewed. You can do black-box or white-box testing, and installation is also very convenient.

This article will discuss a vulnerability I found a while ago, which uses the most basic and classic attack method, file upload leading to RCE.

Vulnerability ID: [CVE-2022-27862
 WordPress VikBooking Hotel Booking Engine & PMS plugin <= 1.5.3 - Arbitrary File Upload leading to RCE](https://patchstack.com/database/vulnerability/vikbooking/wordpress-vikbooking-hotel-booking-engine-pms-plugin-1-5-3-arbitrary-file-upload-leading-to-rce)

<!-- more -->

## Introduction to VikBooking and Vulnerability Details

[VikBooking](https://wordpress.org/plugins/vikbooking/) is a WordPress booking plugin. The demo on the official website looks like this:

![booking page](/img/wordpress-plugin-vikbooking-unauth-rce/p1-booking-page.png)

There is no difference from other booking plugins. After completing the booking, the administrator can manage the order in the WordPress backend, and the consumer will also receive an email with a URL to manage their own booking:

![booking page customer](/img/wordpress-plugin-vikbooking-unauth-rce/p2-email.png)

Although there is not much on the UI, since we have the source code, we can use white-box testing to see what the implementation is like.

The main operations and logic are in `site/controller.php`, and each function inside it basically corresponds to an action. I found a method called `storesignature`, and the code is as follows:

``` php
public function storesignature()
{
  $sid = VikRequest::getString('sid', '', 'request');
  $ts = VikRequest::getString('ts', '', 'request');
  $psignature = VikRequest::getString('signature', '', 'request', VIKREQUEST_ALLOWRAW);
  $ppad_width = VikRequest::getInt('pad_width', '', 'request');
  $ppad_ratio = VikRequest::getInt('pad_ratio', '', 'request');
  $pitemid = VikRequest::getInt('Itemid', '', 'request');
  $ptmpl = VikRequest::getString('tmpl', '', 'request');
  $dbo = JFactory::getDBO();
  $mainframe = JFactory::getApplication();
  $q = "SELECT * FROM `#__vikbooking_orders` WHERE `ts`=" . $dbo->quote($ts) . " AND `sid`=" . $dbo->quote($sid) . " AND `status`='confirmed';";
  $dbo->setQuery($q);
  $dbo->execute();
  if ($dbo->getNumRows() < 1) {
    VikError::raiseWarning('', 'Booking not found');
    $mainframe->redirect('index.php');
    exit;
  }
  $row = $dbo->loadAssoc();
  $tonight = mktime(23, 59, 59, date('n'), date('j'), date('Y'));
  if ($tonight > $row['checkout']) {
    VikError::raiseWarning('', 'Check-out date is in the past');
    $mainframe->redirect('index.php');
    exit;
  }
  $customer = array();
  $q = "SELECT `c`.*,`co`.`idorder`,`co`.`signature`,`co`.`pax_data`,`co`.`comments` FROM `#__vikbooking_customers` AS `c` LEFT JOIN `#__vikbooking_customers_orders` `co` ON `c`.`id`=`co`.`idcustomer` WHERE `co`.`idorder`=".(int)$row['id'].";";
  $dbo->setQuery($q);
  $dbo->execute();
  if ($dbo->getNumRows() > 0) {
    $customer = $dbo->loadAssoc();
  }
  if (!(count($customer) > 0)) {
    VikError::raiseWarning('', 'Customer not found');
    $mainframe->redirect('index.php');
    exit;
  }
  //check if the signature has been submitted
  $signature_data = '';
  $cont_type = '';
  if (!empty($psignature)) {
    //check whether the format is accepted
    if (strpos($psignature, 'image/png') !== false || strpos($psignature, 'image/jpeg') !== false || strpos($psignature, 'image/svg') !== false) {
      $parts = explode(';base64,', $psignature);
      $cont_type_parts = explode('image/', $parts[0]);
      $cont_type = $cont_type_parts[1];
      if (!empty($parts[1])) {
        $signature_data = base64_decode($parts[1]);
      }
    }
  }
  $ret_link = JRoute::rewrite('index.php?option=com_vikbooking&task=signature&sid='.$row['sid'].'&ts='.$row['ts'].(!empty($pitemid) ? '&Itemid='.$pitemid : '').($ptmpl == 'component' ? '&tmpl=component' : ''), false);
  if (empty($signature_data)) {
    VikError::raiseWarning('', JText::translate('VBOSIGNATUREISEMPTY'));
    $mainframe->redirect($ret_link);
    exit;
  }
  //write file
  $sign_fname = $row['id'].'_'.$row['sid'].'_'.$customer['id'].'.'.$cont_type;
  $filepath = VBO_ADMIN_PATH . DIRECTORY_SEPARATOR . 'resources' . DIRECTORY_SEPARATOR . 'idscans' . DIRECTORY_SEPARATOR . $sign_fname;
  $fp = fopen($filepath, 'w+');
  $bytes = fwrite($fp, $signature_data);
  fclose($fp);
  if ($bytes !== false && $bytes > 0) {
    //update the signature in the DB
    $q = "UPDATE `#__vikbooking_customers_orders` SET `signature`=".$dbo->quote($sign_fname)." WHERE `idorder`=".(int)$row['id'].";";
    $dbo->setQuery($q);
    $dbo->execute();
    $mainframe->enqueueMessage(JText::translate('VBOSIGNATURETHANKS'));
    //resize image for screens with high resolution
    if ($ppad_ratio > 1) {
      $new_width = floor(($ppad_width / 2));
      $creativik = new vikResizer();
      $creativik->proportionalImage($filepath, $filepath, $new_width, $new_width);
    }
    //
  } else {
    VikError::raiseWarning('', JText::translate('VBOERRSTORESIGNFILE'));
  }
  $mainframe->redirect($ret_link);
  exit;
}
```

From the function name and code, it can be inferred that it is a function to upload a signature file, and the contents of the file will be base64-encoded first. Therefore, the code decodes it back to binary and writes it to the file. The core code is as follows:

``` php
$psignature = VikRequest::getString('signature', '', 'request', VIKREQUEST_ALLOWRAW);

//check if the signature has been submitted
$signature_data = '';
$cont_type = '';

if (!empty($psignature)) {
  //check whether the format is accepted
  if (strpos($psignature, 'image/png') !== false || strpos($psignature, 'image/jpeg') !== false || strpos($psignature, 'image/svg') !== false) {
    $parts = explode(';base64,', $psignature);
    $cont_type_parts = explode('image/', $parts[0]);
    $cont_type = $cont_type_parts[1];
    if (!empty($parts[1])) {
      $signature_data = base64_decode($parts[1]);
    }
  }
}
$ret_link = JRoute::rewrite('index.php?option=com_vikbooking&task=signature&sid='.$row['sid'].'&ts='.$row['ts'].(!empty($pitemid) ? '&Itemid='.$pitemid : '').($ptmpl == 'component' ? '&tmpl=component' : ''), false);
if (empty($signature_data)) {
  VikError::raiseWarning('', JText::translate('VBOSIGNATUREISEMPTY'));
  $mainframe->redirect($ret_link);
  exit;
}
$sign_fname = $row['id'].'_'.$row['sid'].'_'.$customer['id'].'.'.$cont_type;
$filepath = VBO_ADMIN_PATH . DIRECTORY_SEPARATOR . 'resources' . DIRECTORY_SEPARATOR . 'idscans' . DIRECTORY_SEPARATOR . $sign_fname;
$fp = fopen($filepath, 'w+');
$bytes = fwrite($fp, $signature_data);
fclose($fp);
```

From the last paragraph, it can be seen that the content written to the file is `$signature_data`, and the path is `VBO_ADMIN_PATH . DIRECTORY_SEPARATOR . 'resources' . DIRECTORY_SEPARATOR . 'idscans' . DIRECTORY_SEPARATOR . $sign_fname`. If we can control `$signature_data` and `$sign_fname`, we have an arbitrary file writing vulnerability. The values of these variables are as follows:

``` php
if (strpos($psignature, 'image/png') !== false || strpos($psignature, 'image/jpeg') !== false || strpos($psignature, 'image/svg') !== false) {
  $parts = explode(';base64,', $psignature);
  $cont_type_parts = explode('image/', $parts[0]);
  $cont_type = $cont_type_parts[1];
  if (!empty($parts[1])) {
    $signature_data = base64_decode($parts[1]);
  }
}
$sign_fname = $row['id'].'_'.$row['sid'].'_'.$customer['id'].'.'.$cont_type;
```

A normal `$psignature` looks like this: `data:image/png;base64,image_content`.

Here, we first check if `$psignature` has the specified content type. If so, we use `;base64,` to split the string. The split parts will become:

``` php
parts[0] = 'data:image/png';
parts[1] = image_content;
```

Then, we use `image/` to split `parts[0]`, and the second part of the data obtained (in the example above, `png`) is the content type, while `parts[1]` is directly base64-decoded and used as the file content to be written.

The `$sign_fname` part of the file name is some ID with the content type just obtained added at the end.

From the above logic, it can be seen that the file content can be controlled arbitrarily, and the file name can also be easily bypassed, like this:

```
image/png/../../../../shell.php;base64,web_shell
```

The check will pass because it contains `image/png`. After the cut, `parts[0]` becomes `image/png/../../../../shell.php`. The resulting content type is `png/../../../../shell.php`, and the concatenated file name will look like this: `id_sid_cid.png/../../../../shell.php`. Although this file name looks very unreasonable, it is the file followed by `../`. However, this is not a problem in PHP. You can see the following example:

``` php
<?php
  $filepath = 'not_exist.php/../poc.php';
  $fp = fopen($filepath, 'w+');
  $bytes = fwrite($fp, 'abc');
  fclose($fp);
?>
```

Code like the one above will still write the content to `poc.php` in the same directory.

After having an arbitrary file writing vulnerability, writing a web shell will result in RCE, as shown below:

![rce](/img/wordpress-plugin-vikbooking-unauth-rce/p3-rce.png)

## Fix

Vikbooking fixed this vulnerability in version 1.5.4 by changing the code that retrieves data and content type to the following:

``` php
if (!empty($psignature)) {
    /**
     * Implemented safe filtering of base64-encoded signature image
     * to obtain content and file extension.
     *
     * @since       1.15.1 (J) - 1.5.4 (WP)
     */
    if (preg_match("/^data:image\/(png|jpe?g|svg);base64,([A-Za-z0-9\/=+]+)$/", $psignature, $safe_match)) {
            $signature_data = base64_decode($safe_match[2]);
            $cont_type = $safe_match[1];
    }
}
```

After changing to use regular expressions to process, it ensures that the matched content type will only be the file extension of the image. In the case where other parameters in the file name cannot be controlled, files cannot be written to arbitrary locations.

## Conclusion

It can only be said that when implementing functions that allow users to upload files, you must be especially careful. This function is particularly prone to problems, such as:

1. The file name is not filtered well, uploading PHP can result in web shell, uploading HTML is XSS
2. The path is not filtered well, and files can be uploaded to any location
3. Unpacking may encounter [zip slip](https://github.com/snyk/zip-slip-vulnerability)

In short, in the future, when implementing similar functions, remember to pay special attention to these issues to avoid writing vulnerable code.
