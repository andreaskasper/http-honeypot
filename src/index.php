<?php

$wait_sec = rand(0,10);
$set_cookie = md5(microtime(true));

@file_put_contents("/var/log/honeypot.test.log", var_export($_SERVER, true), FILE_APPEND);

$row  = date("Y-m-d H:i:s").';';
$row .= $_SERVER["REMOTE_ADDR"].';';
$row .= $wait_sec.';';
@file_put_contents("/var/log/honeypot.log1.csv", $row, FILE_APPEND);

setcookie ("akhp", $set_cookie, time()+365*86400, "/", $_SERVER["HTTP_HOST"], false, false);
sleep($wait_sec);
  
header($_SERVER["SERVER_PROTOCOL"]." 404 Not Found");
exit;
