<?php

$wait_sec = rand(0,10);
$set_cookie = md5(microtime(true));

file_put_contents("/var/log/honeypot.test.log", var_export($_SERVER, true), FILE_APPEND);

sleep($wait_sec);
  
header($_SERVER["SERVER_PROTOCOL"]." 404 Not Found");
exit;
