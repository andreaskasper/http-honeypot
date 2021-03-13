<?php

namespace goo1\Honeypot;

class Honeypot {

  public static function start() {
  
    $wait_sec = rand(0,10);
    $set_cookie = md5(microtime(true));
    $remote_ip = $_SERVER["HTTP_X_FORWARDED_FOR"] ?? $_SERVER["REMOTE_ADDR"] ?? null;

    @file_put_contents("/var/log/honeypot.test.log", var_export($_SERVER, true), FILE_APPEND);

    $row  = date("Y-m-d H:i:s").';';
    $row .= $remote_ip.';';
    $row .= $wait_sec.';';
    $row .= '"'.($_SERVER["HTTP_HOST"] ?? null).'";';
    $row .= '"'.($_SERVER["REQUEST_URI"] ?? null).'";';
    $row .= '"'.($_SERVER["HTTP_USER_AGENT"] ?? null).'";';

    $row .= '"'.json_encode($_SERVER ?? null).'";';
    $row .= '"'.json_encode($_ENV ?? null).'";';
    $row .= '"'.json_encode($_GET ?? null).'";';
    $row .= '"'.json_encode($_POST ?? null).'";';
    $row .= '"'.json_encode($_COOKIE ?? null).'";';

    @file_put_contents("/var/log/honeypot.log1.csv", $row.PHP_EOL, FILE_APPEND);

    setcookie ("akhp", $_COOKIE["akhp"] ?? $set_cookie, time()+365*86400, "/", $_SERVER["HTTP_HOST"], false, false);
    sleep($wait_sec);


    @file_put_contents("/var/log/honeypot.urls.404.log", "http://".$_SERVER["HTTP_HOST"].$_SERVER["REQUEST_URI"].PHP_EOL, FILE_APPEND);

    header($_SERVER["SERVER_PROTOCOL"]." 404 Not Found");
    exit;
  }

}
