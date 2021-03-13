<?php

namespace goo1\Honeypot;

class Honeypot {

  public static function start() {
  
    $wait_sec = rand(0,10);
    $set_cookie = md5(microtime(true));
    $remote_ip = $_SERVER["HTTP_X_FORWARDED_FOR"] ?? $_SERVER["REMOTE_ADDR"] ?? null;

    @file_put_contents("/var/log/honeypot.test.log", "--------------".PHP_EOL.var_export($_SERVER, true).PHP_EOL."=== GET ===".var_export($_GET, true).PHP_EOL."=== POST ===".PHP_EOL.var_export($_POST, true).PHP_EOL, FILE_APPEND);

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
    
    //https://thephp.cc/neuigkeiten/2020/02/phpunit-ein-sicherheitsrisiko
    if (substr($_SERVER["REQUEST_URI"],-14,14) == "eval-stdin.php") {
      die("root@localhost:~# ".PHP_EOL);
    }
    
    if (substr($_SERVER["REQUEST_URI"],-5,5) == "/RPC2") {
      die("ready...".PHP_EOL);
    }
    
    if (substr($_SERVER["REQUEST_URI"],-12,12) == "swagger.json") {
      header("Content-Type: application/json");
      die(file_get_contents(__DIR__."/assets/swagger.json"));
    }
    
    if ($_SERVER["REQUEST_URI"] == "/") {
      die(file_get_contents(__DIR__."/assets/nginx_default.html")); 
    }
    
    /* === no good response send 404 ===*/

    @file_put_contents("/var/log/honeypot.urls.404.log", "http://".$_SERVER["HTTP_HOST"].$_SERVER["REQUEST_URI"].PHP_EOL, FILE_APPEND);

    header($_SERVER["SERVER_PROTOCOL"]." 404 Not Found");
    exit;
  }

}
