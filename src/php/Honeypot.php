<?php

namespace goo1\Honeypot;

class Honeypot {

  public static function start() {
  
    $wait_sec = rand(0,20);
    $set_cookie = md5(microtime(true));
    $remote_ip = $_SERVER["HTTP_X_FORWARDED_FOR"] ?? $_SERVER["REMOTE_ADDR"] ?? null;
    
    $ipinfo = json_decode(@file_get_contents("https://api.goo1.de/ipinfo.scan.json?ip=".urlencode($remote_ip)), true);

    // If API didn't provide a hostname, try DNS PTR lookup
    if (isset($ipinfo["result"]) && (empty($ipinfo["result"]["hostname"]) || $ipinfo["result"]["hostname"] === $remote_ip)) {
      $ptr_host = @gethostbyaddr($remote_ip);
      // Only use PTR if it's not just the IP address
      if ($ptr_host && $ptr_host !== $remote_ip) {
        $ipinfo["result"]["hostname"] = $ptr_host;
      }
    }

    @file_put_contents("/var/log/honeypot.test.log", "--------------".PHP_EOL.var_export($_SERVER, true).PHP_EOL."=== ipinfo ===".var_export($ipinfo["result"] ?? null, true).PHP_EOL."=== GET ===".var_export($_GET, true).PHP_EOL."=== POST ===".PHP_EOL.var_export($_POST, true).PHP_EOL, FILE_APPEND);

    $row  = date("Y-m-d H:i:s").';';
    $row .= $remote_ip.';';
    $row .= $wait_sec.';';
    
    $row .= '"'.($_SERVER["REQUEST_METHOD"] ?? null).'";';
    $row .= '"'.($_SERVER["HTTP_HOST"] ?? null).'";';
    $row .= '"'.($_SERVER["REQUEST_URI"] ?? null).'";';
    $row .= '"'.($ipinfo["result"]["hostname"] ?? null).'";';
    $row .= '"'.($ipinfo["result"]["country"] ?? null).'";';
    $row .= '"'.($ipinfo["result"]["region"] ?? null).'";';
    $row .= '"'.($ipinfo["result"]["postal"] ?? null).'";';
    $row .= '"'.($ipinfo["result"]["city"] ?? null).'";';
    $row .= '"'.($_SERVER["HTTP_USER_AGENT"] ?? null).'";';

    $row .= '"'.json_encode($_SERVER ?? null).'";';
    $row .= '"'.json_encode($_ENV ?? null).'";';
    $row .= '"'.json_encode($_GET ?? null).'";';
    $row .= '"'.json_encode($_POST ?? null).'";';
    $row .= '"'.json_encode($_COOKIE ?? null).'";';

    @file_put_contents("/var/log/honeypot.log1.csv", $row.PHP_EOL, FILE_APPEND);

    setcookie ("akhp", $_COOKIE["akhp"] ?? $set_cookie, time()+365*86400, "/", $_SERVER["HTTP_HOST"], false, false);
    sleep($wait_sec);
    
    switch ($_SERVER["REQUEST_URI"]) {
      case "/":
        die(file_get_contents(__DIR__."/assets/nginx_default.html"));
      case "/admin//config.php":
        self::add_ip_to_blacklist($remote_ip);
        die("a");
      case "/admin/config.php":
        self::add_ip_to_blacklist($remote_ip);
        die("b");
      case "/owa/":
        die(file_get_contents(__DIR__."/assets/owa_logon_aspx.html"));
    }
    
    //https://thephp.cc/neuigkeiten/2020/02/phpunit-ein-sicherheitsrisiko
    if (substr($_SERVER["REQUEST_URI"],-14,14) == "eval-stdin.php") {
      self::add_ip_to_blacklist($remote_ip);
      die("root@localhost:~# ".PHP_EOL);
    }
    
    if (substr($_SERVER["REQUEST_URI"],-5,5) == "/RPC2") {
      die("ready...".PHP_EOL);
    }
    
    if (substr($_SERVER["REQUEST_URI"],-12,12) == "swagger.json") {
      header("Content-Type: application/json");
      die(file_get_contents(__DIR__."/assets/swagger.json"));
    }
    
    if (substr($_SERVER["REQUEST_URI"],-5,5) == "/.env") {
      self::add_ip_to_blacklist($remote_ip);
      header('Content-Type: text/plain');
      echo('S3_BUCKET="superbucket"'.PHP_EOL);
      echo('SECRET_KEY="abc123"'.PHP_EOL);
      exit;
    }
    
    if (strpos($_SERVER["REQUEST_URI"], "/owa/auth/logon.aspx") !== FALSE) {
      self::add_ip_to_blacklist($remote_ip);
      die(file_get_contents(__DIR__."/assets/owa_logon_aspx.html"));
    }
    
    if (preg_match("@^/aspnet_client/[A-Za-z0-9]+.aspx@", $_SERVER["REQUEST_URI"])) {
      self::add_ip_to_blacklist($remote_ip);
      die('<xml></xml>');
    }
    
    /* === no good response send 404 ===*/

    @file_put_contents("/var/log/honeypot.urls.404.log", "http://".$_SERVER["HTTP_HOST"].$_SERVER["REQUEST_URI"].PHP_EOL, FILE_APPEND);

    header($_SERVER["SERVER_PROTOCOL"]." 404 Not Found");
    exit;
  }
  
  public static function add_ip_to_blacklist($ip) {
    @file_put_contents("/var/log/honeypot.ip.blacklist.log", $ip.PHP_EOL, FILE_APPEND);
  }

}
