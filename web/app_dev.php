<?php

// this check prevents access to debug front controllers that are deployed by accident to production servers.
// feel free to remove this, extend it, or make something more sophisticated.
$chk_arr = array(
	'192.168.6',
	'192.168.1',
	'127.0.0.1',
    '172.20.10',
);

foreach ($chk_arr as $chk) {
  if (!in_array(substr($_SERVER['REMOTE_ADDR'],0,strlen($chk)), $chk_arr))
  {
   	header('HTTP/1.0 403 Forbidden');
   	die('You are not allowed to access this file. Check '.basename(__FILE__).' for more information.');
  }
}

require_once __DIR__.'/../app/bootstrap.php.cache';
require_once __DIR__.'/../app/AppKernel.php';

use Symfony\Component\HttpFoundation\Request;

$kernel = new AppKernel('dev', true);
$kernel->loadClassCache();
$kernel->handle(Request::createFromGlobals())->send();
