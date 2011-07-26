<?php

// this check prevents access to debug front controllers that are deployed by accident to production servers.
// feel free to remove this, extend it, or make something more sophisticated.
$checklist = array(
	array('192','168','6'),
	array('192','168','1'),
	array('127','0','0'),
    array('172','20','1'),
    array('192','168','4'),
    array('192','168','43'),
);

$server = array_slice(explode('.', $_SERVER['REMOTE_ADDR']), 0, 3);

if (!in_array($server, $checklist))
{
   	header('HTTP/1.0 403 Forbidden');
   	die('You are not allowed to access this file. Check '.basename(__FILE__).' for more information.');
}

require_once __DIR__.'/../app/bootstrap.php.cache';
require_once __DIR__.'/../app/AppKernel.php';

use Symfony\Component\HttpFoundation\Request;

$kernel = new AppKernel('dev', true);
$kernel->loadClassCache();
$kernel->handle(Request::createFromGlobals())->send();
