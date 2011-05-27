<?php 
  require_once('dbconnection.php');
  require_once('page_manager.php');
?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<title>Security4Donkeys</title>
<meta http-equiv="Content-Language" content="English" />
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<link rel="stylesheet" type="text/css" href="style.css" media="screen" />
</head>
<body>

<div id="wrap">

<div id="header">
<h1><a href="index.php">Security4Donkeys</a></h1>
<h2>Security stuff for security donkeys.</h2>
</div>

<div id="content">
<div class="left">

<h2>Lessons :</h2>
<ul>
<li><a href="index.php?p=xss_1">XSS Stored #1</a></li>
<li><a href="index.php?p=xss_2">XSS Stored #2</a></li>
<li><a href="index.php?p=xss_3">XSS Reflected #1</a></li>
<li><a href="index.php?p=xss_4">XSS Reflected #2</a></li>
<li><a href="index.php?p=xss_5">XSS Reflected #3</a></li>
<li><a href="index.php?p=sqlinjection_1">Sql injection #1</a></li>
<li><a href="index.php?p=sqlinjection_2">Sql Injection #2</a></li>
<li><a href="index.php?p=csrf">Csrf</a></li>
<li><a href="index.php?p=codequality">Code Quality</a></li>
<li><a href="index.php?p=maliciousfileexecution">Malicious file execution</a></li>
<li><a href="index.php?p=failuretorestricturlaccess">Failure to restrict URL access</a></li>
</ul>

</div>

<div class="right">
<?php include($included); ?>
</div>
</div>
<div style="clear: both;"> </div>

<div id="footer">
Security4Donkeys are Dario Ghilardi, Stefano Locatelli, Davide Marcassoli - v. 0.1 - Released under GPL 2009.
</div>
</div>

</body>
</html>