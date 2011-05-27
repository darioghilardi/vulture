<?php 
  require_once('config.php');
?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<title>XSS Reflected #3 Example Page</title>
<meta http-equiv="Content-Language" content="English" />
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<link rel="stylesheet" type="text/css" href="style.css" media="screen" />
</head>
<body>

<div id="wrap">

<div id="header">
<h1>Rips Example Pages</h1>
</div>

<div id="content">
  
<div class="left">
  <?php require_once('menu.php');?>
</div>

<div class="right">
<h2><a href="#">XSS Reflected #3</a></h2>
<div class="articles">
Here is a lot of informations about you!<br /><br />

<span style="color: blue;font-weight:bold;">This form is vulnerable to XSS.<br />
The User Agent can be used to make the exploit.</span><br /><br />

IP Address: <?php echo $_SERVER['REMOTE_ADDR']; ?><br />
Browser: <?php echo $_SERVER['HTTP_USER_AGENT']; ?><br />

</div>
</div>
</div>
<div style="clear: both;"> </div>

<div id="footer">
RIPS example pages.
</div>
</div>

</body>
</html>