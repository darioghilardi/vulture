<?php 
  require_once('config.php');
?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<title>XSS Reflected #1 Example Page</title>
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
<?php
if (isset($_GET['submit'])) {
  if(!empty($_GET['name'])) {
    echo "<span style=\"color:red;\">Welcome ".$_GET['name']."</span>";
  }
  else {
    echo "<span style=\"color:red;\">All fields are required.</span>";
  }
}
else {
?>

<h2><a href="#">XSS Reflected #1</a></h2>
<div class="articles">
Add your name here and the system will give you a welcome message.<br /><br />
<span style="color: blue;font-weight:bold;">This form is vulnerable to XSS.</span><br />
<form action="xss_reflected_01.php" method="GET">
  <label for="formname">Insert your name:</label><br /><br />
  <input type="text" id="formname" name="name" /><br /><br />
  <input type="hidden" id="p" name="p" value="xss_3" /><br /><br />
  <input type="submit" name="submit" value="Submit" />
</form>
</div>
<?php
}
?>
</div>
</div>
<div style="clear: both;"> </div>

<div id="footer">
RIPS example pages.
</div>
</div>

</body>
</html>