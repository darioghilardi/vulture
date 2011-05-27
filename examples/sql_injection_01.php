<?php 
  require_once('config.php');
?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<title>SQL Injection #1 Example Page</title>
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
if (isset($_POST['submit'])) {
  if((!empty($_POST['username'])) && (!empty($_POST['password']))) {
    $query = "SELECT count(*) FROM sql_injection_01 WHERE username='".$_POST['username']."' AND password='".$_POST['password']."';";
    $result = mysql_query($query) or die(mysql_error());
    $row = mysql_fetch_row($result);
     if (!empty($row[0])) {
       echo "Welcome!";
     }
     else {
       echo "<span style=\"color:red;\">User not recognized.</span>";
     }
  }
  else {
    echo "<span style=\"color:red;\">All fields are required.</span>";
  }
}
else {
?>

<div class="rightal"><a href="reset_db.php?source=sql_injection_01" title="Reset Database">Reset Database</a></div>
<h2><a href="#">SQL Injection #1</a></h2>
<div class="articles">
This is a message board. Add your message inside the form below. <br /><br />
<span style="color: blue;font-weight:bold;">This form is vulnerable to SQL Injection attacks.</span>
<form action="sql_injection_01" method="POST">
  <label for="formtitle">Username</label><br />
  <input type="text" id="formusername" name="username" /><br />
  <label for="formtitle">Password</label><br />
  <input type="password" id="formpassword" name="password" /><br />
  <input type="submit" name="submit" value="Login" />
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
