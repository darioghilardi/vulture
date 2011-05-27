<?php 
  require_once('config.php');
?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<title>XSS Stored #1 Example Page</title>
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
function extract_from_db($table, $order) {
  $query = "SELECT * FROM ".$table." ORDER BY '".$order." DESC';";
  $result = mysql_query($query) or die(mysql_error());
  while($row = mysql_fetch_array($result)) {
    $array[] = array(
      'title' => $row['title'],
      'message' => $row['message'],
      'date' => $row['date'],
      );
  }
  return $array;
}

if (isset($_POST['submit'])) {
  if((!empty($_POST['title'])) && (!empty($_POST['message']))) {
    $_POST['title'] = addslashes($_POST['title']);
    $_POST['message'] = addslashes($_POST['message']);
    $query = "INSERT INTO xss_stored_01 (title, message, date) VALUES ('".$_POST['title']."', '".$_POST['message']."', '".date('Y-m-d H:i:s')."');";
    if (!mysql_query($query,$link)) {
      die('Error: ' . mysql_error());
    }
  echo "<span style=\"color:red;\">Message added!</span>";
  }
  else {
    echo "<span style=\"color:red;\">All fields are required.</span>";
  }
}
?>

<div class="rightal"><a href="reset_db.php?source=xss_stored_01" title="Reset Database">Reset Database</a></div>
<h2><a href="#">XSS Stored #1</a></h2>
<div class="articles">
This is a message board. Add your message inside the form below. <br /><br />
<span style="color: blue;font-weight:bold;">This form is vulnerable to XSS. <br />
  The addslashes() function is used while extracting.</span>
<form action="xss_stored_01.php" method="POST">
  <label for="formtitle">Title</label><br />
  <input type="text" id="formtitle" name="title" /><br />
  <label for="formtitle">Message</label><br />
  <textarea id="formmessage" name="message"></textarea><br />
  <input type="submit" name="submit" value="Submit" />
</form>
<table class="messageboard">
  <tr>
    <td style="color:red;font-weight:bold;">Title</td>
    <td style="color:red;font-weight:bold;">Message</td>
    <td style="color:red;font-weight:bold;">Date</td>
  </tr>
  <?php
  $values = extract_from_db('xss_stored_01', 'date');
  if (!empty($values)) {
    foreach($values as $row) {
      echo "<tr>";
      echo "<td>".$row['title']."</td>";
      echo "<td>".$row['message']."</td>";
      echo "<td>".$row['date']."</td>";
      echo "</tr>";
    }
  echo "</table>";
  }
  else {
    echo "</table>";
    echo "No messages!";
  }
  ?>
  </table>
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