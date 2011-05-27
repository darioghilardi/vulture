<?php

  // Change this parameters to make RIPS examples working.
  
  // Database location
  $host = "localhost";
  
  // Database name
  $db_name = "rips";
  
  // Database username
  $user = "ripsuser";
  
  // Database password
  $pass = "ripspassword";  

  // Execute the database connection
  $link = mysql_connect($host, $user, $pass);
  $selected = mysql_select_db($db_name);
  
  // Set encoding to utf8
  mysql_query("SET NAMES utf8");
?>
