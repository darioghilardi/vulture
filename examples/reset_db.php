<?php
  require_once('config.php');
  switch ($_GET['source']):
    case 'xss_stored_01':
      mysql_query("TRUNCATE TABLE xss_stored_01;");
    break;
    case 'xss_stored_02':
      mysql_query("TRUNCATE TABLE xss_stored_02;");
    break;
    case 'csrf_01':
      mysql_query("TRUNCATE TABLE csrf_01;");
    break;
    case 'sql_injection_01':
      mysql_query("TRUNCATE TABLE sql_injection_01;");
      $query = "INSERT INTO sql_injection_01 (username, password) VALUES ('admin', 'logmein');";
      $result = mysql_query($query) or die(mysql_error());
    break;
    default:
    break;
   endswitch;
  header('Location: '.$_GET['source'].'.php');
?>