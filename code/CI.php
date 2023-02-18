<?php
$p = $_GET[‘p’];
$e= exec(‘cat ‘.$p);
echo $e;
?>
