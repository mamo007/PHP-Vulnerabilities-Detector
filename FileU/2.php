<?php
$file = $_FILES['wpshop_file'];
$tmp_name = $file['tmp_name'];
$name = $file["name"];
move_uploaded_file($tmp_name, WPSHOP_UPLOAD_DIR.$name);
?>
