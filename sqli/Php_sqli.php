<?php
$id=$_GET['id'];
$query="select * from users where id='".$id."'";
mysqli_query($conn,$query);
?>
