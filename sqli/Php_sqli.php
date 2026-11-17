<?php
$id=$_GET['id'];
$query="select * from users where id='".$id."'";
mysqli_query($conn,$query);

mysqli_query($conn, "SELECT * FROM users WHERE id = ".$id)

$conn->query("SELECT * FROM users WHERE id = $id")

pg_query("SELECT * FROM users WHERE id = ".$id)

$pdo->_query("SELECT * FROM users WHERE id = ".$id)

$pdo->_exec("DELETE * FROM users WHERE id = ".$id)

$pdo->_prepare("SELECT * FROM users WHERE id = ".$id).execute()
?>
