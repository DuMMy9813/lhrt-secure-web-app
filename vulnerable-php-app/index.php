<?php
// index.php – Landing page
require_once 'config.php';
if (isset($_SESSION['user_id'])) {
    header('Location: dashboard.php');
    exit();
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Health Tracker</title>
<style>
  body { font-family: Arial, sans-serif; background:#f0f4f8; display:flex; justify-content:center; align-items:center; min-height:100vh; margin:0; }
  .hero { text-align:center; }
  h1 { color:#2d6a9f; font-size:2.5rem; }
  p  { color:#555; max-width:480px; line-height:1.6; }
  a.btn { display:inline-block; margin-top:1.5rem; padding:.7rem 2rem; background:#2d6a9f; color:#fff; border-radius:6px; text-decoration:none; font-size:1.1rem; }
  a.btn:hover { background:#1e4f7a; }
</style>
</head>
<body>
<div class="hero">
  <h1>🏥 Health Tracker</h1>
  <p>A lightweight web application to log and monitor personal health records including weight, blood pressure, and heart rate.</p>
  <a class="btn" href="login.php">Login to Your Account</a>
</div>
</body>
</html>
