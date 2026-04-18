<?php
// login.php — VULNERABLE login page
// VULNERABILITIES:
//   1. SQL Injection: user input concatenated directly into query
//   2. Plain MD5 password hashing (no salt, broken hash)
//   3. No CSRF token
//   4. Session ID not regenerated after login (session fixation)
//   5. XSS: $error reflected without escaping

require_once 'config.php';

$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'];          // VULNERABLE: no sanitisation
    $password = $_POST['password'];

    $hashed = md5($password);               // VULNERABLE: MD5, no salt

    // VULNERABLE: direct string interpolation → SQL injection
    // Example exploit: username = ' OR '1'='1' --
    $query = "SELECT * FROM users WHERE username = '$username' AND password = '$hashed'";
    $result = mysqli_query($conn, $query);

    if ($result && mysqli_num_rows($result) > 0) {
        $user = mysqli_fetch_assoc($result);
        // VULNERABLE: session fixation – session ID never regenerated
        $_SESSION['user_id']   = $user['id'];
        $_SESSION['username']  = $user['username'];
        $_SESSION['full_name'] = $user['full_name'];
        header('Location: dashboard.php');
        exit();
    } else {
        // VULNERABLE: reflects $username back without HTML-encoding → stored/reflected XSS
        $error = "Invalid credentials for user: $username";
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Health Tracker – Login</title>
<style>
  body { font-family: Arial, sans-serif; background: #f0f4f8; display:flex; justify-content:center; align-items:center; min-height:100vh; margin:0; }
  .card { background:#fff; padding:2rem; border-radius:8px; box-shadow:0 2px 12px rgba(0,0,0,.12); width:340px; }
  h2 { margin-top:0; color:#2d6a9f; }
  input { width:100%; padding:.5rem; margin:.4rem 0 1rem; border:1px solid #ccc; border-radius:4px; box-sizing:border-box; }
  button { width:100%; padding:.6rem; background:#2d6a9f; color:#fff; border:none; border-radius:4px; cursor:pointer; font-size:1rem; }
  button:hover { background:#1e4f7a; }
  .error { background:#ffe0e0; color:#c00; padding:.5rem; border-radius:4px; margin-bottom:1rem; }
  a { color:#2d6a9f; }
</style>
</head>
<body>
<div class="card">
  <h2>🏥 Health Tracker</h2>
  <p style="color:#666;font-size:.9rem;">Lightweight Health Record System</p>

  <?php if ($error): ?>
    <!-- VULNERABLE: $error contains unsanitised user input – XSS vector -->
    <div class="error"><?= $error ?></div>
  <?php endif; ?>

  <form method="POST" action="login.php">
    <label>Username</label>
    <input type="text"     name="username" placeholder="Enter username" required>
    <label>Password</label>
    <input type="password" name="password" placeholder="Enter password" required>
    <button type="submit">Login</button>
  </form>
  <p style="text-align:center;margin-top:1rem;"><a href="index.php">← Back to Home</a></p>
</div>
</body>
</html>
