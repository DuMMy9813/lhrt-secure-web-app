<?php
// config.php — Database connection for the VULNERABLE PHP application
// VULNERABILITY: Credentials hardcoded in source; no environment separation

define('DB_HOST', 'localhost');
define('DB_USER', 'root');
define('DB_PASS', 'root');          // VULNERABLE: hardcoded credential
define('DB_NAME', 'health_tracker');

// VULNERABLE: error reporting exposes internals to the browser
error_reporting(E_ALL);
ini_set('display_errors', 1);

$conn = mysqli_connect(DB_HOST, DB_USER, DB_PASS, DB_NAME);

if (!$conn) {
    // VULNERABLE: exposes raw DB error to the user
    die("Connection failed: " . mysqli_connect_error());
}

// Session started here so every page can call session_start() safely
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}
?>
