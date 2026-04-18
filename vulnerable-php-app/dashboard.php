<?php
// dashboard.php — VULNERABLE dashboard
// VULNERABILITIES:
//   1. IDOR: ?view_user=<id> lets any authenticated user see any other user's records
//   2. SQL Injection: record_date, notes, etc. concatenated without escaping
//   3. XSS: notes and blood_pressure reflected without htmlspecialchars
//   4. No CSRF protection on add/delete forms
//   5. Mass assignment: all POST fields accepted without whitelist

require_once 'config.php';

if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit();
}

$current_user_id = $_SESSION['user_id'];

// VULNERABLE: IDOR – attacker can pass any user_id in the query string
$view_user_id = isset($_GET['view_user']) ? (int)$_GET['view_user'] : $current_user_id;

// ---- Handle ADD record ----
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'add') {
    $date  = $_POST['record_date'];        // VULNERABLE: no validation
    $wt    = $_POST['weight_kg'];
    $bp    = $_POST['blood_pressure'];
    $hr    = $_POST['heart_rate'];
    $notes = $_POST['notes'];

    // VULNERABLE: SQL injection via any of these fields
    $sql = "INSERT INTO health_records (user_id, record_date, weight_kg, blood_pressure, heart_rate, notes)
            VALUES ($current_user_id, '$date', '$wt', '$bp', '$hr', '$notes')";
    mysqli_query($conn, $sql);
    header('Location: dashboard.php');
    exit();
}

// ---- Handle DELETE record ----
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'delete') {
    $record_id = $_POST['record_id'];
    // VULNERABLE: no ownership check – any user can delete any record by id
    $sql = "DELETE FROM health_records WHERE id = $record_id";
    mysqli_query($conn, $sql);
    header('Location: dashboard.php');
    exit();
}

// ---- Fetch records ----
// VULNERABLE: $view_user_id from GET but no authorisation check
$sql     = "SELECT * FROM health_records WHERE user_id = $view_user_id ORDER BY record_date DESC";
$result  = mysqli_query($conn, $sql);
$records = [];
while ($row = mysqli_fetch_assoc($result)) {
    $records[] = $row;
}

// Fetch all users for admin-style dropdown (exposed to all authenticated users)
$users_result = mysqli_query($conn, "SELECT id, username, full_name FROM users");
$users = [];
while ($u = mysqli_fetch_assoc($users_result)) {
    $users[] = $u;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Health Tracker – Dashboard</title>
<style>
  * { box-sizing: border-box; }
  body { font-family: Arial, sans-serif; background:#f0f4f8; margin:0; }
  nav  { background:#2d6a9f; color:#fff; padding:.8rem 1.5rem; display:flex; justify-content:space-between; align-items:center; }
  nav a { color:#fff; text-decoration:none; margin-left:1rem; }
  .container { max-width:960px; margin:2rem auto; padding:0 1rem; }
  .card { background:#fff; padding:1.5rem; border-radius:8px; box-shadow:0 2px 8px rgba(0,0,0,.1); margin-bottom:1.5rem; }
  h3 { margin-top:0; color:#2d6a9f; }
  table { width:100%; border-collapse:collapse; }
  th, td { text-align:left; padding:.5rem .75rem; border-bottom:1px solid #e2e8f0; }
  th { background:#f7fafc; font-weight:600; }
  input, textarea, select { width:100%; padding:.4rem; border:1px solid #ccc; border-radius:4px; margin-bottom:.8rem; }
  .btn { padding:.4rem .8rem; border:none; border-radius:4px; cursor:pointer; color:#fff; }
  .btn-add { background:#38a169; }
  .btn-del { background:#e53e3e; font-size:.8rem; }
  .warning { background:#fff3cd; padding:.5rem 1rem; border-radius:4px; border-left:4px solid #f6c23e; font-size:.85rem; }
</style>
</head>
<body>
<nav>
  <span>🏥 Health Tracker</span>
  <div>
    Welcome, <?= $_SESSION['full_name'] /* VULNERABLE: XSS if full_name contains HTML */ ?>
    <a href="logout.php">Logout</a>
  </div>
</nav>

<div class="container">

  <!-- VULNERABLE: any user can view any other user's records via this form -->
  <div class="card">
    <h3>View User Records (Admin Debug)</h3>
    <p class="warning">⚠️ VULNERABILITY: No access control – any user can view any other user's records.</p>
    <form method="GET">
      <select name="view_user" onchange="this.form.submit()">
        <?php foreach ($users as $u): ?>
          <option value="<?= $u['id'] ?>" <?= $u['id'] == $view_user_id ? 'selected' : '' ?>>
            <?= $u['full_name'] ?> (<?= $u['username'] ?>)
          </option>
        <?php endforeach; ?>
      </select>
    </form>
  </div>

  <!-- Add Record Form -->
  <div class="card">
    <h3>Add Health Record</h3>
    <form method="POST">
      <input type="hidden" name="action" value="add">
      <label>Date</label>
      <input type="date" name="record_date" required>
      <label>Weight (kg)</label>
      <input type="number" step="0.1" name="weight_kg">
      <label>Blood Pressure (e.g. 120/80)</label>
      <input type="text" name="blood_pressure">
      <label>Heart Rate (bpm)</label>
      <input type="number" name="heart_rate">
      <label>Notes</label>
      <!-- VULNERABLE: notes rendered without escaping below → stored XSS -->
      <textarea name="notes" rows="2"></textarea>
      <button type="submit" class="btn btn-add">Add Record</button>
    </form>
  </div>

  <!-- Records Table -->
  <div class="card">
    <h3>Health Records</h3>
    <?php if (empty($records)): ?>
      <p>No records found.</p>
    <?php else: ?>
    <table>
      <tr><th>Date</th><th>Weight (kg)</th><th>Blood Pressure</th><th>Heart Rate</th><th>Notes</th><th>Action</th></tr>
      <?php foreach ($records as $r): ?>
      <tr>
        <td><?= $r['record_date'] ?></td>
        <td><?= $r['weight_kg'] ?></td>
        <!-- VULNERABLE: blood_pressure and notes rendered without htmlspecialchars → XSS -->
        <td><?= $r['blood_pressure'] ?></td>
        <td><?= $r['heart_rate'] ?></td>
        <td><?= $r['notes'] ?></td>
        <td>
          <form method="POST" style="margin:0">
            <input type="hidden" name="action"    value="delete">
            <!-- VULNERABLE: no ownership check on delete -->
            <input type="hidden" name="record_id" value="<?= $r['id'] ?>">
            <button class="btn btn-del">Delete</button>
          </form>
        </td>
      </tr>
      <?php endforeach; ?>
    </table>
    <?php endif; ?>
  </div>

</div>
</body>
</html>
