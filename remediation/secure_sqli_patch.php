<?php
/**
 * Defensive Remediation: Parameterized Prepared Statements
 * CWE-89: SQL Injection Mitigation
 */

$dsn = 'mysql:host=localhost;dbname=dvwa;charset=utf8mb4';
$dbUser = 'dvwa';
$dbPass = 'password';

try {
    $pdo = new PDO($dsn, $dbUser, $dbPass, [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES   => false, // Enforce native prepared statements
    ]);
} catch (PDOException $e) {
    exit('Database connection failed.');
}

// 1. Strict input validation
$id = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT);

if ($id === false || $id === null) {
    exit('Invalid input: User ID must be an integer.');
}

// 2. Prepared statement ensures user data is never parsed as SQL syntax
$stmt = $pdo->prepare('SELECT first_name, last_name FROM users WHERE user_id = :id');
$stmt->execute([':id' => $id]);
$records = $stmt->fetchAll();

// 3. Context-aware output encoding to prevent secondary XSS
foreach ($records as $user) {
    echo htmlspecialchars($user['first_name'], ENT_QUOTES, 'UTF-8') . ' ' .
         htmlspecialchars($user['last_name'], ENT_QUOTES, 'UTF-8') . '<br />';
}
?>
