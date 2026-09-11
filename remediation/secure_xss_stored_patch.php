<?php
/**
 * Defensive Remediation: Input Sanitization & Context-Aware Output Encoding
 * CWE-79: Stored Cross-Site Scripting Mitigation
 */

header("Content-Security-Policy: default-src 'self'; script-src 'self';");
header("X-Content-Type-Options: nosniff");

if (isset($_POST['btnSign'])) {
    $name = trim($_POST['txtName']);
    $message = trim($_POST['mtxMessage']);

    // Layer 1: Input Sanitization
    $clean_name = strip_tags($name);

    // Layer 2: Prepared Statements for Safe Database Storage
    $stmt = $pdo->prepare("INSERT INTO guestbook (comment, name) VALUES (:comment, :name)");
    $stmt->execute([
        ':comment' => $message,
        ':name'    => $clean_name
    ]);
}

// Layer 3: Context-Aware Output Encoding (Executed at HTML Render Time)
function renderGuestbookEntry($comment, $author) {
    $safe_comment = htmlspecialchars($comment, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $safe_author  = htmlspecialchars($author, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');

    echo "<div class='guestbook-entry'>";
    echo "<p><strong>Author:</strong> " . $safe_author . "</p>";
    echo "<p>" . nl2br($safe_comment) . "</p>";
    echo "</div>";
}
?>
