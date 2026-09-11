<?php
/**
 * Defensive Remediation: Context-Aware Output Encoding & CSP
 * CWE-79: Reflected Cross-Site Scripting Mitigation
 */

// Restrict script execution contexts via HTTP headers
header("Content-Security-Policy: default-src 'self'; script-src 'self';");
header("X-Content-Type-Options: nosniff");

if (!isset($_GET['name']) || trim($_GET['name']) === '') {
    $isEmpty = true;
} else {
    $name = trim($_GET['name']);

    // Context-Aware Output Encoding
    $safe_name = htmlspecialchars($name, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');

    echo '<pre>';
    echo 'Hello ' . $safe_name;
    echo '</pre>';
}
?>
