<?php
/**
 * Defensive Remediation: Strict Validation & Argument Escaping
 * CWE-78: OS Command Injection Mitigation
 */

if (isset($_POST['Submit'])) {
    $target = trim($_POST['ip']);

    // 1. Strict Whitelist Validation: Enforce RFC-compliant IP address syntax
    if (filter_var($target, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_IPV6)) {
        
        // 2. Argument Escaping: Neutralize any residual shell metacharacters
        $safe_target = escapeshellarg($target);

        if (stristr(php_uname('s'), 'Windows NT')) {
            $cmd = shell_exec('ping ' . $safe_target);
        } else {
            $cmd = shell_exec('ping -c 3 ' . $safe_target);
        }

        echo '<pre>' . htmlspecialchars($cmd, ENT_QUOTES, 'UTF-8') . '</pre>';
    } else {
        echo '<pre>Error: Invalid IP address format. Domain names and shell characters are rejected.</pre>';
    }
}
?>
