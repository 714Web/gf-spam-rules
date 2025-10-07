// Mock GFCommon for logging
if (!class_exists('GFCommon')) {
    class GFCommon {
        public static function log_debug($msg) { /* echo "[DEBUG] $msg\n"; */ }
    }
}
<?php

// Mock base class if not present
if (!class_exists('GFSpamRules')) {
    class GFSpamRules {
        public static function get_plugin_setting($key) { return null; }
        public static function get_plugin_settings($form = null) { return []; }
    }
}
// Mock GFCommon for logging
if (!class_exists('GFCommon')) {
    class GFCommon {
        public static function log_debug($msg) { /* echo "[DEBUG] $msg\n"; */ }
    }
}

require_once __DIR__ . '/../inc/core-functions.php';

// Simulate WordPress functions if not present
if (!function_exists('get_transient')) {
    function get_transient($key) {
        return isset($GLOBALS['__transients'][$key]) ? $GLOBALS['__transients'][$key] : false;
    }
    function set_transient($key, $value, $expiration) {
        $GLOBALS['__transients'][$key] = $value;
        return true;
    }
}

// Helper to clear transients for test IP
function clear_test_transients($ip_key) {
    unset($GLOBALS['__transients']['gf_rate_limit_' . $ip_key]);
    unset($GLOBALS['__transients']['gf_rate_limit_lockout_' . $ip_key]);
}

// Setup test IP and sanitize for key
$test_ip = '192.0.2.123';
$ip_key = preg_replace('/[^a-zA-Z0-9\.]/', '_', $test_ip);
clear_test_transients($ip_key);

// Mock $_SERVER
$_SERVER['REMOTE_ADDR'] = $test_ip;
unset($_SERVER['HTTP_X_FORWARDED_FOR']);

// Create instance
$core = new GFSpamRulesCoreFunctions();

// Dummy form and entry
$form = ['id' => 1, 'fields' => []];
$entry = [];

// Simulate 4 submissions in quick succession
$results = [];
for ($i = 1; $i <= 4; $i++) {
    $result = $core->sofw_gform_rate_limit_submissions(false, $form, $entry);
    $results[] = $result ? 'SPAM' : 'OK';
}

// Simulate a 5th submission (should be locked out)
$result = $core->sofw_gform_rate_limit_submissions(false, $form, $entry);
$results[] = $result ? 'SPAM' : 'OK';

// Output results
foreach ($results as $idx => $res) {
    echo "Submission " . ($idx+1) . ": $res\n";
}

// Clean up
clear_test_transients($ip_key);
