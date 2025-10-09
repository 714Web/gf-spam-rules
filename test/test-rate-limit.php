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



// Cloudflare test credentials (replace with real/test values as needed)

$cloudflare_api_token = getenv('CF_API_TOKEN') ?: 'L9zn-tIvsMSE2yyNgl1dFUd-u7DS1FXBffd_NaLO';
$cloudflare_account_id = getenv('CF_ACCOUNT_ID') ?: 'ebcff93a5149b6d37aa799ea12c661e0';


$results = [];
$blocked = false;
// Only mock if using test token or test account id
$mock_mode = ($cloudflare_api_token === 'test_api_token' || $cloudflare_account_id === 'test_account_id');
for ($i = 1; $i <= 5; $i++) {
    $result = $core->sofw_gform_rate_limit_submissions(false, $form, $entry);
    if ($result && !$blocked) {
        // Only block once for the first SPAM
        $blocked = true;
        echo "Submission $i: SPAM (triggering Cloudflare block)\n";
        if ($mock_mode) {
            echo "[Cloudflare API Debug] MOCK MODE: Simulating success for IP $test_ip\n";
            $cf_result = true;
        } else {
            require_once __DIR__ . '/../inc/block-ip-cloudflare.php';
            $cf_result = block_ip_in_cloudflare($test_ip, $cloudflare_api_token, $cloudflare_account_id);
        }
        echo "Cloudflare block_ip_in_cloudflare() result: ";
        var_dump($cf_result);
    } else {
        echo "Submission $i: " . ($result ? 'SPAM' : 'OK') . "\n";
    }
}

// Clean up
clear_test_transients($ip_key);
