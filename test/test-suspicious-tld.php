<?php
// Test script for suspicious_tld_protection
// Mock GFCommon for logging
if (!class_exists('GFCommon')) {
    class GFCommon {
        public static function log_debug($msg) { /* echo "[DEBUG] $msg\n"; */ }
    }
}
// Mock base class if not present
if (!class_exists('GFSpamRules')) {
    class GFSpamRules {
        public static function get_plugin_setting($key) { return true; } // Always enable for test
        public static function get_plugin_settings($form = null) { return []; }
    }
}
require_once __DIR__ . '/../inc/core-functions.php';

$core = new GFSpamRulesCoreFunctions();
$form = ['id' => 1, 'fields' => []];

$test_cases = [
    // Should be spam
    ['entry' => ['1' => 'Check this: http://example.ru'], 'expected' => true, 'desc' => 'RU TLD'],
    ['entry' => ['1' => 'Visit https://foo.xyz for more info'], 'expected' => true, 'desc' => 'XYZ TLD'],
    ['entry' => ['1' => 'http://badsite.top'], 'expected' => true, 'desc' => 'TOP TLD'],
    // Should NOT be spam
    ['entry' => ['1' => 'Check this: http://example.com'], 'expected' => false, 'desc' => 'COM TLD'],
    ['entry' => ['1' => 'Just a normal message'], 'expected' => false, 'desc' => 'No URL'],
    ['entry' => ['1' => 'https://mysite.org'], 'expected' => false, 'desc' => 'ORG TLD'],
];

foreach ($test_cases as $idx => $case) {
    $result = $core->suspicious_tld_protection(false, $form, $case['entry']);
    $pass = ($result === $case['expected']) ? 'PASS' : 'FAIL';
    echo "Test " . ($idx+1) . " ({$case['desc']}): $pass\n";
}
