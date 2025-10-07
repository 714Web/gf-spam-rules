<?php
// Test for sofw_gform_sql_xss_protection
if (!class_exists('GFSpamRules')) { class GFSpamRules { public static function get_plugin_setting($key) { return true; } } }
if (!class_exists('GFCommon')) { class GFCommon { public static function log_debug($msg) {} } }
require_once __DIR__ . '/../inc/core-functions.php';
$core = new GFSpamRulesCoreFunctions();
$form = ['id' => 1];
$tests = [
    ['entry' => ['1' => 'SELECT * FROM users'], 'expected' => true, 'desc' => 'SQLi'],
    ['entry' => ['1' => '<script>alert(1)</script>'], 'expected' => true, 'desc' => 'XSS'],
    ['entry' => ['1' => 'ls -la'], 'expected' => true, 'desc' => 'Command'],
    ['entry' => ['1' => 'Normal text'], 'expected' => false, 'desc' => 'Clean'],
];
foreach ($tests as $idx => $test) {
    $result = $core->sofw_gform_sql_xss_protection(false, $form, $test['entry']);
    $pass = ($result === $test['expected']) ? 'PASS' : 'FAIL';
    echo "Test ".($idx+1)." ({$test['desc']}): $pass\n";
}
