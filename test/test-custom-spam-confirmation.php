<?php
// Test for custom_spam_confirmation
if (!class_exists('GFSpamRules')) { class GFSpamRules {} }
if (!function_exists('rgar')) { function rgar($arr, $key) { return isset($arr[$key]) ? $arr[$key] : null; } }
require_once __DIR__ . '/../inc/core-functions.php';
$core = new GFSpamRulesCoreFunctions();

$tests = [
    ['entry' => [], 'expected' => 'Your message has not been delivered because it was identified as spam.', 'desc' => 'Empty entry'],
    ['entry' => ['status' => 'spam'], 'expected' => 'Your message has not been delivered because it was identified as spam.', 'desc' => 'Spam status'],
    ['entry' => ['status' => 'active'], 'expected' => 'OK', 'desc' => 'Active status'],
];
foreach ($tests as $idx => $test) {
    $confirmation = 'OK';
    $result = $core->custom_spam_confirmation($confirmation, [], $test['entry']);
    $pass = ($result === $test['expected']) ? 'PASS' : 'FAIL';
    echo "Test ".($idx+1)." ({$test['desc']}): $pass\n";
}
