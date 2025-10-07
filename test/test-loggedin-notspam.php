<?php
// Test for sofw_gform_loggedin_notspam
if (!class_exists('GFSpamRules')) { class GFSpamRules { public static function get_plugin_setting($key) { return true; } } }
if (!class_exists('GFCommon')) { class GFCommon { public static function log_debug($msg) {} } }
if (!function_exists('is_user_logged_in')) { function is_user_logged_in() { return true; } }
require_once __DIR__ . '/../inc/core-functions.php';
$core = new GFSpamRulesCoreFunctions();

// Test when user is logged in and setting enabled
$res = $core->sofw_gform_loggedin_notspam(true, [], []);
echo "Test 1 (already spam, logged in): ".($res === false ? 'PASS' : 'FAIL')."\n";
$res = $core->sofw_gform_loggedin_notspam(false, [], []);
echo "Test 2 (not spam, logged in): ".($res === false ? 'PASS' : 'FAIL')."\n";
// Test when setting is empty
class GFSpamRules2 extends GFSpamRules { public static function get_plugin_setting($key) { return null; } }
$core2 = new class extends GFSpamRulesCoreFunctions { public static function get_plugin_setting($key) { return null; } };
$res = $core2->sofw_gform_loggedin_notspam(false, [], []);
echo "Test 3 (setting empty): ".($res === false ? 'PASS' : 'FAIL')."\n";