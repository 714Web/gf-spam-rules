<?php
// Test for sofw_gform_email_blacklist
if (!class_exists('GFSpamRules')) { class GFSpamRules { public static function get_plugin_settings($form = null) { return ['email_blacklist'=>'foo','email_blacklist_add'=>'bar']; } } }
if (!class_exists('GFCommon')) { class GFCommon { public static function log_debug($msg) {} } }
if (!function_exists('get_option')) { function get_option($key) { return ['foo']; } }
if (!function_exists('wp_remote_get')) { function wp_remote_get($url) { return []; } }
if (!function_exists('is_wp_error')) { function is_wp_error($resp) { return false; } }
if (!function_exists('wp_remote_retrieve_header')) { function wp_remote_retrieve_header($resp, $key) { return ''; } }
if (!function_exists('wp_remote_retrieve_body')) { function wp_remote_retrieve_body($resp) { return ''; } }
if (!function_exists('update_option')) { function update_option($k, $v) {} }
require_once __DIR__ . '/../inc/core-functions.php';
$core = new GFSpamRulesCoreFunctions();
$form = ['fields' => [new class { public $id = 1; public function is_administrative() { return false; } public function get_input_type() { return 'email'; } public function get_value_export($entry) { return $entry['1']??''; } }]];
$entry1 = ['1' => 'foo'];
$entry2 = ['1' => 'bar'];
$entry3 = ['1' => 'baz'];
$res1 = $core->sofw_gform_email_blacklist(false, $form, $entry1);
echo "Test 1 (foo): ".($res1 === true ? 'PASS' : 'FAIL')."\n";
$res2 = $core->sofw_gform_email_blacklist(false, $form, $entry2);
echo "Test 2 (bar): ".($res2 === true ? 'PASS' : 'FAIL')."\n";
$res3 = $core->sofw_gform_email_blacklist(false, $form, $entry3);
echo "Test 3 (baz): ".($res3 === false ? 'PASS' : 'FAIL')."\n";
