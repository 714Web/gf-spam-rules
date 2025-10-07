<?php
// Test for sofw_gform_name_spam
if (!class_exists('GFSpamRules')) { class GFSpamRules { public static function get_plugin_settings($form = null) { return ['name_blacklist'=>'foo','name_blacklist_add'=>'bar']; } } }
if (!class_exists('GFCommon')) { class GFCommon { public static function log_debug($msg) {} } }
if (!function_exists('rgar')) { function rgar($arr, $key) { return isset($arr[$key]) ? $arr[$key] : ''; } }
require_once __DIR__ . '/../inc/core-functions.php';
$core = new GFSpamRulesCoreFunctions();
$form = ['fields' => [new class {
	public $id = 1;
	public function is_administrative() { return false; }
	public function get_input_type() { return 'name'; }
	public function get_value_export($entry) {
		return ($entry['1.3'] ?? '') . ($entry['1.6'] ?? '');
	}
}]];
$entry1 = ['1.3' => 'foo', '1.6' => 'bar']; // blacklisted
$entry2 = ['1.3' => 'zbyszko', '1.6' => 'krystl']; // whitelisted
$entry3 = ['1.3' => 'normal', '1.6' => 'name']; // clean
$entry4 = ['1.3' => 'longname', '1.6' => 'xqwrtyps']; // too few vowels, not whitelisted


$res1 = $core->sofw_gform_name_spam(false, $form, $entry1);
echo "Test 1 (blacklisted): ".($res1 === true ? 'PASS' : 'FAIL')."\n";
$res2 = $core->sofw_gform_name_spam(false, $form, $entry2);
echo "Test 2 (whitelisted): ".($res2 === false ? 'PASS' : 'FAIL')."\n";
$res3 = $core->sofw_gform_name_spam(false, $form, $entry3);
echo "Test 3 (clean): ".($res3 === false ? 'PASS' : 'FAIL')."\n";
$res4 = $core->sofw_gform_name_spam(false, $form, $entry4);
echo "Test 4 (few vowels): ".($res4 === true ? 'PASS' : 'FAIL')."\n";
