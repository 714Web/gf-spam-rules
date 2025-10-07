<?php
// Test for sofw_gform_url_spam
if (!class_exists('GFSpamRules')) { class GFSpamRules { public static function get_plugin_setting($key) { return true; } } }
if (!class_exists('GFCommon')) { class GFCommon { public static function log_debug($msg) {} } }
require_once __DIR__ . '/../inc/core-functions.php';
$core = new GFSpamRulesCoreFunctions();

// Proper mock for field object
class MockField {
	public $id;
	private $value;
	public function __construct($id, $value) { $this->id = $id; $this->value = $value; }
	public function is_administrative() { return false; }
	public function get_input_type() { return 'text'; }
	public function get_value_export($entry) { return $this->value; }
}

$form = ['fields' => [new MockField(1, 'This is a test http://example.com')]];
$entry1 = ['1' => 'This is a test http://example.com'];
$res1 = $core->sofw_gform_url_spam(false, $form, $entry1);
echo "Test 1 (URL present): ".($res1 === true ? 'PASS' : 'FAIL')."\n";

$form = ['fields' => [new MockField(1, 'No url here')]];
$entry2 = ['1' => 'No url here'];
$res2 = $core->sofw_gform_url_spam(false, $form, $entry2);
echo "Test 2 (No URL): ".($res2 === false ? 'PASS' : 'FAIL')."\n";