<?php
// Test for sofw_enforce_gravity_forms_anti_spam_honeypot
if (!class_exists('GFSpamRules')) { class GFSpamRules { } }
require_once __DIR__ . '/../inc/core-functions.php';

// Mock with setting enabled
$core = new class extends GFSpamRulesCoreFunctions {
	public function get_plugin_setting($key) { return true; }
};
$form = [];
$res = $core->sofw_enforce_gravity_forms_anti_spam_honeypot($form);
echo isset($res['enableHoneypot']) && $res['enableHoneypot'] ? "Test 1 (honeypot enabled): PASS\n" : "Test 1: FAIL\n";

// Mock with setting disabled
$core2 = new class extends GFSpamRulesCoreFunctions {
	public function get_plugin_setting($key) { return null; }
};
$res2 = $core2->sofw_enforce_gravity_forms_anti_spam_honeypot($form);
echo !isset($res2['enableHoneypot']) ? "Test 2 (honeypot not enabled): PASS\n" : "Test 2: FAIL\n";