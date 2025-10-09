<?php
/**
 * Block an IP address in Cloudflare using the API (account-level IP Access Rule)
 *
 * @param string $ip The IP address to block
 * @param string $api_token Cloudflare API token (with Firewall Access Rules permissions)
 * @param string $account_id Cloudflare Account ID
 * @return bool|array True on success, array with error info on failure
 */
function block_ip_in_cloudflare($ip, $api_token, $account_id) {
    if (empty($ip) || empty($api_token) || empty($account_id)) {
        return array('error' => 'Missing required parameters');
    }
    $url = "https://api.cloudflare.com/client/v4/accounts/{$account_id}/firewall/access_rules/rules";
    $data = array(
        'mode' => 'block',
        'configuration' => array(
            'target' => 'ip',
            'value' => $ip,
        ),
        'notes' => 'Blocked by Gravity Forms Spam Rules plugin (rate limit)',
    );
    $headers = array(
        'Authorization: Bearer ' . $api_token,
        'Content-Type: application/json',
    );
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    $response = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $err = curl_error($ch);
    curl_close($ch);
    if ($err) {
        return array('error' => $err);
    }
    $result = json_decode($response, true);
    if ($http_code === 200 && isset($result['success']) && $result['success']) {
        return true;
    }
    return array('error' => $result);
}
