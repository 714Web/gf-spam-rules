<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! function_exists( 'block_ip_in_cloudflare' ) ) {
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

	    // A hung Cloudflare API call would otherwise block the visitor's own
	    // form submission (this runs synchronously during gform_entry_is_spam).
	    $response = wp_remote_post( $url, array(
	        'timeout' => 5,
	        'headers' => array(
	            'Authorization' => 'Bearer ' . $api_token,
	            'Content-Type'  => 'application/json',
	        ),
	        'body' => wp_json_encode( $data ),
	    ) );

	    if ( is_wp_error( $response ) ) {
	        return array( 'error' => $response->get_error_message() );
	    }

	    $http_code = wp_remote_retrieve_response_code( $response );
	    $result = json_decode( wp_remote_retrieve_body( $response ), true );

	    if ( $http_code === 200 && isset($result['success']) && $result['success'] ) {
	        return true;
	    }
	    return array( 'error' => isset( $result['errors'] ) ? $result['errors'] : 'Unknown error (HTTP ' . $http_code . ')' );
	}
}
