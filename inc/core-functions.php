<?php
/*
 *
 * Core Functions
 * 
 */

class GFSpamRulesCoreFunctions extends GFSpamRules {
    
    /**
     * Customizes the spam confirmation message for Gravity Forms.
     *
     * @param mixed $confirmation The original confirmation message.
     * @param array $form The Gravity Forms form array.
     * @param array $entry The Gravity Forms entry array.
     * @return string The spam message or the original confirmation.
     */
    public function custom_spam_confirmation( $confirmation, $form, $entry ) {
        if ( empty( $entry ) || rgar( $entry, 'status' ) === 'spam' ) {
            return 'Your message has not been delivered because it was identified as spam.';
        }

        return $confirmation;
    }


    /**
     * Always allow submissions from logged-in users, even if other filters mark as spam.
     * If the 'bypass_spam' setting is enabled and the user is logged in, override all spam checks.
     *
     * @param bool $is_spam Current spam status (may be true from other filters)
     * @param array $form Gravity Forms form array
     * @param array $entry Gravity Forms entry array
     * @return bool false (not spam) for logged-in users if setting enabled, otherwise original $is_spam
     */
    public function sofw_gform_loggedin_notspam( $is_spam, $form, $entry ) {
        $setting = parent::get_plugin_setting( 'bypass_spam' );

        if ( empty($setting) ) {
            GFCommon::log_debug( __METHOD__ . '(): Option not set.' );
            return $is_spam;
        }

        if ( !empty($setting) && is_user_logged_in() ) {
            GFCommon::log_debug( __METHOD__ . '(): Entry marked as not spam for logged-in user (bypass all spam checks).');
            return false; // Always allow logged-in users
        }

        return $is_spam;
    }
    
    
    /**
     * Flags submissions as spam if a URL is detected in text fields.
     *
     * @param bool $is_spam Current spam status
     * @param array $form Gravity Forms form array
     * @param array $entry Gravity Forms entry array
     * @return bool True if spam detected, otherwise original $is_spam
     */
    public function sofw_gform_url_spam( $is_spam, $form, $entry ) {
        if ( $is_spam ) { return $is_spam; }

        $setting = parent::get_plugin_setting( 'url_spam' );

		if ( empty($setting) ) {
            GFCommon::log_debug( __METHOD__ . '(): Option not set.' );
            return $is_spam;
        }

        $field_types_to_check = array(
            'text',
            'textarea',
            'post_title',
        );

        foreach ( $form['fields'] as $field ) {
            // Skipping fields which are administrative or the wrong type.
            if ( $field->is_administrative() || ! in_array( $field->get_input_type(), $field_types_to_check ) ) {
                continue;
            }

            // Skipping fields which don't have a value.
            $value = $field->get_value_export( $entry );
            if ( empty( $value ) ) {
                continue;
            }

            // If value contains a URL mark submission as spam.
            GFCommon::log_debug( __METHOD__ . '(): Checking field id '.$field->id.'.' );
            if ( preg_match( '~(https?|ftp):\/\/\S+~', $value ) ) {
                GFCommon::log_debug( __METHOD__ . '(): Contains URL spam.' );
                return true;
            }
        }

        return $is_spam;
    }
    
    
    /**
     * Enforce Gravity Forms honeypot if the setting is enabled.
     * If the 'enforce_honeypot' setting is truthy, sets enableHoneypot on the form.
     *
     * @param array $form Gravity Forms form array
     * @return array Modified form array
     */
    public function sofw_enforce_gravity_forms_anti_spam_honeypot( $form ) {
        $setting = $this->get_plugin_setting( 'enforce_honeypot' );

        if ( empty( $setting ) ) {
            return $form;
        }
        
        $form['enableHoneypot'] = true;
        return $form;
    }


    /**
     * Provides SQL injection, XSS, and command injection protection for Gravity Forms entries.
     *
     * @param bool $is_spam Current spam status
     * @param array $form Gravity Forms form array
     * @param array $entry Gravity Forms entry array
     * @return bool True if spam detected, otherwise false
     */
    public function sofw_gform_sql_xss_protection( $is_spam, $form, $entry ) {
        // If already marked as spam by another filter, leave it
        if ( $is_spam ) { return $is_spam; }

        $setting = parent::get_plugin_setting( 'sql_xss_cmd_protection' );

		if ( empty($setting) ) {
            GFCommon::log_debug( __METHOD__ . '(): Option not set.' );
            return $is_spam;
        }

        // Suspicious pattern signatures (extended and deduped)
        $sql_injection_patterns = [
            // Classic SQLi
            '/\b(UNION\s+SELECT|SELECT\s+.*FROM|INSERT\s+INTO|UPDATE\s+.+SET|DELETE\s+FROM|DROP\s+TABLE|ALTER\s+TABLE|TRUNCATE\s+TABLE|CREATE\s+TABLE|INTO\s+OUTFILE|INTO\s+DUMPFILE|LOAD\s+DATA)\b/i',
            '/\b(OR|AND)\s*[\( ]*1\s*=\s*1[\) ]*/i',
            '/(;|--|#|\/\*|\*\/)+\s*(DROP|ALTER|TRUNCATE|EXEC|SLEEP|BENCHMARK|LOAD_FILE|OUTFILE|INTO|DUMPFILE)\b/i',
            '/\bINFORMATION_SCHEMA\b/i',
            '/\b(CONCAT|GROUP_CONCAT|HEX|UNHEX|CAST|CONVERT)\s*\(/i',
            '/\b(SELECT\s+.*@@|@@version|@@datadir|@@hostname)\b/i',
            '/\bWAITFOR\s+DELAY\b/i',
            // Hex encoded
            '/0x[0-9a-fA-F]+/i',
            // Stacked queries
            '/;\s*\w+\s*\(/i',
        ];

        $xss_patterns = [
            // Script and event handlers
            '/<\s*script\b[^>]*>|<\/\s*script\s*>/i',
            '/<\s*iframe\b[^>]*>|<\/\s*iframe\s*>/i',
            '/<\s*img\b[^>]*onerror\s*=\s*["\"][^"\']*["\"][^>]*>/i',
            '/<\s*a\b[^>]*href\s*=\s*["\']javascript:[^"\']*["\'][^>]*>/i',
            '/<\s*body\b[^>]*onload\s*=\s*["\"][^"\']*["\"][^>]*>/i',
            '/on[a-z]+\s*=\s*["\"][^"\']*["\"]/i', // any event handler
            // SVG, MathML, and other risky tags
            '/<\s*(div|span|p|form|input|textarea|button|select|option|link|meta|svg|math|embed|object|applet)[^>]*>/i',
            '/<\s*(iframe|embed|object|applet|link|meta|svg|math)[^>]*>/i',
            // srcdoc attribute
            '/srcdoc\s*=\s*["\"]/i',
            // style attribute with expression or url(javascript:)
            '/style\s*=\s*["\"][^"\']*(expression|url\(javascript:)[^"\']*["\"]/i',
            // data: with alert/prompt/eval
            '/data\s*:[^,]+,.*(alert|prompt|confirm|eval)\(/i',
            '/(javascript|vbscript|data):/i',
            // base64 blobs
            '/base64\s*,\s*[A-Za-z0-9\/\+=]{40,}/i',
            // Obfuscated JS
            '/\b(unescape|fromCharCode|String\\.fromCharCode)\b/i',
        ];

        $command_patterns = [
            // Command injection and shell tricks
            '/\b(ls|cat|whoami|uname|id|pwd|curl|wget|nc|netcat|bash|sh|php|perl|python|ruby|env|export)\b/i',
            '/\b(;|\||&&|\$\(.*\)|`.*`|\$\{[^}]+\})\b/i', // command chaining, shell vars
            '/(\b|\W)(system|exec|shell_exec|passthru|popen|proc_open)\s*\(/i',
            '/(\b|\W)(base64_decode|eval|assert|preg_replace\s*\(\s*["\'].*\/e["\'])/i',
            '/(\b|\W)(curl|wget|scp|ftp|file_get_contents|fopen|include|require)(_once)?\s*\(/i',
            // Encoded payloads
            '/base64\s*,\s*[A-Za-z0-9\/\+=]{40,}/i',
        ];

        $general_patterns = [
            // Long non-ASCII or repeated chars
            '/[\x80-\xFF]{4,}/',
            '/([a-zA-Z0-9])\1{10,}/',
            // Suspicious query params
            '/[?&](id|token|session|key)=/i',
        ];

        $patterns = array_merge(
            $sql_injection_patterns,
            $xss_patterns,
            $command_patterns,
            $general_patterns
        );

        foreach ( $entry as $field_id => $value ) {
            if ( ! is_string( $value ) ) continue;

            foreach ( $patterns as $regex ) {
                if ( preg_match( $regex, $value ) ) {

                    // Optional: log what was rejected for tuning/debugging
                    error_log( sprintf(
                        '[GF SPAM REJECTED] Form %d, Field %s matched %s. Value: %s',
                        $form['id'], $field_id, $regex, substr( $value, 0, 200 )
                    ));

                    // Hard reject: stop processing, don’t save entry
                    return true;
                }
            }
        }

        return false; // clean entry
    }


    /**
     * Flags entries as spam if they contain suspicious top-level domains (TLDs).
     *
     * @param bool $is_spam Current spam status
     * @param array $form Gravity Forms form array
     * @param array $entry Gravity Forms entry array
     * @return bool True if spam detected, otherwise false
     */
    public function suspicious_tld_protection( $is_spam, $form, $entry ) {
        // If already marked as spam by another filter, leave it
        if ( $is_spam ) { return $is_spam; }

        $setting = parent::get_plugin_setting( 'suspicious_tld_protection' );

		if ( empty($setting) ) {
            GFCommon::log_debug( __METHOD__ . '(): Option not set.' );
            return $is_spam;
        }

        $patterns = [
            // Suspicious TLDs
            '/https?:\/\/[^\s]+\.(ru|cn|tk|xyz|top|click|work|gq|ml|ga|icu|cf|pw|cc|in|bid|info|site|online|space|loan|win|men|stream|review|party|gdn|ninja|science|accountant|faith|date|download|racing|jetzt|wang|kim|red|blue|black|pink|green|gold|pro|rocks|lol|ooo|link|pics|photo|photos|today|trade|webcam|website|wiki|zip|zone)\b/i',
        ];

        foreach ( $entry as $field_id => $value ) {
            if ( ! is_string( $value ) ) continue;

            foreach ( $patterns as $regex ) {
                if ( preg_match( $regex, $value ) ) {

                    // Optional: log what was rejected for tuning/debugging
                    error_log( sprintf(
                        '[GF SPAM REJECTED] Form %d, Field %s matched %s. Value: %s',
                        $form['id'], $field_id, $regex, substr( $value, 0, 200 )
                    ));

                    // Hard reject: stop processing, don’t save entry
                    return true;
                }
            }
        }

        return false; // clean entry
    }


    /**
     * Rate-limits form submissions by IP address.
     *
     * @param bool $is_spam Current spam status
     * @param array $form Gravity Forms form array
     * @param array $entry Gravity Forms entry array
     * @return bool True if rate limit exceeded, otherwise false
     */
    public function sofw_gform_rate_limit_submissions( $is_spam, $form, $entry ) {
        // If already marked as spam by another filter, leave it
        if ( $is_spam ) { return $is_spam; }

        // Hard-coded rate limit: 3 submissions per 1 minute (60 seconds), 1 hour lockout
        $max_submissions = 3;
        $window_seconds = 60;
        $lockout_seconds = 3600;

        // Get IP address
        $ip = isset($_SERVER['HTTP_X_FORWARDED_FOR']) ? explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'])[0] : $_SERVER['REMOTE_ADDR'];
        $ip = trim($ip);
        if (empty($ip)) {
            GFCommon::log_debug( __METHOD__ . '(): Could not determine IP address.' );
            return $is_spam;
        }

        // Sanitize IP for use in transient key (replace non-alphanumeric and non-dot chars with _)
        $ip_key = preg_replace('/[^a-zA-Z0-9\.]/', '_', $ip);

        // Check for lockout
        $lockout_key = 'gf_rate_limit_lockout_' . $ip_key;
        if ( get_transient($lockout_key) ) {
            GFCommon::log_debug( __METHOD__ . "(): IP $ip is currently locked out due to previous rate limit violation." );
            return true; // mark as spam
        }

        // Use a transient to store timestamps for this IP
        $transient_key = 'gf_rate_limit_' . $ip_key;
        $timestamps = get_transient($transient_key);
        if (!is_array($timestamps)) {
            $timestamps = [];
        }

        // Remove timestamps outside the window
        $now = time();
        $timestamps = array_filter($timestamps, function($ts) use ($now, $window_seconds) {
            return ($ts > $now - $window_seconds);
        });

        // Add this submission
        $timestamps[] = $now;

        // Save back to transient
        set_transient($transient_key, $timestamps, $window_seconds);

        if (count($timestamps) > $max_submissions) {
            GFCommon::log_debug( __METHOD__ . "(): Rate limit exceeded for IP $ip. Locking out for $lockout_seconds seconds." );
            set_transient($lockout_key, 1, $lockout_seconds);
            return true; // mark as spam
        }

        return false; // clean entry
    }
    

    /**
     * Initiates remote blacklist updates when the Gravity Forms settings page is loaded.
     *
     * @param string $hook_suffix The current admin page hook suffix
     * @return void
     */
    public function maybe_initiate_remote_blacklists($hook_suffix) {
        if($hook_suffix !== 'forms_page_gf_settings') {
            return;
        }

        $content_blacklist = parent::get_plugin_setting( 'content_blacklist' );
        $email_blacklist = parent::get_plugin_setting( 'email_blacklist' );

        $url_components = $_SERVER['QUERY_STRING'];
        if ( empty($url_components) || !is_string($url_components) ) {
            return;
        }
        $params = explode( '&', $url_components );
        foreach ( $params as $k => $v ) {
            if ( $v == 'subview=gfspamrules' ) {
                if ( !empty($content_blacklist) ) $this->maybe_update_content_blacklist();
                if ( !empty($email_blacklist) ) $this->maybe_update_email_blacklist();
            }
        }
    }
    
    
    /**
     * Updates the local content blacklist from a remote source if needed.
     *
     * @return void
     */
    public function maybe_update_content_blacklist() {
        // Get comment blacklist
        $response = wp_remote_get(
            'https://raw.githubusercontent.com/splorp/wordpress-comment-blacklist/master/blacklist.txt'
        );
        if ( is_wp_error( $response ) ) {
            return;
        } else {
            GFCommon::log_debug( __METHOD__ . '(): Retrieved remote blacklist.' );
        }

        // Get the etag
        $remote_etag = wp_remote_retrieve_header( $response, 'etag' );
        $etag = preg_replace( '/^[a-f0-9"]$/', '', $remote_etag );

        // Compare etag to check for updated file
        if ( $etag == get_option('sofw_comment_blacklist_etag') && is_array( get_option( 'sofw_comment_blacklist') ) ) {
            GFCommon::log_debug( __METHOD__ . '(): Local blacklist is already up to date.' );
            return;
        }

        // If remote blacklist is new, update etag and save blacklist
        update_option( 'sofw_comment_blacklist_etag', $etag );

        $blacklist_body = wp_remote_retrieve_body( $response );
        $blacklist_content = explode( "\n", $blacklist_body );

        if ( is_array($blacklist_content) ) {
            update_option( 'sofw_comment_blacklist', $blacklist_content );
            GFCommon::log_debug( __METHOD__ . '(): Updated.' );
        }
    }
    
    
    /**
     * Flags entries as spam if they contain blacklisted content.
     *
     * @param bool $is_spam Current spam status
     * @param array $form Gravity Forms form array
     * @param array $entry Gravity Forms entry array
     * @return bool True if blacklisted content found, otherwise original $is_spam
     */
    public function sofw_gform_content_blacklist( $is_spam, $form, $entry ) {
        if ( $is_spam ) { return $is_spam; }

		$settings = parent::get_plugin_settings( $form );
        $content_blacklist = $settings['content_blacklist'];
        $content_blacklist_add = $settings['content_blacklist_add'];

		if ( empty($content_blacklist) ) {
            GFCommon::log_debug( __METHOD__ . '(): Option not set.' );
            return $is_spam;
        }
        
        $sofw_comment_blacklist = array();
        
        // Get remote blacklist
        GFCommon::log_debug( __METHOD__ . '(): Checking for remote blacklist updates.' );
        $this->maybe_update_content_blacklist();
        $sofw_comment_blacklist = get_option('sofw_comment_blacklist');
        
        // Get custom blacklist content w/o triggering error if db table !exist
        $custom_content = array();
        $blacklist_content = $sofw_comment_blacklist;

        if ( !empty($content_blacklist_add) ) {
            $custom_content = explode( "\r\n", $content_blacklist_add );
            
            if ( is_array( $sofw_comment_blacklist) && is_array( $custom_content) ) {
                $blacklist_content = array_merge( $sofw_comment_blacklist, $custom_content );
            }
        }
        
        if ( empty($blacklist_content) ) {
            GFCommon::log_debug( __METHOD__ . '(): No blacklist.' );
            return $is_spam;
        }
        
        $field_types_to_check = array(
            'hidden',
            'text',
            'textarea',
            'name',
            'post_title',
            'post_content',
            'post_excerpt',
            'post_tags',
            'post_category',
        );

        foreach ( $form['fields'] as $field ) {
            // Skipping fields which are administrative or the wrong type.
            if ( $field->is_administrative() || ! in_array( $field->get_input_type(), $field_types_to_check ) ) {
                continue;
            }

            // Skipping fields which don't have a value.
            $value = $field->get_value_export( $entry );
            if ( empty( $value ) ) {
                continue;
            }

            GFCommon::log_debug( __METHOD__ . '(): Checking field id '.$field->id.'.' );

            // foreach( $blacklist_content as $blacklist_item ) {
            //     $str = preg_replace('/\s'.$blacklist_item.'\b|\b'.$blacklist_item.'\b/i', '', $value);
            //     if( strlen($str) !== strlen($value) ) {
            //         GFCommon::log_debug( __METHOD__ . '(): Contains blacklisted content. preg_replace: '.$blacklist_item );
            //         return true;
            //     }
            // }
            // GFCommon::log_debug( __METHOD__ . '(): preg_replace result: '. $str );
            
            if( strlen( str_ireplace($blacklist_content, '', $value) ) !== strlen($value) ) {
                GFCommon::log_debug( __METHOD__ . '(): Contains blacklisted content.' );
                return true;
            }
        }

        return $is_spam;
    }
    
    
    /**
     * Updates the local email blacklist from a remote source if needed.
     *
     * @return void
     */
    public function maybe_update_email_blacklist() {
        // Get comment blacklist
        $response = wp_remote_get(
            'https://raw.githubusercontent.com/matomo-org/referrer-spam-list/master/spammers.txt'
        );
        if ( is_wp_error( $response ) ) {
            return;
        } else {
            GFCommon::log_debug( __METHOD__ . '(): Retrieved remote blacklist.' );
        }

        // Get the etag
        $remote_etag = wp_remote_retrieve_header( $response, 'etag' );
        $etag = preg_replace( '/^[a-f0-9"]$/', '', $remote_etag );

        // Compare etag to check for updated file
        if ( $etag == get_option('sofw_email_blacklist_etag') && is_array( get_option( 'sofw_email_blacklist') ) ) {
            GFCommon::log_debug( __METHOD__ . '(): Local blacklist is already up to date.' );
            return;
        }

        // If remote blacklist is new, update etag and save blacklist
        update_option( 'sofw_email_blacklist_etag', $etag );

        $blacklist_body = wp_remote_retrieve_body( $response );
        $blacklist_content = explode( "\n", $blacklist_body );

        if ( is_array($blacklist_content) ) {
            update_option( 'sofw_email_blacklist', $blacklist_content );
            GFCommon::log_debug( __METHOD__ . '(): Updated.' );
        }
    }
    
    
    /**
     * Flags entries as spam if they contain blacklisted email addresses.
     *
     * @param bool $is_spam Current spam status
     * @param array $form Gravity Forms form array
     * @param array $entry Gravity Forms entry array
     * @return bool True if blacklisted email found, otherwise original $is_spam
     */
    public function sofw_gform_email_blacklist( $is_spam, $form, $entry ) {
        if ( $is_spam ) { return $is_spam; }

		$settings = parent::get_plugin_settings( $form );
        $email_blacklist = $settings['email_blacklist'];
        $custom_email_add = $settings['email_blacklist_add'];

		if ( empty($email_blacklist) ) {
            GFCommon::log_debug( __METHOD__ . '(): Option not set.' );
            return $is_spam;
        }

        $email_blacklist = array();
        
        // Get remote blacklist
        $this->maybe_update_email_blacklist();
        $email_blacklist = get_option('sofw_email_blacklist');
        
        // Get custom blacklist content w/o triggering error if db table !exist
        $custom_content = array();
        if ( !empty($custom_email_add) ) {
            $custom_content = explode( "\r\n", $custom_email_add );
            $email_blacklist = array_merge( $email_blacklist, $custom_content );
        }
        
        if ( empty($email_blacklist) ) {
            GFCommon::log_debug( __METHOD__ . '(): Email blacklist is empty.' );
            return $is_spam;
        }

        $field_types_to_check = array(
            'email',
        );

        foreach ( $form['fields'] as $field ) {
            // Skipping fields which are administrative or the wrong type.
            if ( $field->is_administrative() || ! in_array( $field->get_input_type(), $field_types_to_check ) ) {
                continue;
            }

            // Skipping fields which don't have a value.
            $value = $field->get_value_export( $entry );
            if ( empty( $value ) ) {
                continue;
            }

            GFCommon::log_debug( __METHOD__ . '(): Checking field id '.$field->id.'.' );
            if( strlen( str_replace($email_blacklist, '', $value) ) !== strlen($value) ) {
                GFCommon::log_debug( __METHOD__ . '(): Email is blacklisted.' );
                return true;
            }
        }

        return $is_spam;
    }
    
    
    /**
     * Flags entries as spam based on name blacklist, whitelist, and vowel rules.
     *
     * @param bool $is_spam Current spam status
     * @param array $form Gravity Forms form array
     * @param array $entry Gravity Forms entry array
     * @return bool True if name is blacklisted, not whitelisted, or fails vowel rule; otherwise original $is_spam
     */
    public function sofw_gform_name_spam( $is_spam, $form, $entry ) {
        if ( $is_spam ) { return $is_spam; }

        $name_blacklist = array();
        $settings = parent::get_plugin_settings( $form );
        if (!empty($settings['name_blacklist'])) {
            if (is_array($settings['name_blacklist'])) {
                $name_blacklist = array_merge($name_blacklist, $settings['name_blacklist']);
            } else {
                $name_blacklist[] = $settings['name_blacklist'];
            }
        }
        if (!empty($settings['name_blacklist_add'])) {
            $name_blacklist = array_merge($name_blacklist, explode("\r\n", $settings['name_blacklist_add']));
        }
        // Always ensure $name_blacklist is an array
        if (!is_array($name_blacklist)) {
            $name_blacklist = array();
        }

        $field_types_to_check = array('name');
        foreach ( $form['fields'] as $field ) {
            if ( $field->is_administrative() || ! in_array( $field->get_input_type(), $field_types_to_check ) ) {
                continue;
            }
            $value = $field->get_value_export( $entry );
            if ( empty( $value ) ) {
                continue;
            }
            GFCommon::log_debug( __METHOD__ . '(): Checking field id '.$field->id.'.' );
            $first  = rgar( $entry, $field->id . '.3' );
            $last   = rgar( $entry, $field->id . '.6' );
            if ( str_contains($last, $first) ) {
                GFCommon::log_debug( __METHOD__ . '(): Last Name contains First Name.' );
                return true;
            }
            if ( preg_match('~[0-9_]+~', $first) || preg_match('~[0-9_]+~', $last) ) {
                GFCommon::log_debug( __METHOD__ . '(): Name contains disallowed characters.' );
                return true;
            }
            if ( !empty($name_blacklist) ) {
                $first_replaced = str_ireplace($name_blacklist, '', $first);
                $last_replaced = str_ireplace($name_blacklist, '', $last);
                if ( strlen($first_replaced) !== strlen($first) || strlen($last_replaced) !== strlen($last) ) {
                    GFCommon::log_debug( __METHOD__ . '(): Name is in custom blacklist.' );
                    return true;
                }
            }
            $name_whitelist = [
                'zbyszko','krystl','lyndsbr','rhythms','krzyżan','krzyzan','gryndal','svrček','svrcek','czrnyst',
            ];
            $full_name = strtolower($first . $last);
            $full_name_spaced = strtolower(trim($first . ' ' . $last));
            $is_whitelisted = in_array($full_name, $name_whitelist) || in_array($full_name_spaced, $name_whitelist);
            $first_vowel_count = preg_match_all('/[aeiou]/i', $first);
            $last_vowel_count = preg_match_all('/[aeiou]/i', $last);
            if ((strlen($first) > 7 && $first_vowel_count <= 1 && !$is_whitelisted) || (strlen($last) > 7 && $last_vowel_count <= 1 && !$is_whitelisted)) {
                GFCommon::log_debug( __METHOD__ . '(): Name has too few vowels (not whitelisted).' );
                return true;
            }
        }
        return $is_spam;
    }
}