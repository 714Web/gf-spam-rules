<?php
/*
 *
 * Core Functions
 * 
 */

 class GFSpamRulesCoreFunctions extends GFSpamRules {
    
    public function custom_spam_confirmation( $confirmation, $form, $entry ) {
        if ( empty( $entry ) || rgar( $entry, 'status' ) === 'spam' ) {
            return 'Your message has not been delivered because it was identified as spam.';
        }

        return $confirmation;
    }


    public function sofw_gform_loggedin_notspam( $is_spam, $form, $entry ) {
        $setting = parent::get_plugin_setting( 'bypass_spam' );

        if ( empty($setting) ) {
            GFCommon::log_debug( __METHOD__ . '(): Option not set.' );
            return $is_spam;
        }

        if ( !empty($setting) && is_user_logged_in() ) {
            GFCommon::log_debug( __METHOD__ . '(): Entry marked as not spam for loggedin user.' );
            $is_spam = false;
        }

        return $is_spam;
    }
    
    
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
    
    
    public function sofw_enforce_gravity_forms_anti_spam_honeypot( $form ) {
        $setting = parent::get_plugin_setting( 'enforce_honeypot' );

        if ( empty( $setting ) ) {
            return $form;
        }
        
        $form['enableHoneypot'] = true;
        return $form;
    }
    

    public function maybe_initiate_remote_blacklists($hook_suffix) {
        if($hook_suffix !== 'forms_page_gf_settings') {
            return;
        }

        $content_blacklist = parent::get_plugin_setting( 'content_blacklist' );
        $email_blacklist = parent::get_plugin_setting( 'email_blacklist' );

		$url_components = $_SERVER['QUERY_STRING'];
		if ( empty($url_components) || !is_string($url_components) ) {
			return $form;
		}
		$params = explode( '&', $url_components );
		foreach ( $params as $k => $v ) {
			if ( $v == 'subview=gfspamrules' ) {
                if ( !empty($content_blacklist) ) $this->maybe_update_content_blacklist();
                if ( !empty($email_blacklist) ) $this->maybe_update_email_blacklist();
			}
		}
    }
    
    
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
    
    
    public function sofw_gform_name_spam( $is_spam, $form, $entry ) {
        if ( $is_spam ) { return $is_spam; }

		$settings = parent::get_plugin_settings( $form );

		if ( empty($settings['name_blacklist']) ) {
            GFCommon::log_debug( __METHOD__ . '(): Option not set.' );
            return $is_spam;
        }

        $name_blacklist = array();
        $custom_name_add = $settings['name_blacklist_add'];
        if ( !empty($custom_name_add) ) {
            $name_blacklist = explode( "\r\n", $custom_name_add );
        }

        $field_types_to_check = array(
            'name',
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
            $first  = rgar( $entry, $field->id . '.3' );
            $last   = rgar( $entry, $field->id . '.6' );
    
            // if last name contains first name
            if ( str_contains($last, $first) ) {
                GFCommon::log_debug( __METHOD__ . '(): Last Name contains First Name.' );
                return true;
            }

            // if names contain integers or characters that shouldn't be in a name
            if ( preg_match('~[0-9_]+~', $first) || preg_match('~[0-9_]+~', $last) ) {
                GFCommon::log_debug( __METHOD__ . '(): Name contains disallowed characters.' );
                return true;
            }

            if ( empty($name_blacklist) ) {
                return $is_spam;
            }
            if ( strlen( str_ireplace($name_blacklist, '', $first) ) !== strlen($first) || strlen( str_ireplace($name_blacklist, '', $last) ) !== strlen($last) ) {
                GFCommon::log_debug( __METHOD__ . '(): Name is in custom blacklist.' );
                return true;
            }
        }

        return $is_spam;
    }

 }