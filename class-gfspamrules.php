<?php

GFForms::include_addon_framework();

class GFSpamRules extends GFAddOn {

	protected $_version = GF_SPAMRULES_VERSION;
	protected $_min_gravityforms_version = '1.9';
	protected $_slug = 'gfspamrules';
	protected $_path = 'gfspamrules/gfspamrules.php';
	protected $_full_path = __FILE__;
	protected $_title = 'Gravity Forms Spam Rules';
	protected $_short_title = 'Spam Rules';

	private static $_instance = null;

	/**
	 * Get an instance of this class.
	 *
	 * @return GFSpamRules
	 */
	public static function get_instance() {
		if ( self::$_instance == null ) {
			self::$_instance = new GFSpamRules();
		}

		return self::$_instance;
	}

	/**
	 * Handles hooks and loading of language files.
	 */
	public function init() {
		parent::init();

		require( 'inc/core-functions.php' );
		$cf = new GFSpamRulesCoreFunctions();
		
		add_filter( 'gform_form_post_get_meta', array($cf, 'sofw_enforce_gravity_forms_anti_spam_honeypot') );
		add_action( 'admin_enqueue_scripts', array($cf, 'maybe_initiate_remote_blacklists'), 10, 1 );
		add_filter( 'gform_entry_is_spam', array($cf, 'sofw_gform_loggedin_notspam'), 12, 3 );
		add_filter( 'gform_entry_is_spam', array($cf, 'sofw_gform_name_spam'), 11, 3 );
		add_filter( 'gform_entry_is_spam', array($cf, 'sofw_gform_email_blacklist'), 11, 3 );
		add_filter( 'gform_entry_is_spam', array($cf, 'sofw_gform_url_spam'), 11, 3 );
		add_filter( 'gform_entry_is_spam', array($cf, 'sofw_gform_sql_xss_protection'), 11, 3 );
		add_filter( 'gform_entry_is_spam', array($cf, 'suspicious_tld_protection'), 11, 3 );
		add_filter( 'gform_entry_is_spam', array($cf, 'sofw_gform_content_blacklist'), 11, 3 );
		add_filter( 'gform_confirmation', array($cf, 'custom_spam_confirmation'), 11, 3 );
	}


	// # SCRIPTS & STYLES --------------------------------------------------------------------------------------

	/**
	 * Return the scripts which should be enqueued.
	 *
	 * @return array
	 */
	public function scripts() {
		$scripts = array(
			array(
				'handle'  => 'gfspamrules-plugin-settings',
				'src'     => $this->get_base_url() . '/js/gfspamrules-plugin-settings.js',
				'version' => $this->_version,
				'deps'    => array( 'jquery' ),
				'enqueue' => array(
					array(
						'admin_page' => array( 'plugin_settings' ),
						'tab'        => 'gfspamrules'
					)
				)
			),
			array(
				'handle'  => 'bootstrap',
				'src'     => $this->get_base_url() . '/js/bootstrap.min.js',
				'version' => '5.3.1',
				'deps'    => array( 'jquery' ),
				'enqueue' => array(
					array(
						'admin_page' => array( 'plugin_page' ),
						'tab'        => 'gfspamrules'
					)
				)
			),

		);

		return array_merge( parent::scripts(), $scripts );
	}

	/**
	 * Return the stylesheets which should be enqueued.
	 *
	 * @return array
	 */
	public function styles() {
		$styles = array(
			array(
				'handle'  => 'gfspamrules-plugin-settings',
				'src'     => $this->get_base_url() . '/css/gfspamrules-plugin-settings.css',
				'version' => $this->_version,
				'enqueue' => array(
					array(
						'admin_page' => array( 'plugin_settings' ),
						'tab'        => 'gfspamrules'
					)
				)
			),
			array(
				'handle'  => 'gfspamrules-plugin-page',
				'src'     => $this->get_base_url() . '/css/gfspamrules-plugin-page.css',
				'version' => $this->_version,
				'enqueue' => array(
					array(
						'admin_page' => array( 'plugin_page' ),
						'tab'        => 'gfspamrules'
					)
				)
			),
			array(
				'handle'  => 'bootstrap',
				'src'     => $this->get_base_url() . '/css/bootstrap.min.css',
				'version' => '5.3.1',
				'enqueue' => array(
					array(
						'admin_page' => array( 'plugin_page' ),
						'tab'        => 'gfspamrules'
					)
				)
			)
		);

		return array_merge( parent::styles(), $styles );
	}


	// # FRONTEND FUNCTIONS --------------------------------------------------------------------------------------------

	public function get_all_form_spam_entries() {
		$search_criteria = array();
		$search_criteria['status'] = "spam";
		$form_id = 0;
		$page_size = 20;
		$current_page = max( 1, isset($_REQUEST['pagenum']) ? (int)$_REQUEST['pagenum'] : 1 );
		$offset   = ($current_page - 1) * $page_size;
		$sorting = array();
		$paging = array( 'offset' => $offset, 'page_size' => $page_size ); 
		$total_count = 0;
		$results = GFAPI::get_entries( $form_id, $search_criteria, $sorting, $paging, $total_count );
		$total_pages = ceil( $total_count / $page_size ); 

		// pass-through data
		$results['current_page'] = $current_page;
		$results['total_count'] = $total_count;
		$results['total_pages'] = $total_pages;
			
		return $results;
	}


	// # ADMIN FUNCTIONS --------------------------------------------------------------------------------------

	/**
	 * Creates a custom page for this add-on.
	 */
	public function plugin_page() {
		$results = $this->get_all_form_spam_entries();

		// Build pagination
		$pagination_links = '';
		if ( $results['total_pages'] > 1 ) {
			$pagination_links   = '<nav aria-label="Pagination">';
			$pagination_links  .= paginate_links([
						'base'      => @add_query_arg('pagenum','%#%'),
						'format'    => '&pagenum=%#%',
						'current'   => $results['current_page'],
						'total'     => $results['total_pages'],
						'prev_next' => true,
						'prev_text' => '&laquo;',
						'next_text' => '&raquo;',
						'type' 		=> 'list',
					]);
			$pagination_links .= '</nav>';
		}
		// convert to bootstrap pagination
		$pagination_links = str_replace("<ul class='page-numbers'>", '<ul class="pagination pagination-sm mb-0 justify-content-end">', $pagination_links);
		$pagination_links = str_replace('page-numbers', 'page-link', $pagination_links);
		$pagination_links = str_replace('<li>', '<li class="page-item mb-0">', $pagination_links);
		$pagination_links = str_replace(
			'<li class="page-item mb-0"><span aria-current="page" class="page-link current">',
			'<li class="page-item mb-0 active" aria-current="page"><span class="page-link">',
			$pagination_links
		);
		?>
		<div class="wrap px-0">
			<p><a href="<?php echo esc_url( admin_url( 'admin.php?page=gf_settings&subview=' . $this->_slug ) ); ?>">Edit Settings</a></p>

			<div id="top-pagination">
				<div class="container px-0">
					<div class="row mx-auto w-100">
						<div class="col col-12 col-md-6 px-0">
							<p><strong><?php echo $results['total_count']; ?></strong> total spam entries from all forms.</p>
						</div>
						<div class="col col-12 col-md-6 px-0 justify-content-end">
							<!-- pagination -->
							<?php echo $pagination_links; ?>
							<!-- pagination end -->
						</div>
					</div>
				</div>
			</div>
			<div id="universal-message-container">
				<div class="container">
					<div class="row">
						<div class="col col-2">Entry ID<br>Date/Time</div>
						<div class="col col-2"><br>Form Title</div>
						<div class="col col-3"><br>Source URL</div>
						<div class="col"><br>Other Submission Fields</div>
					</div>
				</div>
				<div class="container pt-2 mt-0">
		<?php
		// remove pass-through data before foreach
		unset($results['current_page']);
		unset($results['total_count']);
		unset($results['total_pages']);
		
		foreach ($results as $entry) {
			$id = $entry['id'];
			$form_id = $entry['form_id'];
			$date = $entry['date_created'];
			$source = $entry['source_url'];
			$url = admin_url('admin.php?page=gf_entries&view=entry&id='.$form_id.'&lid='.$id);
			
			$form = GFAPI::get_form( $form_id );
			$form_title = $form['title'];
			
			$build = '<div class="row py-2 border border-0 border-top border-light-subtle">';
			$build .= '<div class="col col-2">';
			$build .= '<a href="'.$url.'" target="_blank" class="pe-2">'.$id.'</a><br>';
			$build .= $date;
			$build .= '</div>';
			$build .= '<div class="col col-2"><strong>';
			$build .= $form_title;
			$build .= '</strong></div>';
			$build .= '<div class="col col-3" style="overflow: hidden;">';
			$build .= '<a href="'.$source.'" target="_blank" class="pe-2">'.$source.'</a>';
			$build .= '</div>';
			
			$i = 0;
			$extra = '';
			foreach( $entry as $key=>$value ) {
				if ( is_int( (int)$key ) && (int)$key !== 0 && !empty($value) ) {
					if ( strlen( $value ) > 100 ) {
						$extra = 'col-12 mt-2';
					}
					$build .= '<div class="col '.$extra.'">';
					$build .= $value;
					$build .= '</div>';
					$i++;
				}
			}
			
			$build .= '</div>';
			
			
			print_r( $build );
		}
		  
							?>
				</div>
				
			</div><!-- #universal-message-container -->

			<div id="bottom-pagination">
				<div class="container px-0 pt-1">
					<div class="row mx-auto w-100">
						<div class="col px-0 justify-content-end">
							<!-- pagination -->
							<?php echo $pagination_links; ?>
							<!-- pagination end -->
						</div>
					</div>
				</div>
			</div>

		</div><!-- .wrap -->
		<?php
	}

	/**
	 * Configures the settings which should be rendered on the add-on settings tab.
	 *
	 * @return array
	 */
	public function plugin_settings_fields() {
		return array(
			array(
				'title'  => esc_html__( $this->_short_title, 'gfspamrules' ),
				'fields' => array(
					array(
						'label'   => esc_html__( 'Bypass Spam Filters For Logged-In Users', 'gfspamrules' ),
						'type'    => 'checkbox',
						'name'    => 'bypass_spam_title',
						'description' => '<p>' . sprintf( esc_html__( 'Ensure form submissions for logged-in users are never marked as spam.', 'gfspamrules' ) ) . '</p>',
						'tooltip' => sprintf(
							'<h6>%s</h6>%s',
							esc_html__( 'Notice', 'gfspamrules' ),
							esc_html__( 'Spam filtering functions will still run at form submission, but the entry will not be flagged as spam for logged-in users.', 'gfspamrules' )
						),
						'choices' => array(
							array(
								'label' => esc_html__( 'Enable', 'gfspamrules' ),
								'name'  => 'bypass_spam',
							),
						),
					),
					array(
						'label'   => esc_html__( 'URL Spam Protection', 'gfspamrules' ),
						'type'    => 'checkbox',
						'name'    => 'url_spam_title',
						'description' => '<p>' . sprintf( esc_html__( 'Marks form submissions as spam if they contain URL\'s. Only text, textarea, and post_title fields will be evaluated.', 'gfspamrules' ) ) . '</p>',
						'tooltip' => esc_html__( 'The majority of spam submissions contain URL\'s.', 'gfspamrules' ),
						'choices' => array(
							array(
								'label' => esc_html__( 'Enable', 'gfspamrules' ),
								'name'  => 'url_spam',
							),
						),
					),
					array(
						'label'   => esc_html__( 'Enforce Honeypot', 'gfspamrules' ),
						'type'    => 'checkbox',
						'name'    => 'enforce_honeypot_title',
						'description' => '<p>' . sprintf( esc_html__( 'Force the built-in anti-spam honeypot option to be enabled on all forms. This overrides the current setting on all individual forms.', 'gfspamrules' ) ) . '</p>',
						'tooltip' => esc_html__( 'The Gravity Forms honeypot adds a hidden field to the form when the page loads, and if that field is populated, the honeypot considers the entry spam. It also implements an extra javascript input that is added to the POST request when the form is submitted, so a human would never see it, but submissions will fail validation if this extra input does not contain the expected value.', 'gfspamrules' ),
						'choices' => array(
							array(
								'label' => esc_html__( 'Enable', 'gfspamrules' ),
								'name'  => 'enforce_honeypot'
							),
						),
					),
					array(
						'label'   => esc_html__( 'SQL/XSS/Command Injection Protection', 'gfspamrules' ),
						'type'    => 'checkbox',
						'name'    => 'sql_xss_cmd_protection_title',
						'description' => '<p>' . sprintf( esc_html__( 'Marks form submissions as spam if they contain SQL, XSS, or command injection patterns.', 'gfspamrules' ) ) . '</p>',
						'tooltip' => esc_html__( 'Many spam submissions contain malicious patterns, such as SQL injection, XSS (Cross-Site Scripting), command injection, shell tricks, encoded payloads, long non-ASCII, repeated chars, suspiciously long base64, or suspicious query params.', 'gfspamrules' ),
						'choices' => array(
							array(
								'label' => esc_html__( 'Enable', 'gfspamrules' ),
								'name'  => 'sql_xss_cmd_protection',
								'default_value' => 1,
							),
						),
					),
					array(
						'label'   => esc_html__( 'Suspicious TLD Protection', 'gfspamrules' ),
						'type'    => 'checkbox',
						'name'    => 'suspicious_tld_protection_title',
						'description' => '<p>' . sprintf( esc_html__( 'Marks form submissions as spam if they contain suspicious top-level domains (TLDs).', 'gfspamrules' ) ) . '</p>',
						'tooltip' => esc_html__( 'Many spam submissions contain suspicious TLDs, such as .ru, .cn, .tk, .xyz, .top, .click, .work, .gq, .ml, .ga, .icu, .cf, .pw, .cc, .in, .bid, .info, .site, .online, .space, .loan, .win, .men, .stream, .review, .party, .gdn, .ninja, .science, .accountant, .faith, .date, .download, .racing, .jetzt, .wang, .kim, .red, .blue, .black, .pink, .green, .gold, .pro, .rocks, .lol, .ooo, .link, .pics, .photo, .photos, .today, .trade, .webcam, .website, .wiki, .zip, .zone.', 'gfspamrules' ),
						'choices' => array(
							array(
								'label' => esc_html__( 'Enable', 'gfspamrules' ),
								'name'  => 'suspicious_tld_protection',
								'default_value' => 1,
							),
						),
					),
					array(
						'label'   => esc_html__( 'Enable Content Blacklist?', 'gfspamrules' ),
						'type'    => 'checkbox',
						'name'    => 'content_blacklist_title',
						// translators: %1 is an opening <a> tag, and %2 is a closing </a> tag.
						'description' => '<p>' . sprintf( esc_html__( 'Utilizes the %1$sComment Blacklist for WordPress%2$s and enables the ability to add additional words or phrases via the Custom Content Blacklist.', 'gfspamrules' ), '<a href="https://github.com/splorp/wordpress-comment-blacklist" target="_blank">', '</a>' ) . '</p>',
						'choices' => array(
							array(
								'label' => esc_html__( 'Enable', 'gfspamrules' ),
								'name'  => 'content_blacklist',
								'default_value' => 1,
							),
						),
						'onclick' => "if(this.checked){jQuery('#gform_setting_content_blacklist_add').show();} else{jQuery('#gform_setting_content_blacklist_add').hide();}",
					),
					array(
						'label'   => esc_html__( 'Custom Content Blacklist', 'gfspamrules' ),
						'type'    => 'textarea',
						'name'    => 'content_blacklist_add',
						// translators: %1 is an opening <a> tag, and %2 is a closing </a> tag.
						'description' => '<p>' . sprintf( esc_html__( 'Add additional words or phrases below (one per line) to customize the blacklist. Beware: partial matches count and they are not case-sensitive (E.g., "Rob" will blacklist "robert", "Robby", "JIM ROB", etc.).', 'gfspamrules' ) ) . '</p>',
						'class'   => 'medium',
					),
					array(
						'label'   => esc_html__( 'Enable Email Domain Blacklist?', 'gfspamrules' ),
						'type'    => 'checkbox',
						'name'    => 'email_blacklist_title',
						// translators: %1 is an opening <a> tag, and %2 is a closing </a> tag.
						'description' => '<p>' . sprintf( esc_html__( 'Utilizes the %1$sReferrer Spam List%2$s and enables the ability to blacklist additional email addresses and email domains.', 'gfspamrules' ), '<a href="https://github.com/matomo-org/referrer-spam-list" target="_blank">', '</a>' ) . '</p>',
						'choices' => array(
							array(
								'label' => esc_html__( 'Enable', 'gfspamrules' ),
								'name'  => 'email_blacklist',
								'default_value' => 1,
							),
						),
						'onclick' => "if(this.checked){jQuery('#gform_setting_email_blacklist_add').show();} else{jQuery('#gform_setting_email_blacklist_add').hide();}",
					),
					array(
						'label'   => esc_html__( 'Custom Email Address & Domain Blacklist', 'gfspamrules' ),
						'type'    => 'textarea',
						'name'    => 'email_blacklist_add',
						// translators: %1 is an opening <a> tag, and %2 is a closing </a> tag.
						'description' => '<p>' . sprintf( esc_html__( 'Add additional email addresses or domain names below (one per line) to customize the blacklist. Beware: partial matches count and they are not case-sensitive (E.g., "site.com" will blacklist all emails @ "mysite.com", "WEBSITE.com", etc.).', 'gfspamrules' ) ) . '</p>',
						'class'   => 'medium',
					),
					array(
						'label'   => esc_html__( 'Enable Name Filtering?', 'gfspamrules' ),
						'type'    => 'checkbox',
						'name'    => 'name_blacklist_title',
						// translators: %1 is an opening <a> tag, and %2 is a closing </a> tag.
						'description' => '<p>' . sprintf( esc_html__( 'Mark form submissions as spam if the Last Name field contains the First Name (E.g., RobertGurge RobertGurgess) or if either name field contains characters that should never be in a name (E.g., underscore, integer, etc). Also enables the ability to blacklist additional custom names.', 'gfspamrules' ) ) . '</p>',
						'choices' => array(
							array(
								'label' => esc_html__( 'Enable', 'gfspamrules' ),
								'name'  => 'name_blacklist',
								'default_value' => 1,
							),
						),
						'onclick' => "if(this.checked){jQuery('#gform_setting_name_blacklist_add').show();} else{jQuery('#gform_setting_name_blacklist_add').hide();}",
					),
					array(
						'label'   => esc_html__( 'Custom Name Blacklist', 'gfspamrules' ),
						'type'    => 'textarea',
						'name'    => 'name_blacklist_add',
						// translators: %1 is an opening <a> tag, and %2 is a closing </a> tag.
						'description' => '<p>' . sprintf( esc_html__( 'Add any First Name or Last Name you wish to blacklist (one per line). Beware: partial matches count and they are not case-sensitive (E.g., "Rob" will blacklist "robert", "Robby", "JIM ROB", etc.).', 'gfspamrules' ) ) . '</p>',
						'class'   => 'medium',
					),
				)
			)
		);
	}

	/**
	 * Define dashicons
	 * @since 0.1
	 */
	public function get_app_menu_icon() {
		return $this->get_base_url() . '/img/gf-spamrules.svg';
	}
	public function get_menu_icon() {
		return $this->get_base_url() . '/img/gf-spamrules.svg';
	}


}
