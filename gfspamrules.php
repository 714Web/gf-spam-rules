<?php
/*
Plugin Name: Gravity Forms Spam Rules
Plugin URI: https://github.com/gf-spam-rules
Description: A Gravity Forms add-on to enable spam filtering options.
Version: 0.1
Author: Jeremy Caris
Author URI: https://github.com/jeremycaris

------------------------------------------------------------------------

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
*/

define( 'GF_SPAMRULES_VERSION', '0.1' );

add_action( 'gform_loaded', array( 'GF_SpamRules_Bootstrap', 'load' ), 5 );

class GF_SpamRules_Bootstrap {

    public static function load() {

        if ( ! method_exists( 'GFForms', 'include_addon_framework' ) ) {
            return;
        }

        require_once( 'class-gfspamrules.php' );

        GFAddOn::register( 'GFSpamRules' );
    }

}

function gf_spamrules() {
    return GFSpamRules::get_instance();
}



/* Load update checker */
require 'inc/plugin-update-checker-5.3/plugin-update-checker.php';
use YahnisElsts\PluginUpdateChecker\v5\PucFactory;

$myUpdateChecker = PucFactory::buildUpdateChecker(
    'https://github.com/jeremycaris/gf-spam-rules/',
    __FILE__,
    'gf-spam-rules'
);
// $myUpdateChecker->setAuthentication('411a94ddac97544ac4d5e1bc0ccde4fb976a71cc');
$myUpdateChecker->getVcsApi()->enableReleaseAssets();
