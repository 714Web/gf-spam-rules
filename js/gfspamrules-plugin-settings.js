jQuery(document).ready(function($) {
    if ($('#gform_setting_content_blacklist_title input[type="checkbox"]').is(':checked')) {
        $('#gform_setting_content_blacklist_add').show();
    }

    if ($('#gform_setting_email_blacklist_title input[type="checkbox"]').is(':checked')) {
        $('#gform_setting_email_blacklist_add').show();
    }

    if ($('#gform_setting_name_blacklist_title input[type="checkbox"]').is(':checked')) {
        $('#gform_setting_name_blacklist_add').show();
    }

    // --- Cloudflare Key Masking (robust selector) ---
    console.log('[GFSpamRules] Settings JS loaded');

    function findSettingInput(name) {
        // Prefer the settings row id Gravity Forms renders: #gform_setting_<name>
        var $row = $('#gform_setting_' + name);
        var $input = $row.find('input, textarea, select').first();
        if ($input.length) return $input;
        // Fallbacks: try common attribute variants used by the Add-On framework/themes
        $input = $('input[name="' + name + '"]');
        if ($input.length) return $input;
        $input = $('input[data-setting="' + name + '"]');
        if ($input.length) return $input;
        $input = $('[id*="' + name + '"]').filter('input, textarea, select').first();
        return $input;
    }

    // --- Cloudflare Key Masking ---
    function maskValue(val) {
        if (!val || val.length <= 4) return val;
        return '•'.repeat(val.length - 4) + val.slice(-4);
    }

    function setupMaskingByName(name) {
        var $input = findSettingInput(name);
        if ($input.length === 0) {
            console.log('[GFSpamRules] Field not found:', name);
            return;
        }
        // Avoid duplicate bindings
        $input.off('.gfspmask');
        var realValue = $input.val();

        // Store real value in data attribute
        $input.data('real-value', realValue);

        // Mask on load
        $input.val(maskValue(realValue));

        $input.on('focus.gfspmask', function() {
            $input.val($input.data('real-value'));
        });
        $input.on('blur.gfspmask', function() {
            $input.val(maskValue($input.data('real-value')));
        });
        $input.on('input.gfspmask', function() {
            $input.data('real-value', $input.val());
        });
        // On form submit, restore real value
        $input.closest('form').off('submit.gfspmask').on('submit.gfspmask', function() {
            $input.val($input.data('real-value'));
        });
        console.log('[GFSpamRules] Masked field initialized:', name, 'found:', $input.length);
    }

    setupMaskingByName('cloudflare_api_token');
    setupMaskingByName('cloudflare_account_id');
    // --- End Cloudflare Key Masking ---
});