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
    // console.log('[GFSpamRules] Settings JS loaded');

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
        $input.off('.gfspmask');
        var realValue = $input.val();
        var maskedValue = maskValue(realValue);
        var isDirty = false;

        // Store the real value in a closure, not in the DOM
        $input.val(maskedValue);

        $input.on('focus.gfspmask click.gfspmask', function(e) {
            // Prevent revealing the real value
            // Optionally, select the field for overwrite
            setTimeout(function() { $input[0].setSelectionRange(maskedValue.length, maskedValue.length); }, 0);
        });
        $input.on('input.gfspmask', function() {
            isDirty = true;
        });
        $input.on('paste.gfspmask', function() {
            isDirty = true;
        });
        $input.on('keydown.gfspmask', function(e) {
            // If user starts typing, clear the field for new value
            if (!isDirty && e.key.length === 1) {
                $input.val("");
                isDirty = true;
            }
        });
        // On form submit, restore real value if not dirty
        $input.closest('form').off('submit.gfspmask').on('submit.gfspmask', function() {
            if (!isDirty && $input.val() === maskedValue) {
                $input.val(realValue);
            }
            // else: user entered a new value, submit as-is
        });
    }

    setupMaskingByName('cloudflare_api_token');
    setupMaskingByName('cloudflare_account_id');
    // --- End Cloudflare Key Masking ---
});