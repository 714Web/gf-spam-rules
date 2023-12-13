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
});