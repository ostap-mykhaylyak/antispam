<?php
/**
 * Fired when the plugin is uninstalled.
 *
 * @package AntiSpam
 */

// If uninstall not called from WordPress, then exit.
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
    exit;
}

// Delete options
delete_option( 'asg_settings' );
delete_option( 'asg_version' );

// Delete custom table
global $wpdb;
$table_name = $wpdb->prefix . 'asg_logs';
$wpdb->query( "DROP TABLE IF EXISTS $table_name" );

// Clear transients
$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_asg_%'" );
$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_timeout_asg_%'" );
