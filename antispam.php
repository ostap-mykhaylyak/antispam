<?php
/**
 * Plugin Name: AntiSpam
 * Plugin URI: https://github.com/ostap-mykhaylyak/antispam
 * Description: Plugin antispam avanzato per WordPress e WooCommerce.
 * Version: 1.0.0
 * Author: Ostap Mykhaylyak
 * Author URI: https://github.com/ostap-mykhaylyak/
 * License: GPL v2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: antispam
 * Domain Path: /languages
 * Requires at least: 6.0
 * Requires PHP: 7.4
 * Tested up to: 6.7
 * WC requires at least: 8.0
 * WC tested up to: 9.0
 */

// Prevenire accesso diretto
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

// Definire costanti del plugin
define( 'ASG_VERSION', '1.0.0' );
define( 'ASG_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
define( 'ASG_PLUGIN_URL', plugin_dir_url( __FILE__ ) );
define( 'ASG_PLUGIN_BASENAME', plugin_basename( __FILE__ ) );

/**
 * Classe principale del plugin
 */
class AntiSpam {

    private static $instance = null;

    public static function get_instance() {
        if ( null === self::$instance ) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function __construct() {
        $this->load_dependencies();
        $this->set_hooks();
    }

    private function load_dependencies() {
        require_once ASG_PLUGIN_DIR . 'includes/class-api.php';
        require_once ASG_PLUGIN_DIR . 'includes/class-security.php';
        require_once ASG_PLUGIN_DIR . 'includes/class-admin.php';
        require_once ASG_PLUGIN_DIR . 'includes/class-brute-force.php';

        if ( $this->is_woocommerce_active() ) {
            require_once ASG_PLUGIN_DIR . 'includes/class-woocommerce.php';
        }
    }

    private function is_woocommerce_active() {
        return class_exists( 'WooCommerce' );
    }

    private function set_hooks() {
        add_action( 'plugins_loaded', array( $this, 'load_textdomain' ) );
        register_activation_hook( __FILE__, array( $this, 'activate' ) );
        register_deactivation_hook( __FILE__, array( $this, 'deactivate' ) );
        add_action( 'plugins_loaded', array( $this, 'maybe_upgrade' ) );
        add_action( 'init', array( $this, 'init_components' ) );
    }

    public function load_textdomain() {
        load_plugin_textdomain(
            'antispam',
            false,
            dirname( ASG_PLUGIN_BASENAME ) . '/languages/'
        );
    }

    public function activate() {
        $default_options = array(
            'enabled'             => true,
            'check_ip'            => true,
            'check_email'         => true,
            'check_username'      => false,
            'frequency_threshold' => 1,
            'confidence_threshold'=> 50,
            'block_tor'           => false,
            'cache_duration'      => 3600,
            'log_enabled'         => true,
            'bf_enabled'          => true,
            'bf_max_attempts'     => 5,
            'bf_window'           => 600,
            'bf_lockout_duration' => 900,
            'bf_lockout_max'      => 86400,
            'bf_notify_admin'     => true,
        );

        add_option( 'asg_settings', $default_options );
        add_option( 'asg_version', ASG_VERSION );
        $this->create_logs_table();
        flush_rewrite_rules();
    }

    public function deactivate() {
        flush_rewrite_rules();
    }

    /**
     * Crea la tabella se mancante o aggiorna la struttura in caso di nuova versione.
     * Viene eseguita ad ogni caricamento del plugin: sicura grazie a dbDelta.
     */
    public function maybe_upgrade() {
        $installed_version = get_option( 'asg_version' );

        if ( $installed_version !== ASG_VERSION || $this->logs_table_missing() ) {
            $this->create_logs_table();
            update_option( 'asg_version', ASG_VERSION );

            // Assicura che le opzioni di default esistano (utile per installazioni via FTP)
            if ( false === get_option( 'asg_settings' ) ) {
                $default_options = array(
                    'enabled'              => true,
                    'check_ip'             => true,
                    'check_email'          => true,
                    'check_username'       => false,
                    'frequency_threshold'  => 1,
                    'confidence_threshold' => 50,
                    'block_tor'            => false,
                    'cache_duration'       => 3600,
                    'log_enabled'          => true,
                    'bf_enabled'          => true,
                    'bf_max_attempts'     => 5,
                    'bf_window'           => 600,
                    'bf_lockout_duration' => 900,
                    'bf_lockout_max'      => 86400,
                    'bf_notify_admin'     => true,
                );
                add_option( 'asg_settings', $default_options );
            }
        }
    }

    /**
     * Controlla se la tabella dei log esiste fisicamente nel database.
     */
    private function logs_table_missing() {
        global $wpdb;
        $table_name = $wpdb->prefix . 'asg_logs';
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery
        return $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table_name ) ) !== $table_name;
    }

    private function create_logs_table() {
        global $wpdb;
        $table_name = $wpdb->prefix . 'asg_logs';
        $charset_collate = $wpdb->get_charset_collate();

        $sql = "CREATE TABLE IF NOT EXISTS $table_name (
            id bigint(20) NOT NULL AUTO_INCREMENT,
            timestamp datetime DEFAULT CURRENT_TIMESTAMP,
            ip_address varchar(100) NOT NULL,
            email varchar(255) DEFAULT NULL,
            username varchar(255) DEFAULT NULL,
            type varchar(50) NOT NULL,
            frequency int(11) DEFAULT 0,
            confidence float DEFAULT 0,
            action varchar(50) NOT NULL,
            source varchar(100) DEFAULT NULL,
            user_agent text DEFAULT NULL,
            PRIMARY KEY (id),
            KEY ip_address (ip_address),
            KEY timestamp (timestamp)
        ) $charset_collate;";

        require_once( ABSPATH . 'wp-admin/includes/upgrade.php' );
        dbDelta( $sql );
    }

    public function init_components() {
        new ASG_API();
        new ASG_Security();
        new ASG_BruteForce();
        new ASG_Admin();

        if ( $this->is_woocommerce_active() ) {
            new ASG_WooCommerce();
        }
    }
}

add_action( 'plugins_loaded', function() {
    AntiSpam::get_instance();
});
