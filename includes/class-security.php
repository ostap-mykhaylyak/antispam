<?php
/**
 * Classe per la gestione della sicurezza e dei controlli antispam
 *
 * @package AntiSpam
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class ASG_Security {

    private $api;
    private $options;

    public function __construct() {
        $this->options = get_option( 'asg_settings', array() );
        $this->api     = new ASG_API();
        $this->set_hooks();
    }

    private function set_hooks() {
        if ( empty( $this->options['enabled'] ) ) {
            return;
        }

        // Registrazione WordPress
        add_filter( 'registration_errors', array( $this, 'check_registration' ), 10, 3 );

        // Login WordPress
        add_filter( 'authenticate', array( $this, 'check_login' ), 30, 3 );

        // Commenti
        add_filter( 'preprocess_comment', array( $this, 'check_comment' ) );
    }

    /**
     * Controlla la registrazione utente
     */
    public function check_registration( $errors, $sanitized_user_login, $user_email ) {
        $ip = $this->api->get_visitor_ip();

        $data = array(
            'ip'    => $ip,
            'email' => $user_email,
        );

        if ( ! empty( $this->options['check_username'] ) ) {
            $data['username'] = $sanitized_user_login;
        }

        $result = $this->api->check_multiple( $data );

        if ( is_wp_error( $result ) ) {
            return $errors;
        }

        $blocked = false;
        $reason  = '';

        if ( ! empty( $this->options['check_ip'] ) && $this->api->is_spam( $result, 'ip' ) ) {
            $blocked = true;
            $reason  = 'ip';
        }

        if ( ! $blocked && ! empty( $this->options['check_email'] ) && $this->api->is_spam( $result, 'email' ) ) {
            $blocked = true;
            $reason  = 'email';
        }

        if ( ! $blocked && ! empty( $this->options['check_username'] ) && $this->api->is_spam( $result, 'username' ) ) {
            $blocked = true;
            $reason  = 'username';
        }

        if ( $blocked ) {
            $this->log_attempt( $ip, $user_email, $sanitized_user_login, $reason, $result, 'blocked', 'registration' );
            $errors->add(
                'asg_spam_blocked',
                __( '<strong>Errore</strong>: Registrazione bloccata per motivi di sicurezza.', 'antispam' )
            );
        } else {
            $this->log_attempt( $ip, $user_email, $sanitized_user_login, 'none', $result, 'allowed', 'registration' );
        }

        return $errors;
    }

    /**
     * Controlla il tentativo di login
     */
    public function check_login( $user, $username, $password ) {
        if ( empty( $username ) || empty( $password ) ) {
            return $user;
        }

        $ip = $this->api->get_visitor_ip();

        if ( empty( $this->options['check_ip'] ) ) {
            return $user;
        }

        $result = $this->api->check_ip( $ip );

        if ( is_wp_error( $result ) ) {
            return $user;
        }

        if ( $this->api->is_spam( $result, 'ip' ) ) {
            $this->log_attempt( $ip, '', $username, 'ip', $result, 'blocked', 'login' );
            return new WP_Error(
                'asg_spam_blocked',
                __( '<strong>Errore</strong>: Accesso bloccato per motivi di sicurezza.', 'antispam' )
            );
        }

        return $user;
    }

    /**
     * Controlla i commenti
     */
    public function check_comment( $commentdata ) {
        $ip    = $this->api->get_visitor_ip();
        $email = isset( $commentdata['comment_author_email'] ) ? $commentdata['comment_author_email'] : '';

        $data = array( 'ip' => $ip );
        if ( ! empty( $email ) ) {
            $data['email'] = $email;
        }

        $result = $this->api->check_multiple( $data );

        if ( is_wp_error( $result ) ) {
            return $commentdata;
        }

        $blocked = false;

        if ( ! empty( $this->options['check_ip'] ) && $this->api->is_spam( $result, 'ip' ) ) {
            $blocked = true;
        }

        if ( ! $blocked && ! empty( $this->options['check_email'] ) && ! empty( $email ) && $this->api->is_spam( $result, 'email' ) ) {
            $blocked = true;
        }

        if ( $blocked ) {
            $author = isset( $commentdata['comment_author'] ) ? $commentdata['comment_author'] : '';
            $this->log_attempt( $ip, $email, $author, 'comment', $result, 'blocked', 'comment' );
            wp_die(
                esc_html__( 'Il tuo commento è stato bloccato per motivi di sicurezza.', 'antispam' ),
                esc_html__( 'Commento bloccato', 'antispam' ),
                array( 'response' => 403, 'back_link' => true )
            );
        }

        return $commentdata;
    }

    /**
     * Registra un tentativo nel log
     */
    public function log_attempt( $ip, $email, $username, $type, $result, $action, $source = '' ) {
        if ( empty( $this->options['log_enabled'] ) ) {
            return;
        }

        global $wpdb;
        $table_name = $wpdb->prefix . 'asg_logs';

        $frequency  = 0;
        $confidence = 0;

        if ( is_array( $result ) && isset( $result[ $type ] ) ) {
            $frequency  = isset( $result[ $type ]['frequency'] )  ? intval( $result[ $type ]['frequency'] )   : 0;
            $confidence = isset( $result[ $type ]['confidence'] ) ? floatval( $result[ $type ]['confidence'] ) : 0;
        }

        $user_agent = isset( $_SERVER['HTTP_USER_AGENT'] )
            ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) )
            : '';

        $wpdb->insert(
            $table_name,
            array(
                'ip_address' => $ip,
                'email'      => $email,
                'username'   => $username,
                'type'       => $type,
                'frequency'  => $frequency,
                'confidence' => $confidence,
                'action'     => $action,
                'source'     => $source,
                'user_agent' => $user_agent,
            ),
            array( '%s', '%s', '%s', '%s', '%d', '%f', '%s', '%s', '%s' )
        );
    }

    /**
     * Restituisce true se la tabella dei log esiste nel DB.
     */
    private static function table_exists() {
        global $wpdb;
        $table_name = $wpdb->prefix . 'asg_logs';
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery
        return $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table_name ) ) === $table_name;
    }

    public static function get_logs( $per_page = 20, $page = 1 ) {
        if ( ! self::table_exists() ) {
            return array();
        }

        global $wpdb;
        $table_name = $wpdb->prefix . 'asg_logs';
        $offset     = ( $page - 1 ) * $per_page;

        return $wpdb->get_results(
            $wpdb->prepare(
                "SELECT * FROM {$table_name} ORDER BY timestamp DESC LIMIT %d OFFSET %d",
                $per_page,
                $offset
            )
        );
    }

    /**
     * Conta il totale dei log
     */
    public static function count_logs() {
        if ( ! self::table_exists() ) {
            return 0;
        }

        global $wpdb;
        $table_name = $wpdb->prefix . 'asg_logs';
        return (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table_name}" );
    }

    /**
     * Svuota i log
     */
    public static function clear_logs() {
        if ( ! self::table_exists() ) {
            return;
        }

        global $wpdb;
        $table_name = $wpdb->prefix . 'asg_logs';
        $wpdb->query( "TRUNCATE TABLE {$table_name}" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
    }
}
