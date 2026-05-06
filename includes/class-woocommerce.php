<?php
/**
 * Classe per l'integrazione con WooCommerce
 *
 * @package AntiSpam
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class ASG_WooCommerce {

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

        // Checkout
        add_action( 'woocommerce_checkout_process',         array( $this, 'check_checkout' ) );

        // Registrazione cliente WooCommerce
        add_filter( 'woocommerce_registration_errors',      array( $this, 'check_wc_registration' ), 10, 3 );

        // Ordine creato (controllo post-checkout)
        add_action( 'woocommerce_checkout_order_created',   array( $this, 'check_order' ) );

        // Dichiarazione compatibilità HPOS
        add_action( 'before_woocommerce_init',              array( $this, 'declare_hpos_compatibility' ) );
    }

    /**
     * Dichiara compatibilità con High Performance Order Storage
     */
    public function declare_hpos_compatibility() {
        if ( class_exists( \Automattic\WooCommerce\Utilities\FeaturesUtil::class ) ) {
            \Automattic\WooCommerce\Utilities\FeaturesUtil::declare_compatibility(
                'custom_order_tables',
                ASG_PLUGIN_DIR . 'antispam.php',
                true
            );
        }
    }

    /**
     * Controlla il processo di checkout
     */
    public function check_checkout() {
        $ip    = $this->api->get_visitor_ip();
        $email = isset( $_POST['billing_email'] )
            ? sanitize_email( wp_unslash( $_POST['billing_email'] ) )
            : '';

        $data = array();

        if ( ! empty( $this->options['check_ip'] ) ) {
            $data['ip'] = $ip;
        }

        if ( ! empty( $this->options['check_email'] ) && ! empty( $email ) ) {
            $data['email'] = $email;
        }

        if ( empty( $data ) ) {
            return;
        }

        $result = $this->api->check_multiple( $data );

        if ( is_wp_error( $result ) ) {
            return;
        }

        $blocked = false;
        $reason  = '';

        if ( ! empty( $data['ip'] ) && $this->api->is_spam( $result, 'ip' ) ) {
            $blocked = true;
            $reason  = 'ip';
        }

        if ( ! $blocked && ! empty( $data['email'] ) && $this->api->is_spam( $result, 'email' ) ) {
            $blocked = true;
            $reason  = 'email';
        }

        if ( $blocked ) {
            $this->log_wc_attempt( $ip, $email, '', $reason, $result, 'blocked', 'checkout' );
            $this->maybe_notify_admin_checkout( $ip, $email, $reason );
            wc_add_notice(
                __( 'Il tuo ordine non può essere completato per motivi di sicurezza. Contatta il supporto se ritieni sia un errore.', 'antispam' ),
                'error'
            );
        }
    }

    /**
     * Controlla la registrazione cliente WooCommerce
     */
    public function check_wc_registration( $validation_error, $username, $email ) {
        $ip = $this->api->get_visitor_ip();

        $data = array(
            'ip'    => $ip,
            'email' => $email,
        );

        if ( ! empty( $this->options['check_username'] ) ) {
            $data['username'] = $username;
        }

        $result = $this->api->check_multiple( $data );

        if ( is_wp_error( $result ) ) {
            return $validation_error;
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
            $this->log_wc_attempt( $ip, $email, $username, $reason, $result, 'blocked', 'wc_registration' );
            return new WP_Error(
                'asg_spam_blocked',
                __( 'Registrazione bloccata per motivi di sicurezza.', 'antispam' )
            );
        }

        return $validation_error;
    }

    /**
     * Controlla l'ordine appena creato
     */
    public function check_order( $order ) {
        if ( ! $order instanceof WC_Order ) {
            return;
        }

        $ip    = $this->api->get_visitor_ip();
        $email = $order->get_billing_email();

        $data = array();

        if ( ! empty( $this->options['check_ip'] ) ) {
            $data['ip'] = $ip;
        }

        if ( ! empty( $this->options['check_email'] ) && ! empty( $email ) ) {
            $data['email'] = $email;
        }

        if ( empty( $data ) ) {
            return;
        }

        $result = $this->api->check_multiple( $data );

        if ( is_wp_error( $result ) ) {
            return;
        }

        $blocked = false;
        $reason  = '';

        if ( ! empty( $data['ip'] ) && $this->api->is_spam( $result, 'ip' ) ) {
            $blocked = true;
            $reason  = 'ip';
        }

        if ( ! $blocked && ! empty( $data['email'] ) && $this->api->is_spam( $result, 'email' ) ) {
            $blocked = true;
            $reason  = 'email';
        }

        if ( $blocked ) {
            $order->update_status(
                'on-hold',
                sprintf(
                    __( '[AntiSpam] Ordine messo in attesa: %s rilevato come spam.', 'antispam' ),
                    $reason
                )
            );

            $this->log_wc_attempt( $ip, $email, '', $reason, $result, 'on-hold', 'order' );
            $this->maybe_notify_admin_order( $order, $ip, $email, $reason );
        }
    }

    /**
     * Notifica admin per checkout bloccato
     */
    private function maybe_notify_admin_checkout( $ip, $email, $reason ) {
        $message = sprintf(
            __( "Checkout bloccato da AntiSpam.\n\nIP: %s\nEmail: %s\nMotivo: %s\n\nSito: %s", 'antispam' ),
            $ip,
            $email,
            $reason,
            get_bloginfo( 'url' )
        );

        ASG_Admin::notify_admin(
            __( 'Checkout bloccato da AntiSpam', 'antispam' ),
            $message
        );
    }

    /**
     * Notifica admin per ordine messo in attesa
     */
    private function maybe_notify_admin_order( $order, $ip, $email, $reason ) {
        $order_url = admin_url( 'post.php?post=' . $order->get_id() . '&action=edit' );

        $message = sprintf(
            __( "Un ordine è stato messo in attesa da AntiSpam.\n\nOrdine #%d\nIP: %s\nEmail: %s\nMotivo: %s\n\nVisualizza ordine: %s", 'antispam' ),
            $order->get_id(),
            $ip,
            $email,
            $reason,
            $order_url
        );

        ASG_Admin::notify_admin(
            sprintf( __( 'Ordine #%d messo in attesa da AntiSpam', 'antispam' ), $order->get_id() ),
            $message
        );
    }

    /**
     * Log degli eventi WooCommerce (delega a ASG_Security)
     */
    private function log_wc_attempt( $ip, $email, $username, $type, $result, $action, $source ) {
        $security = new ASG_Security();
        $security->log_attempt( $ip, $email, $username, $type, $result, $action, $source );
    }
}
