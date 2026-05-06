<?php
/**
 * Protezione Brute Force per il login WordPress
 *
 * Logica:
 *  - Conta i tentativi falliti per IP e per username separatamente.
 *  - Se uno dei due supera la soglia configurata → lockout temporaneo.
 *  - Il lockout scala esponenzialmente: ogni blocco raddoppia il tempo
 *    (base configurabile, default 15 min), fino a un massimo configurabile.
 *  - Il lockout è memorizzato in transient WordPress (nessuna tabella extra).
 *  - L'admin può sbloccare manualmente da "Log Attività".
 *  - I tentativi falliti vengono loggati nella tabella asg_logs.
 *  - Notifica email all'admin al primo lockout.
 *
 * @package AntiSpam
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class ASG_BruteForce {

    // Prefissi transient
    const TRANSIENT_ATTEMPTS_IP   = 'asg_bf_attempts_ip_';
    const TRANSIENT_ATTEMPTS_USER = 'asg_bf_attempts_user_';
    const TRANSIENT_LOCKOUT_IP    = 'asg_bf_lockout_ip_';
    const TRANSIENT_LOCKOUT_USER  = 'asg_bf_lockout_user_';
    const TRANSIENT_COUNT_IP      = 'asg_bf_lockcount_ip_';
    const TRANSIENT_COUNT_USER    = 'asg_bf_lockcount_user_';

    private $options;

    public function __construct() {
        $this->options = get_option( 'asg_settings', array() );
        $this->set_hooks();
    }

    private function set_hooks() {
        if ( empty( $this->options['enabled'] ) || empty( $this->options['bf_enabled'] ) ) {
            return;
        }

        // Intercetta prima di authenticate (priorità 20, prima di ASG_Security che è 30)
        add_filter( 'authenticate',       array( $this, 'check_lockout' ),        20, 3 );

        // Registra il fallimento dopo che WP ha tentato l'autenticazione
        add_action( 'wp_login_failed',    array( $this, 'on_login_failed' ),       10, 2 );

        // Pulisce il contatore dopo un login riuscito
        add_action( 'wp_login',           array( $this, 'on_login_success' ),      10, 2 );

        // Endpoint AJAX per sblocco manuale (admin)
        add_action( 'wp_ajax_asg_unlock', array( $this, 'ajax_unlock' ) );
    }

    /* ------------------------------------------------------------------ *
     *  Recupero soglie dalle opzioni
     * ------------------------------------------------------------------ */

    private function max_attempts() {
        return max( 1, intval( $this->options['bf_max_attempts'] ?? 5 ) );
    }

    private function lockout_base_seconds() {
        return max( 60, intval( $this->options['bf_lockout_duration'] ?? 900 ) );
    }

    private function lockout_max_seconds() {
        return max( $this->lockout_base_seconds(), intval( $this->options['bf_lockout_max'] ?? 86400 ) );
    }

    private function window_seconds() {
        return max( 60, intval( $this->options['bf_window'] ?? 600 ) );
    }

    /* ------------------------------------------------------------------ *
     *  Chiavi transient
     * ------------------------------------------------------------------ */

    private function key_attempts_ip( $ip ) {
        return self::TRANSIENT_ATTEMPTS_IP . md5( $ip );
    }

    private function key_attempts_user( $username ) {
        return self::TRANSIENT_ATTEMPTS_USER . md5( strtolower( $username ) );
    }

    private function key_lockout_ip( $ip ) {
        return self::TRANSIENT_LOCKOUT_IP . md5( $ip );
    }

    private function key_lockout_user( $username ) {
        return self::TRANSIENT_LOCKOUT_USER . md5( strtolower( $username ) );
    }

    private function key_count_ip( $ip ) {
        return self::TRANSIENT_COUNT_IP . md5( $ip );
    }

    private function key_count_user( $username ) {
        return self::TRANSIENT_COUNT_USER . md5( strtolower( $username ) );
    }

    /* ------------------------------------------------------------------ *
     *  Filtro authenticate — blocca se in lockout
     * ------------------------------------------------------------------ */

    public function check_lockout( $user, $username, $password ) {
        if ( empty( $username ) || empty( $password ) ) {
            return $user;
        }

        $ip = $this->get_ip();

        $lockout_ip   = get_transient( $this->key_lockout_ip( $ip ) );
        $lockout_user = get_transient( $this->key_lockout_user( $username ) );

        if ( false !== $lockout_ip || false !== $lockout_user ) {
            // Determina il tempo rimanente più lungo tra i due lockout
            $remaining = 0;
            if ( false !== $lockout_ip ) {
                $remaining = max( $remaining, $lockout_ip - time() );
            }
            if ( false !== $lockout_user ) {
                $remaining = max( $remaining, $lockout_user - time() );
            }
            $remaining = max( 0, $remaining );
            $minutes   = ceil( $remaining / 60 );

            $this->log_bf_attempt( $ip, $username, 'lockout_blocked' );

            return new WP_Error(
                'asg_brute_force_blocked',
                sprintf(
                    /* translators: %d = minuti rimanenti */
                    _n(
                        '<strong>Accesso temporaneamente bloccato</strong>. Troppi tentativi falliti. Riprova tra %d minuto.',
                        '<strong>Accesso temporaneamente bloccato</strong>. Troppi tentativi falliti. Riprova tra %d minuti.',
                        $minutes,
                        'antispam'
                    ),
                    $minutes
                )
            );
        }

        return $user;
    }

    /* ------------------------------------------------------------------ *
     *  Azione wp_login_failed — incrementa contatori
     * ------------------------------------------------------------------ */

    public function on_login_failed( $username, $error ) {
        $ip = $this->get_ip();

        // Incrementa tentativi per IP
        $attempts_ip = $this->increment_attempts( $this->key_attempts_ip( $ip ) );

        // Incrementa tentativi per username
        $attempts_user = $this->increment_attempts( $this->key_attempts_user( $username ) );

        $max = $this->max_attempts();

        $locked_ip   = false;
        $locked_user = false;

        if ( $attempts_ip >= $max ) {
            $duration = $this->compute_lockout_duration( $this->key_count_ip( $ip ) );
            set_transient( $this->key_lockout_ip( $ip ), time() + $duration, $duration );
            delete_transient( $this->key_attempts_ip( $ip ) );
            $locked_ip = true;
            $this->log_bf_attempt( $ip, $username, 'lockout_ip', $duration );
            $this->maybe_notify_admin( $ip, $username, 'ip', $attempts_ip, $duration );
        }

        if ( $attempts_user >= $max ) {
            $duration = $this->compute_lockout_duration( $this->key_count_user( $username ) );
            set_transient( $this->key_lockout_user( $username ), time() + $duration, $duration );
            delete_transient( $this->key_attempts_user( $username ) );
            $locked_user = true;
            $this->log_bf_attempt( $ip, $username, 'lockout_user', $duration );
            if ( ! $locked_ip ) {
                $this->maybe_notify_admin( $ip, $username, 'username', $attempts_user, $duration );
            }
        }

        if ( ! $locked_ip && ! $locked_user ) {
            $this->log_bf_attempt( $ip, $username, 'failed' );
        }
    }

    /* ------------------------------------------------------------------ *
     *  Azione wp_login — reset contatori
     * ------------------------------------------------------------------ */

    public function on_login_success( $username, $user ) {
        $ip = $this->get_ip();
        delete_transient( $this->key_attempts_ip( $ip ) );
        delete_transient( $this->key_attempts_user( $username ) );
        // Non azzeriamo il lock-count: un lockout avvenuto resta nella storia
    }

    /* ------------------------------------------------------------------ *
     *  Helpers
     * ------------------------------------------------------------------ */

    /**
     * Incrementa il contatore di tentativi e lo rinfresca nel transient.
     */
    private function increment_attempts( $key ) {
        $current = get_transient( $key );
        $count   = ( false === $current ) ? 1 : intval( $current ) + 1;
        set_transient( $key, $count, $this->window_seconds() );
        return $count;
    }

    /**
     * Calcola la durata del lockout con backoff esponenziale.
     * Ogni volta che un IP/username viene bloccato, la durata raddoppia.
     */
    private function compute_lockout_duration( $count_key ) {
        $lock_count = get_transient( $count_key );
        $lock_count = ( false === $lock_count ) ? 0 : intval( $lock_count );
        $lock_count++;

        $duration = min(
            $this->lockout_base_seconds() * ( 2 ** ( $lock_count - 1 ) ),
            $this->lockout_max_seconds()
        );

        // Il contatore lockout non scade: persiste fino al ripristino manuale
        set_transient( $count_key, $lock_count, $this->lockout_max_seconds() * 10 );

        return (int) $duration;
    }

    private function get_ip() {
        // Riutilizza il metodo di ASG_API se disponibile, altrimenti fallback diretto
        if ( class_exists( 'ASG_API' ) ) {
            $api = new ASG_API();
            return $api->get_visitor_ip();
        }
        return isset( $_SERVER['REMOTE_ADDR'] )
            ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) )
            : '0.0.0.0';
    }

    /**
     * Notifica email all'admin al primo lockout
     */
    private function maybe_notify_admin( $ip, $username, $type, $attempts, $duration_seconds ) {
        if ( empty( $this->options['bf_notify_admin'] ) ) {
            return;
        }

        $minutes = ceil( $duration_seconds / 60 );
        $subject = sprintf(
            __( 'Possibile attacco brute force su %s', 'antispam' ),
            get_bloginfo( 'name' )
        );
        $message = sprintf(
            /* translators: %1$s IP, %2$s username, %3$s tipo, %4$d tentativi, %5$d minuti, %6$s url sito */
            __(
                "AntiSpam Guard ha rilevato un possibile attacco brute force.\n\n" .
                "IP: %1\$s\nUsername: %2\$s\nTipo blocco: %3\$s\nTentativi: %4\$d\n" .
                "Durata blocco: %5\$d minuti\n\nSito: %6\$s\n\n" .
                "Puoi sbloccare manualmente dalla pagina Log Attività del plugin.",
                'antispam'
            ),
            $ip,
            $username,
            $type,
            $attempts,
            $minutes,
            get_bloginfo( 'url' )
        );

        ASG_Admin::notify_admin( $subject, $message );
    }

    /**
     * Log nella tabella asg_logs
     */
    private function log_bf_attempt( $ip, $username, $action, $duration = 0 ) {
        if ( empty( $this->options['log_enabled'] ) ) {
            return;
        }

        if ( ! ASG_Security::table_exists_public() ) {
            return;
        }

        global $wpdb;
        $table_name = $wpdb->prefix . 'asg_logs';

        $user_agent = isset( $_SERVER['HTTP_USER_AGENT'] )
            ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) )
            : '';

        $wpdb->insert(
            $table_name,
            array(
                'ip_address' => $ip,
                'email'      => '',
                'username'   => $username,
                'type'       => 'brute_force',
                'frequency'  => $duration > 0 ? (int) ceil( $duration / 60 ) : 0,
                'confidence' => 0,
                'action'     => $action,
                'source'     => 'login',
                'user_agent' => $user_agent,
            ),
            array( '%s', '%s', '%s', '%s', '%d', '%f', '%s', '%s', '%s' )
        );
    }

    /* ------------------------------------------------------------------ *
     *  Sblocco manuale via AJAX (admin)
     * ------------------------------------------------------------------ */

    public function ajax_unlock() {
        check_ajax_referer( 'asg_unlock_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( array( 'message' => __( 'Permesso negato.', 'antispam' ) ) );
        }

        $type  = isset( $_POST['lock_type'] ) ? sanitize_text_field( wp_unslash( $_POST['lock_type'] ) ) : '';
        $value = isset( $_POST['lock_value'] ) ? sanitize_text_field( wp_unslash( $_POST['lock_value'] ) ) : '';

        if ( empty( $type ) || empty( $value ) ) {
            wp_send_json_error( array( 'message' => __( 'Parametri mancanti.', 'antispam' ) ) );
        }

        if ( 'ip' === $type ) {
            delete_transient( $this->key_lockout_ip( $value ) );
            delete_transient( $this->key_attempts_ip( $value ) );
            delete_transient( $this->key_count_ip( $value ) );
        } elseif ( 'username' === $type ) {
            delete_transient( $this->key_lockout_user( $value ) );
            delete_transient( $this->key_attempts_user( $value ) );
            delete_transient( $this->key_count_user( $value ) );
        } else {
            wp_send_json_error( array( 'message' => __( 'Tipo non valido.', 'antispam' ) ) );
        }

        wp_send_json_success( array( 'message' => __( 'Sblocco eseguito.', 'antispam' ) ) );
    }

    /* ------------------------------------------------------------------ *
     *  Metodi statici di utilità (usati dall'admin per mostrare stato)
     * ------------------------------------------------------------------ */

    /**
     * Controlla se un IP è attualmente bloccato e restituisce i secondi rimanenti (0 = libero).
     */
    public static function get_ip_lockout_remaining( $ip ) {
        $expiry = get_transient( self::TRANSIENT_LOCKOUT_IP . md5( $ip ) );
        if ( false === $expiry ) {
            return 0;
        }
        return max( 0, $expiry - time() );
    }

    /**
     * Controlla se uno username è attualmente bloccato e restituisce i secondi rimanenti.
     */
    public static function get_user_lockout_remaining( $username ) {
        $expiry = get_transient( self::TRANSIENT_LOCKOUT_USER . md5( strtolower( $username ) ) );
        if ( false === $expiry ) {
            return 0;
        }
        return max( 0, $expiry - time() );
    }

    /**
     * Restituisce il numero di tentativi correnti per un IP.
     */
    public static function get_ip_attempts( $ip ) {
        $v = get_transient( self::TRANSIENT_ATTEMPTS_IP . md5( $ip ) );
        return false === $v ? 0 : intval( $v );
    }

    /**
     * Restituisce il numero di tentativi correnti per uno username.
     */
    public static function get_user_attempts( $username ) {
        $v = get_transient( self::TRANSIENT_ATTEMPTS_USER . md5( strtolower( $username ) ) );
        return false === $v ? 0 : intval( $v );
    }
}
