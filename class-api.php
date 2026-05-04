<?php
/**
 * Classe per l'integrazione con API
 * 
 * @package AntiSpam
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class ASG_API {

    private $api_url = 'https://api.stopforumspam.org/api';
    private $options;

    public function __construct() {
        $this->options = get_option( 'asg_settings', array() );
    }

    public function check_ip( $ip ) {
        if ( ! $this->is_valid_ip( $ip ) ) {
            return new WP_Error( 'invalid_ip', __( 'Indirizzo IP non valido.', 'antispam' ) );
        }

        $cache_key = 'asg_ip_' . md5( $ip );
        $cached_result = get_transient( $cache_key );

        if ( false !== $cached_result ) {
            return $cached_result;
        }

        $params = array(
            'ip'         => $ip,
            'json'       => '1',
            'confidence' => '1',
        );

        $result = $this->make_request( $params );

        if ( is_wp_error( $result ) ) {
            return $result;
        }

        $cache_duration = isset( $this->options['cache_duration'] ) ? intval( $this->options['cache_duration'] ) : 3600;
        set_transient( $cache_key, $result, $cache_duration );

        return $result;
    }

    public function check_email( $email ) {
        if ( ! is_email( $email ) ) {
            return new WP_Error( 'invalid_email', __( 'Indirizzo email non valido.', 'antispam' ) );
        }

        $cache_key = 'asg_email_' . md5( $email );
        $cached_result = get_transient( $cache_key );

        if ( false !== $cached_result ) {
            return $cached_result;
        }

        $params = array(
            'email'      => $email,
            'json'       => '1',
            'confidence' => '1',
        );

        $result = $this->make_request( $params );

        if ( is_wp_error( $result ) ) {
            return $result;
        }

        $cache_duration = isset( $this->options['cache_duration'] ) ? intval( $this->options['cache_duration'] ) : 3600;
        set_transient( $cache_key, $result, $cache_duration );

        return $result;
    }

    public function check_username( $username ) {
        $username = sanitize_text_field( $username );

        if ( empty( $username ) ) {
            return new WP_Error( 'invalid_username', __( 'Username non valido.', 'antispam' ) );
        }

        $cache_key = 'asg_username_' . md5( $username );
        $cached_result = get_transient( $cache_key );

        if ( false !== $cached_result ) {
            return $cached_result;
        }

        $params = array(
            'username'   => $username,
            'json'       => '1',
            'confidence' => '1',
        );

        $result = $this->make_request( $params );

        if ( is_wp_error( $result ) ) {
            return $result;
        }

        $cache_duration = isset( $this->options['cache_duration'] ) ? intval( $this->options['cache_duration'] ) : 3600;
        set_transient( $cache_key, $result, $cache_duration );

        return $result;
    }

    public function check_multiple( $data ) {
        $params = array( 'json' => '1', 'confidence' => '1' );

        if ( ! empty( $data['ip'] ) && $this->is_valid_ip( $data['ip'] ) ) {
            $params['ip'] = $data['ip'];
        }

        if ( ! empty( $data['email'] ) && is_email( $data['email'] ) ) {
            $params['email'] = $data['email'];
        }

        if ( ! empty( $data['username'] ) ) {
            $params['username'] = sanitize_text_field( $data['username'] );
        }

        if ( count( $params ) <= 2 ) {
            return new WP_Error( 'no_data', __( 'Nessun dato valido fornito per la verifica.', 'antispam' ) );
        }

        return $this->make_request( $params );
    }

    private function make_request( $params ) {
        $url = add_query_arg( $params, $this->api_url );

        $args = array(
            'timeout'     => 10,
            'redirection' => 5,
            'httpversion' => '1.1',
            'user-agent'  => 'AntiSpam/' . OSTAP_ASG_VERSION . '; ' . get_bloginfo( 'url' ),
        );

        $response = wp_remote_get( $url, $args );

        if ( is_wp_error( $response ) ) {
            return $response;
        }

        $response_code = wp_remote_retrieve_response_code( $response );

        if ( 200 !== $response_code ) {
            return new WP_Error( 
                'api_error', 
                sprintf( __( 'Errore API StopForumSpam: codice HTTP %d', 'antispam' ), $response_code ) 
            );
        }

        $body = wp_remote_retrieve_body( $response );
        $data = json_decode( $body, true );

        if ( json_last_error() !== JSON_ERROR_NONE ) {
            return new WP_Error( 'json_error', __( 'Errore nel parsing della risposta JSON.', 'antispam' ) );
        }

        if ( isset( $data['success'] ) && $data['success'] !== 1 ) {
            return new WP_Error( 'api_error', __( 'Richiesta API non riuscita.', 'antispam' ) );
        }

        return $data;
    }

    private function is_valid_ip( $ip ) {
        return filter_var( $ip, FILTER_VALIDATE_IP ) !== false;
    }

    public function get_visitor_ip() {
        $ip_keys = array( 'HTTP_CF_CONNECTING_IP', 'HTTP_CLIENT_IP', 'HTTP_X_FORWARDED_FOR', 'REMOTE_ADDR' );

        foreach ( $ip_keys as $key ) {
            if ( ! empty( $_SERVER[ $key ] ) ) {
                $ip = sanitize_text_field( wp_unslash( $_SERVER[ $key ] ) );

                if ( 'HTTP_X_FORWARDED_FOR' === $key && strpos( $ip, ',' ) !== false ) {
                    $ips = explode( ',', $ip );
                    $ip = trim( $ips[0] );
                }

                if ( $this->is_valid_ip( $ip ) ) {
                    return $ip;
                }
            }
        }

        return '0.0.0.0';
    }

    public function is_spam( $result, $type = 'ip' ) {
        if ( is_wp_error( $result ) || ! isset( $result[ $type ] ) ) {
            return false;
        }

        $data = $result[ $type ];
        $frequency_threshold = isset( $this->options['frequency_threshold'] ) ? intval( $this->options['frequency_threshold'] ) : 1;
        $confidence_threshold = isset( $this->options['confidence_threshold'] ) ? floatval( $this->options['confidence_threshold'] ) : 50;

        if ( isset( $data['frequency'] ) && intval( $data['frequency'] ) >= $frequency_threshold ) {
            return true;
        }

        if ( isset( $data['confidence'] ) && floatval( $data['confidence'] ) >= $confidence_threshold ) {
            return true;
        }

        if ( ! empty( $this->options['block_tor'] ) && isset( $data['torexit'] ) && $data['torexit'] === 1 ) {
            return true;
        }

        return false;
    }
}
