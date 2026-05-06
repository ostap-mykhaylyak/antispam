<?php
/**
 * Classe per la gestione dell'area amministrativa
 *
 * @package AntiSpam
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class ASG_Admin {

    private $options;

    public function __construct() {
        $this->options = get_option( 'asg_settings', array() );
        $this->set_hooks();
    }

    private function set_hooks() {
        add_action( 'admin_menu',            array( $this, 'add_menu_pages' ) );
        add_action( 'admin_init',            array( $this, 'register_settings' ) );
        add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_assets' ) );
        add_filter( 'plugin_action_links_' . ASG_PLUGIN_BASENAME, array( $this, 'add_action_links' ) );
        add_action( 'admin_post_asg_clear_logs', array( $this, 'handle_clear_logs' ) );
    }

    public function add_menu_pages() {
        add_menu_page(
            __( 'AntiSpam Guard', 'antispam' ),
            __( 'AntiSpam Guard', 'antispam' ),
            'manage_options',
            'antispam-guard',
            array( $this, 'render_settings_page' ),
            'dashicons-shield',
            80
        );

        add_submenu_page(
            'antispam-guard',
            __( 'Impostazioni', 'antispam' ),
            __( 'Impostazioni', 'antispam' ),
            'manage_options',
            'antispam-guard',
            array( $this, 'render_settings_page' )
        );

        add_submenu_page(
            'antispam-guard',
            __( 'Log Attività', 'antispam' ),
            __( 'Log Attività', 'antispam' ),
            'manage_options',
            'antispam-guard-logs',
            array( $this, 'render_logs_page' )
        );
    }

    public function register_settings() {
        register_setting(
            'asg_settings_group',
            'asg_settings',
            array( $this, 'sanitize_settings' )
        );

        // Sezione generale
        add_settings_section(
            'asg_general',
            __( 'Impostazioni Generali', 'antispam' ),
            '__return_false',
            'antispam-guard'
        );

        $general_fields = array(
            'enabled'       => __( 'Abilita Plugin', 'antispam' ),
            'check_ip'      => __( 'Verifica IP', 'antispam' ),
            'check_email'   => __( 'Verifica Email', 'antispam' ),
            'check_username'=> __( 'Verifica Username', 'antispam' ),
            'block_tor'     => __( 'Blocca Nodi Tor', 'antispam' ),
            'log_enabled'   => __( 'Abilita Logging', 'antispam' ),
        );

        foreach ( $general_fields as $id => $label ) {
            add_settings_field(
                'asg_' . $id,
                $label,
                array( $this, 'render_checkbox_field' ),
                'antispam-guard',
                'asg_general',
                array( 'id' => $id )
            );
        }

        // Sezione soglie
        add_settings_section(
            'asg_thresholds',
            __( 'Soglie di Blocco', 'antispam' ),
            '__return_false',
            'antispam-guard'
        );

        add_settings_field(
            'asg_frequency_threshold',
            __( 'Soglia Frequenza', 'antispam' ),
            array( $this, 'render_number_field' ),
            'antispam-guard',
            'asg_thresholds',
            array( 'id' => 'frequency_threshold', 'min' => 1, 'max' => 1000,
                   'desc' => __( 'Numero minimo di segnalazioni per bloccare (default: 1)', 'antispam' ) )
        );

        add_settings_field(
            'asg_confidence_threshold',
            __( 'Soglia Confidence Score', 'antispam' ),
            array( $this, 'render_number_field' ),
            'antispam-guard',
            'asg_thresholds',
            array( 'id' => 'confidence_threshold', 'min' => 0, 'max' => 100,
                   'desc' => __( 'Score minimo (0–100) per bloccare (default: 50)', 'antispam' ) )
        );

        add_settings_field(
            'asg_cache_duration',
            __( 'Durata Cache (secondi)', 'antispam' ),
            array( $this, 'render_number_field' ),
            'antispam-guard',
            'asg_thresholds',
            array( 'id' => 'cache_duration', 'min' => 60, 'max' => 86400,
                   'desc' => __( 'Tempo di cache dei risultati API (default: 3600)', 'antispam' ) )
        );

        // Sezione Brute Force
        add_settings_section(
            'asg_bruteforce',
            __( 'Protezione Brute Force', 'antispam' ),
            array( $this, 'render_bf_section_desc' ),
            'antispam-guard'
        );

        add_settings_field(
            'asg_bf_enabled',
            __( 'Abilita protezione brute force', 'antispam' ),
            array( $this, 'render_checkbox_field' ),
            'antispam-guard',
            'asg_bruteforce',
            array( 'id' => 'bf_enabled' )
        );

        add_settings_field(
            'asg_bf_notify_admin',
            __( 'Notifica admin al lockout', 'antispam' ),
            array( $this, 'render_checkbox_field' ),
            'antispam-guard',
            'asg_bruteforce',
            array( 'id' => 'bf_notify_admin' )
        );

        add_settings_field(
            'asg_bf_max_attempts',
            __( 'Tentativi prima del blocco', 'antispam' ),
            array( $this, 'render_number_field' ),
            'antispam-guard',
            'asg_bruteforce',
            array( 'id' => 'bf_max_attempts', 'min' => 1, 'max' => 100,
                   'desc' => __( 'Numero di tentativi falliti prima di bloccare IP o username (default: 5)', 'antispam' ) )
        );

        add_settings_field(
            'asg_bf_window',
            __( 'Finestra di osservazione (secondi)', 'antispam' ),
            array( $this, 'render_number_field' ),
            'antispam-guard',
            'asg_bruteforce',
            array( 'id' => 'bf_window', 'min' => 60, 'max' => 3600,
                   'desc' => __( 'Intervallo in cui vengono contati i tentativi (default: 600 = 10 min)', 'antispam' ) )
        );

        add_settings_field(
            'asg_bf_lockout_duration',
            __( 'Durata lockout base (secondi)', 'antispam' ),
            array( $this, 'render_number_field' ),
            'antispam-guard',
            'asg_bruteforce',
            array( 'id' => 'bf_lockout_duration', 'min' => 60, 'max' => 86400,
                   'desc' => __( 'Durata del primo blocco. Raddoppia ad ogni recidiva (default: 900 = 15 min)', 'antispam' ) )
        );

        add_settings_field(
            'asg_bf_lockout_max',
            __( 'Durata lockout massima (secondi)', 'antispam' ),
            array( $this, 'render_number_field' ),
            'antispam-guard',
            'asg_bruteforce',
            array( 'id' => 'bf_lockout_max', 'min' => 900, 'max' => 604800,
                   'desc' => __( 'Tetto massimo del lockout esponenziale (default: 86400 = 24 ore)', 'antispam' ) )
        );
    }

    public function render_bf_section_desc() {
        echo '<p>' . esc_html__( 'Blocca automaticamente IP e username dopo troppi tentativi di login falliti. Il lockout scala esponenzialmente: ogni recidiva raddoppia la durata del blocco.', 'antispam' ) . '</p>';
    }

    public function sanitize_settings( $input ) {
        $sanitized = array();

        $booleans = array( 'enabled', 'check_ip', 'check_email', 'check_username', 'block_tor', 'log_enabled' );
        foreach ( $booleans as $key ) {
            $sanitized[ $key ] = ! empty( $input[ $key ] );
        }

        $sanitized['frequency_threshold']  = max( 1, intval( $input['frequency_threshold'] ?? 1 ) );
        $sanitized['confidence_threshold']  = min( 100, max( 0, floatval( $input['confidence_threshold'] ?? 50 ) ) );
        $sanitized['cache_duration']        = max( 60, intval( $input['cache_duration'] ?? 3600 ) );

        // Brute force
        $bf_booleans = array( 'bf_enabled', 'bf_notify_admin' );
        foreach ( $bf_booleans as $key ) {
            $sanitized[ $key ] = ! empty( $input[ $key ] );
        }
        $sanitized['bf_max_attempts']     = max( 1,   intval( $input['bf_max_attempts']     ?? 5 ) );
        $sanitized['bf_window']           = max( 60,  intval( $input['bf_window']           ?? 600 ) );
        $sanitized['bf_lockout_duration'] = max( 60,  intval( $input['bf_lockout_duration'] ?? 900 ) );
        $sanitized['bf_lockout_max']      = max( 900, intval( $input['bf_lockout_max']      ?? 86400 ) );

        return $sanitized;
    }

    public function render_checkbox_field( $args ) {
        $id      = $args['id'];
        $checked = ! empty( $this->options[ $id ] ) ? 'checked' : '';
        printf(
            '<input type="checkbox" id="asg_%1$s" name="asg_settings[%1$s]" value="1" %2$s>',
            esc_attr( $id ),
            $checked
        );
    }

    public function render_number_field( $args ) {
        $id    = $args['id'];
        $min   = $args['min'] ?? 0;
        $max   = $args['max'] ?? 9999;
        $desc  = $args['desc'] ?? '';
        $value = isset( $this->options[ $id ] ) ? $this->options[ $id ] : '';
        printf(
            '<input type="number" id="asg_%1$s" name="asg_settings[%1$s]" value="%2$s" min="%3$s" max="%4$s" class="small-text">',
            esc_attr( $id ),
            esc_attr( $value ),
            esc_attr( $min ),
            esc_attr( $max )
        );
        if ( $desc ) {
            echo '<p class="description">' . esc_html( $desc ) . '</p>';
        }
    }

    public function render_settings_page() {
        if ( ! current_user_can( 'manage_options' ) ) {
            return;
        }
        ?>
        <div class="wrap">
            <h1><?php esc_html_e( 'AntiSpam Guard — Impostazioni', 'antispam' ); ?></h1>
            <form method="post" action="options.php">
                <?php
                settings_fields( 'asg_settings_group' );
                do_settings_sections( 'antispam-guard' );
                submit_button();
                ?>
            </form>
        </div>
        <?php
    }

    public function render_logs_page() {
        if ( ! current_user_can( 'manage_options' ) ) {
            return;
        }

        $per_page    = 20;
        $current_page = max( 1, isset( $_GET['paged'] ) ? intval( $_GET['paged'] ) : 1 );
        $logs        = ASG_Security::get_logs( $per_page, $current_page );
        $total       = ASG_Security::count_logs();
        $total_pages = ceil( $total / $per_page );

        ?>
        <div class="wrap">
            <h1><?php esc_html_e( 'AntiSpam Guard — Log Attività', 'antispam' ); ?></h1>

            <form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin-bottom:16px;">
                <input type="hidden" name="action" value="asg_clear_logs">
                <?php wp_nonce_field( 'asg_clear_logs_nonce' ); ?>
                <?php submit_button( __( 'Svuota Log', 'antispam' ), 'delete', 'submit', false ); ?>
            </form>

            <?php if ( ! empty( $_GET['cleared'] ) ) : ?>
                <div class="notice notice-success is-dismissible"><p><?php esc_html_e( 'Log svuotato con successo.', 'antispam' ); ?></p></div>
            <?php endif; ?>

            <div style="background:#fff;border:1px solid #ccd0d4;padding:16px 20px;margin-bottom:20px;max-width:560px;">
                <h2 style="margin-top:0;"><?php esc_html_e( 'Sblocco Manuale Brute Force', 'antispam' ); ?></h2>
                <p><?php esc_html_e( 'Inserisci un IP o uno username per rimuoverne il lockout brute force.', 'antispam' ); ?></p>
                <div style="display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end;">
                    <div>
                        <label for="asg-unlock-type"><strong><?php esc_html_e( 'Tipo', 'antispam' ); ?></strong></label><br>
                        <select id="asg-unlock-type" style="height:30px;">
                            <option value="ip"><?php esc_html_e( 'IP', 'antispam' ); ?></option>
                            <option value="username"><?php esc_html_e( 'Username', 'antispam' ); ?></option>
                        </select>
                    </div>
                    <div>
                        <label for="asg-unlock-value"><strong><?php esc_html_e( 'Valore', 'antispam' ); ?></strong></label><br>
                        <input type="text" id="asg-unlock-value" style="width:240px;" placeholder="es. 192.168.1.1">
                    </div>
                    <div>
                        <button id="asg-unlock-btn" class="button button-primary"><?php esc_html_e( 'Sblocca', 'antispam' ); ?></button>
                    </div>
                </div>
                <p id="asg-unlock-msg" style="margin-top:10px;font-weight:bold;"></p>
            </div>

            <p><?php printf( esc_html__( 'Totale: %d voci', 'antispam' ), $total ); ?></p>

            <table class="widefat fixed striped">
                <thead>
                    <tr>
                        <th><?php esc_html_e( 'Data', 'antispam' ); ?></th>
                        <th><?php esc_html_e( 'IP', 'antispam' ); ?></th>
                        <th><?php esc_html_e( 'Email', 'antispam' ); ?></th>
                        <th><?php esc_html_e( 'Username', 'antispam' ); ?></th>
                        <th><?php esc_html_e( 'Tipo', 'antispam' ); ?></th>
                        <th><?php esc_html_e( 'Frequenza', 'antispam' ); ?></th>
                        <th><?php esc_html_e( 'Confidence', 'antispam' ); ?></th>
                        <th><?php esc_html_e( 'Azione', 'antispam' ); ?></th>
                        <th><?php esc_html_e( 'Sorgente', 'antispam' ); ?></th>
                    </tr>
                </thead>
                <tbody>
                <?php if ( empty( $logs ) ) : ?>
                    <tr><td colspan="9"><?php esc_html_e( 'Nessun log disponibile.', 'antispam' ); ?></td></tr>
                <?php else : ?>
                    <?php foreach ( $logs as $log ) : ?>
                        <tr>
                            <td><?php echo esc_html( $log->timestamp ); ?></td>
                            <td><?php echo esc_html( $log->ip_address ); ?></td>
                            <td><?php echo esc_html( $log->email ); ?></td>
                            <td><?php echo esc_html( $log->username ); ?></td>
                            <td><?php echo esc_html( $log->type ); ?></td>
                            <td><?php echo esc_html( $log->frequency ); ?></td>
                            <td><?php echo esc_html( $log->confidence ); ?></td>
                            <td>
                                <?php if ( 'blocked' === $log->action ) : ?>
                                    <span style="color:#cc0000;font-weight:bold;"><?php esc_html_e( 'Bloccato', 'antispam' ); ?></span>
                                <?php else : ?>
                                    <span style="color:#008000;"><?php esc_html_e( 'Consentito', 'antispam' ); ?></span>
                                <?php endif; ?>
                            </td>
                            <td><?php echo esc_html( $log->source ); ?></td>
                        </tr>
                    <?php endforeach; ?>
                <?php endif; ?>
                </tbody>
            </table>

            <?php if ( $total_pages > 1 ) : ?>
                <div class="tablenav bottom">
                    <div class="tablenav-pages">
                        <?php
                        echo paginate_links( array(
                            'base'      => add_query_arg( 'paged', '%#%' ),
                            'format'    => '',
                            'current'   => $current_page,
                            'total'     => $total_pages,
                        ) );
                        ?>
                    </div>
                </div>
            <?php endif; ?>
        </div>
        <script>
        (function(){
            var btn = document.getElementById('asg-unlock-btn');
            if (!btn) return;
            btn.addEventListener('click', function(){
                var type  = document.getElementById('asg-unlock-type').value;
                var value = document.getElementById('asg-unlock-value').value.trim();
                var msg   = document.getElementById('asg-unlock-msg');
                if (!value) { msg.style.color='#cc0000'; msg.textContent = '<?php echo esc_js( __( 'Inserisci un valore.', 'antispam' ) ); ?>'; return; }
                btn.disabled = true;
                msg.style.color = '#555';
                msg.textContent = '<?php echo esc_js( __( 'In corso…', 'antispam' ) ); ?>';
                var data = new URLSearchParams();
                data.append('action', 'asg_unlock');
                data.append('nonce', '<?php echo esc_js( wp_create_nonce( 'asg_unlock_nonce' ) ); ?>');
                data.append('lock_type', type);
                data.append('lock_value', value);
                fetch('<?php echo esc_url( admin_url( 'admin-ajax.php' ) ); ?>', {
                    method: 'POST', body: data
                })
                .then(function(r){ return r.json(); })
                .then(function(res){
                    btn.disabled = false;
                    if (res.success) {
                        msg.style.color = '#008000';
                        msg.textContent = res.data.message;
                        document.getElementById('asg-unlock-value').value = '';
                    } else {
                        msg.style.color = '#cc0000';
                        msg.textContent = res.data.message;
                    }
                })
                .catch(function(){ btn.disabled=false; msg.style.color='#cc0000'; msg.textContent='Errore di rete.'; });
            });
        })();
        </script>
        <?php
    }

    public function handle_clear_logs() {
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_die( esc_html__( 'Permesso negato.', 'antispam' ) );
        }
        check_admin_referer( 'asg_clear_logs_nonce' );
        ASG_Security::clear_logs();

        $redirect_url = add_query_arg(
            array( 'page' => 'antispam-guard-logs', 'cleared' => '1' ),
            admin_url( 'admin.php' )
        );

        // Redirect sicuro: usa l'header HTTP se possibile, altrimenti JS + meta.
        if ( ! headers_sent() ) {
            wp_redirect( $redirect_url );
            exit;
        }

        // Fallback quando l'output è già iniziato (es. errori DB stampati da WordPress).
        printf(
            '<script>window.location.href = %s;</script><noscript><meta http-equiv="refresh" content="0;url=%s"></noscript>',
            wp_json_encode( $redirect_url ),
            esc_url( $redirect_url )
        );
        exit;
    }

    public function enqueue_assets( $hook ) {
        if ( strpos( $hook, 'antispam-guard' ) === false ) {
            return;
        }
        wp_enqueue_style(
            'asg-admin',
            ASG_PLUGIN_URL . 'assets/css/admin.css',
            array(),
            ASG_VERSION
        );
    }

    public function add_action_links( $links ) {
        $settings_link = sprintf(
            '<a href="%s">%s</a>',
            esc_url( admin_url( 'admin.php?page=antispam-guard' ) ),
            esc_html__( 'Impostazioni', 'antispam' )
        );
        array_unshift( $links, $settings_link );
        return $links;
    }

    /**
     * Invia notifica email all'admin quando un'azione viene bloccata
     */
    public static function notify_admin( $subject, $message ) {
        $admin_email = get_option( 'admin_email' );
        $site_name   = get_bloginfo( 'name' );

        wp_mail(
            $admin_email,
            sprintf( '[%s] %s', $site_name, $subject ),
            $message
        );
    }
}
