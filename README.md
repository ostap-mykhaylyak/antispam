=== AntiSpam ===
Contributors: Ostap Mykhaylyak
Tags: spam, antispam, woocommerce, stopforumspam, security
Requires at least: 6.0
Tested up to: 6.7
Requires PHP: 7.4
Stable tag: 1.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Plugin antispam avanzato per WordPress e WooCommerce.

== Description ==

AntiSpam protegge il tuo sito WordPress e il tuo negozio WooCommerce dallo spam.

= Caratteristiche =

* **Verifica IP in tempo reale** - Controlla gli indirizzi IP
* **Verifica Email** - Controlla gli indirizzi email segnalati come spam
* **Verifica Username** - Controlla gli username sospetti
* **Integrazione WooCommerce** - Protegge checkout, registrazioni e ordini
* **Soglie configurabili** - Imposta frequenza e confidence score per il blocco
* **Cache risultati** - Riduce le chiamate API con cache transient
* **Logging completo** - Registra tutti i tentativi per analisi
* **Notifiche admin** - Avvisi email quando ordini vengono bloccati
* **Supporto IPv6** - Compatibile con IPv4 e IPv6
* **Blocca Tor** - Opzione per bloccare nodi di uscita Tor

= Requisiti =

* WordPress 6.0+
* PHP 7.4+
* WooCommerce 8.0+ (opzionale, per funzionalità e-commerce)

== Installation ==

1. Carica i file del plugin in `/wp-content/plugins/antispam`
2. Attiva il plugin dalla schermata 'Plugin' in WordPress
3. Configura le impostazioni in AntiSpam Guard > Impostazioni
4. Per WooCommerce, verifica che l'integrazione sia attiva in Impostazioni

== Frequently Asked Questions ==

= Come funziona la verifica IP? =

Il plugin invia l'indirizzo IP del visitatore all'API e verifica se è presente nel database delle segnalazioni spam.

= Posso configurare le soglie di blocco? =

Sì, puoi impostare la soglia di frequenza (numero di segnalazioni) e il confidence score minimo per bloccare un visitatore.

= Il plugin rallenta il sito? =

No, i risultati delle verifiche vengono messi in cache per il tempo configurato (default 1 ora), riducendo al minimo le chiamate API.

= È compatibile con altri plugin di sicurezza? =

Sì, AntiSpam è progettato per funzionare in modo complementare con altri plugin di sicurezza.

== Changelog ==

= 1.0.0 =
* Rilascio iniziale
* Integrazione API
* Supporto WordPress e WooCommerce
* Sistema di logging
* Notifiche email admin

== Upgrade Notice ==

= 1.0.0 =
Rilascio iniziale del plugin.
