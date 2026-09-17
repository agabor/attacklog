<?php
/**
 * Plugin Name: Attack Log
 * Description: Restricts site access to Cloudflare IP ranges, refreshes those ranges daily via cron, and provides an admin Tools page to view ranges and forbidden-request logs.
 * Version: 1.0.0
 * Author: Gabor Angyal
 * Author URI: https://webshop.tech
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'ALW_PLUGIN_FILE', __FILE__ );
define( 'ALW_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
define( 'ALW_PLUGIN_URL', plugin_dir_url( __FILE__ ) );

require_once ALW_PLUGIN_DIR . 'includes/class-cf-ip-manager.php';
require_once ALW_PLUGIN_DIR . 'includes/class-cf-request-filter.php';
require_once ALW_PLUGIN_DIR . 'includes/class-cf-logger.php';
require_once ALW_PLUGIN_DIR . 'includes/class-cf-admin-page.php';

class Attacklog_WP {

	private static $instance = null;

	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	public function __construct() {
		$this->init();
	}

	public static function activate() {
		CF_IP_Manager::update_ip_ranges();
		CF_IP_Manager::schedule_cron();
	}

	public static function deactivate() {
		CF_IP_Manager::unschedule_cron();
	}

	public function init() {
		CF_Request_Filter::init();
		CF_Admin_Page::init();
		add_action( 'alw_daily_ip_refresh', array( 'CF_IP_Manager', 'cron_update' ) );
	}
}

register_activation_hook( ALW_PLUGIN_FILE, array( 'Attacklog_WP', 'activate' ) );
register_deactivation_hook( ALW_PLUGIN_FILE, array( 'Attacklog_WP', 'deactivate' ) );
add_action( 'plugins_loaded', array( 'Attacklog_WP', 'instance' ) );