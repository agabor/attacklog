<?php
/**
 * Plugin Name: Attack Log
 * Description: Fetches and refreshes Cloudflare's published IP ranges daily via cron, monitors incoming requests for suspicious activity, and provides an admin Tools page to view Cloudflare indicators and suspicious-request logs.
 * Version: 1.0.0
 * Requires at least: 5.0
 * Requires PHP: 7.0
 * Tested up to: 7.1
 * Author: Gabor Angyal
 * Author URI: https://webshop.tech
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'ALW_PLUGIN_FILE', __FILE__ );
define( 'ALW_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
define( 'ALW_PLUGIN_URL', plugin_dir_url( __FILE__ ) );

require_once ALW_PLUGIN_DIR . 'includes/class-alw-ip-manager.php';
require_once ALW_PLUGIN_DIR . 'includes/class-alw-request-filter.php';
require_once ALW_PLUGIN_DIR . 'includes/class-alw-logger.php';
require_once ALW_PLUGIN_DIR . 'includes/class-alw-admin-page.php';

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
		ALW_IP_Manager::update_ip_ranges();
		ALW_IP_Manager::schedule_cron();
	}

	public static function deactivate() {
		ALW_IP_Manager::unschedule_cron();
	}

	public function init() {
		ALW_Request_Filter::init();
		ALW_Admin_Page::init();
		add_action( 'alw_daily_ip_refresh', array( 'ALW_IP_Manager', 'cron_update' ) );
	}
}

register_activation_hook( ALW_PLUGIN_FILE, array( 'Attacklog_WP', 'activate' ) );
register_deactivation_hook( ALW_PLUGIN_FILE, array( 'Attacklog_WP', 'deactivate' ) );
add_action( 'plugins_loaded', array( 'Attacklog_WP', 'instance' ) );