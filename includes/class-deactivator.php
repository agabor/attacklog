<?php
/**
 * Plugin deactivation handler.
 *
 * @package AttackLog
 */

namespace AttackLog;

defined( 'ABSPATH' ) || exit;

/**
 * Runs the tasks required when the plugin is deactivated.
 */
class Deactivator {

	/**
	 * Unschedules the daily auto-clean cron event. Logged data and plugin
	 * settings are left untouched.
	 *
	 * @return void
	 */
	public static function deactivate() {
		wp_clear_scheduled_hook( 'attacklog_purge' );
	}
}