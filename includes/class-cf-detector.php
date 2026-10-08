<?php
/**
 * Cloudflare bypass detection state management.
 *
 * @package AttackLog
 */

namespace AttackLog;

defined( 'ABSPATH' ) || exit;

/**
 * Detects Cloudflare headers on the current request and manages the
 * one-time automatic Cloudflare bypass detection state.
 */
class Cf_Detector {

	/**
	 * Option name storing the Cloudflare bypass detection state.
	 *
	 * @var string
	 */
	const OPTION_NAME = 'attacklog_cf_status';

	/**
	 * Checks whether the current request carries all three Cloudflare headers.
	 *
	 * @return bool
	 */
	public static function request_has_all_cf_headers() {
		return ! empty( $_SERVER['HTTP_CF_RAY'] )
			&& ! empty( $_SERVER['HTTP_CF_IPCOUNTRY'] )
			&& ! empty( $_SERVER['HTTP_CF_VISITOR'] );
	}

	/**
	 * Counts how many of the three Cloudflare headers are present on the
	 * current request.
	 *
	 * @return int Number between 0 and 3.
	 */
	public static function count_present_cf_headers() {
		$present_header_count = 0;

		if ( ! empty( $_SERVER['HTTP_CF_RAY'] ) ) {
			++$present_header_count;
		}

		if ( ! empty( $_SERVER['HTTP_CF_IPCOUNTRY'] ) ) {
			++$present_header_count;
		}

		if ( ! empty( $_SERVER['HTTP_CF_VISITOR'] ) ) {
			++$present_header_count;
		}

		return $present_header_count;
	}

	/**
	 * Returns the stored Cloudflare bypass detection state, merged with
	 * default values.
	 *
	 * @return array {
	 *     @type bool        $enabled Whether bypass detection is on.
	 *     @type string      $state   'unknown' or 'set'.
	 *     @type string|null $set_by  'activation', 'first_admin_visit', 'user' or null.
	 *     @type string|null $set_at  UTC datetime the state was set, or null.
	 *     @type int|null    $user_id User who last changed the state, or null.
	 * }
	 */
	public static function get_status() {
		$default_status = array(
			'enabled' => false,
			'state'   => 'unknown',
			'set_by'  => null,
			'set_at'  => null,
			'user_id' => null,
		);

		$stored_status = get_option( self::OPTION_NAME, array() );

		if ( ! is_array( $stored_status ) ) {
			$stored_status = array();
		}

		return wp_parse_args( $stored_status, $default_status );
	}

	/**
	 * Checks whether Cloudflare bypass detection is currently enabled.
	 *
	 * @return bool
	 */
	public static function is_bypass_detection_enabled() {
		$current_status = self::get_status();

		return (bool) $current_status['enabled'];
	}

	/**
	 * Checks whether the current request should be treated as having come
	 * through Cloudflare.
	 *
	 * @return bool
	 */
	public static function is_cloudflare_trusted_request() {
		return self::is_bypass_detection_enabled() && self::request_has_all_cf_headers();
	}

	/**
	 * Sets the Cloudflare bypass detection state once, automatically, from
	 * the request that activated the plugin.
	 *
	 * Does nothing if the state has already been set, or if activation ran
	 * without an HTTP request (e.g. WP-CLI).
	 *
	 * @return void
	 */
	public static function maybe_auto_set_on_activation() {
		$current_status = self::get_status();

		if ( 'unknown' !== $current_status['state'] ) {
			return;
		}

		if ( empty( $_SERVER['REQUEST_METHOD'] ) ) {
			return;
		}

		self::set_status( self::request_has_all_cf_headers(), 'activation' );
	}

	/**
	 * Sets the Cloudflare bypass detection state once, automatically, on
	 * the first visit to the Attack Log admin page.
	 *
	 * Does nothing if the state has already been set.
	 *
	 * @return void
	 */
	public static function maybe_auto_set_on_first_admin_visit() {
		$current_status = self::get_status();

		if ( 'unknown' !== $current_status['state'] ) {
			return;
		}

		self::set_status( self::request_has_all_cf_headers(), 'first_admin_visit' );
	}

	/**
	 * Persists the Cloudflare bypass detection state.
	 *
	 * @param bool        $enabled Whether bypass detection should be on.
	 * @param string      $set_by  'activation', 'first_admin_visit' or 'user'.
	 * @param int|null    $user_id User who made the change, when $set_by is 'user'.
	 *
	 * @return void
	 */
	public static function set_status( $enabled, $set_by, $user_id = null ) {
		$new_status = array(
			'enabled' => (bool) $enabled,
			'state'   => 'set',
			'set_by'  => $set_by,
			'set_at'  => gmdate( 'Y-m-d H:i:s' ),
			'user_id' => $user_id,
		);

		update_option( self::OPTION_NAME, $new_status );
	}
}