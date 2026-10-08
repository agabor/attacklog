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

	/**
	 * Computes, from the current request's headers only, a live note
	 * describing whether this request appears to have come through
	 * Cloudflare. Never stored and never affects the switch.
	 *
	 * @return array {
	 *     @type string      $status          'full', 'partial' or 'none'.
	 *     @type string      $message         Human-readable note.
	 *     @type string|null $ray_id          CF-Ray header value, if present.
	 *     @type string|null $country         CF-IPCountry header value, if present.
	 *     @type array       $missing_headers Labels of the headers that are missing.
	 * }
	 */
	public static function get_live_note() {
		$present_header_count = self::count_present_cf_headers();
		$missing_headers      = array();

		if ( empty( $_SERVER['HTTP_CF_RAY'] ) ) {
			$missing_headers[] = 'CF-Ray';
		}

		if ( empty( $_SERVER['HTTP_CF_IPCOUNTRY'] ) ) {
			$missing_headers[] = 'CF-IPCountry';
		}

		if ( empty( $_SERVER['HTTP_CF_VISITOR'] ) ) {
			$missing_headers[] = 'CF-Visitor';
		}

		$ray_id = ! empty( $_SERVER['HTTP_CF_RAY'] )
			? sanitize_text_field( wp_unslash( $_SERVER['HTTP_CF_RAY'] ) )
			: null;

		$country = ! empty( $_SERVER['HTTP_CF_IPCOUNTRY'] )
			? sanitize_text_field( wp_unslash( $_SERVER['HTTP_CF_IPCOUNTRY'] ) )
			: null;

		if ( 3 === $present_header_count ) {
			$status  = 'full';
			$message = sprintf(
				/* translators: 1: Cloudflare Ray ID, 2: two-letter country code. */
				__( 'This request came through Cloudflare (Ray %1$s, %2$s)', 'attack-log' ),
				$ray_id,
				$country
			);
		} elseif ( $present_header_count > 0 ) {
			$status  = 'partial';
			$message = sprintf(
				/* translators: %s: comma-separated list of missing header names. */
				__( 'This request has only some Cloudflare headers (missing: %s)', 'attack-log' ),
				implode( ', ', $missing_headers )
			);
		} else {
			$status  = 'none';
			$message = __( 'This request did not come through Cloudflare', 'attack-log' );
		}

		return array(
			'status'          => $status,
			'message'         => $message,
			'ray_id'          => $ray_id,
			'country'         => $country,
			'missing_headers' => $missing_headers,
		);
	}

	/**
	 * Returns a hint when the stored switch and the current request
	 * disagree, or null when they agree.
	 *
	 * @return string|null
	 */
	public static function get_switch_hint() {
		$bypass_detection_enabled = self::is_bypass_detection_enabled();
		$request_has_all_headers  = self::request_has_all_cf_headers();
		$present_header_count     = self::count_present_cf_headers();

		if ( $bypass_detection_enabled && 0 === $present_header_count ) {
			return __( "You reached the site without Cloudflare. That's expected if you use a VPN, a hosts-file entry or a staging domain. Otherwise Cloudflare proxying (orange cloud) may be switched off — and every visitor would be logged as a bypass.", 'attack-log' );
		}

		if ( ! $bypass_detection_enabled && $request_has_all_headers ) {
			return __( 'This site seems to be behind Cloudflare. Turn on bypass detection?', 'attack-log' );
		}

		return null;
	}
}