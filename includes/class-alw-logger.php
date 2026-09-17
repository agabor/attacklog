<?php

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class ALW_Logger {

	const MAX_LOG_ENTRIES = 500;

	public static function log( $ip, $request_uri, $user_agent, $headers = array(), $status_code = '', $cloudflare_status = '' ) {
		$logs = get_option( 'alw_logs', array() );

		$logs[] = array(
			'timestamp'  => current_time( 'mysql' ),
			'ip'         => $ip,
			'uri'        => $request_uri,
			'user_agent' => $user_agent,
			'headers'    => $headers,
			'status'     => $status_code,
			'cf_status'  => $cloudflare_status,
		);

		if ( count( $logs ) > self::MAX_LOG_ENTRIES ) {
			$logs = array_slice( $logs, -self::MAX_LOG_ENTRIES );
		}

		update_option( 'alw_logs', $logs );
	}

	public static function get_logs() {
		$logs = get_option( 'alw_logs', array() );
		return array_reverse( $logs );
	}

	public static function clear_logs() {
		delete_option( 'alw_logs' );
	}
}