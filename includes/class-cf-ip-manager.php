<?php

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class CF_IP_Manager {

	public static function fetch_ip_ranges() {
		$ipv4 = array();
		$ipv6 = array();

		$response_v4 = wp_remote_get( 'https://www.cloudflare.com/ips-v4/' );
		if ( ! is_wp_error( $response_v4 ) && 200 === wp_remote_retrieve_response_code( $response_v4 ) ) {
			$body_v4 = wp_remote_retrieve_body( $response_v4 );
			$lines_v4 = preg_split( '/\r\n|\r|\n/', trim( $body_v4 ) );
			foreach ( $lines_v4 as $line ) {
				$line = trim( $line );
				if ( ! empty( $line ) ) {
					$ipv4[] = $line;
				}
			}
		}

		$response_v6 = wp_remote_get( 'https://www.cloudflare.com/ips-v6/' );
		if ( ! is_wp_error( $response_v6 ) && 200 === wp_remote_retrieve_response_code( $response_v6 ) ) {
			$body_v6 = wp_remote_retrieve_body( $response_v6 );
			$lines_v6 = preg_split( '/\r\n|\r|\n/', trim( $body_v6 ) );
			foreach ( $lines_v6 as $line ) {
				$line = trim( $line );
				if ( ! empty( $line ) ) {
					$ipv6[] = $line;
				}
			}
		}

		return array(
			'ipv4' => $ipv4,
			'ipv6' => $ipv6,
		);
	}

	public static function update_ip_ranges() {
		$ranges = self::fetch_ip_ranges();

		if ( empty( $ranges['ipv4'] ) && empty( $ranges['ipv6'] ) ) {
			return false;
		}

		update_option( 'alw_ipv4_ranges', $ranges['ipv4'] );
		update_option( 'alw_ipv6_ranges', $ranges['ipv6'] );
		update_option( 'alw_last_updated', current_time( 'mysql' ) );

		return true;
	}

	public static function get_ip_ranges() {
		return array(
			'ipv4' => get_option( 'alw_ipv4_ranges', array() ),
			'ipv6' => get_option( 'alw_ipv6_ranges', array() ),
		);
	}

	public static function get_last_updated() {
		return get_option( 'alw_last_updated', '' );
	}

	public static function schedule_cron() {
		if ( ! wp_next_scheduled( 'alw_daily_ip_refresh' ) ) {
			wp_schedule_event( time(), 'daily', 'alw_daily_ip_refresh' );
		}
	}

	public static function unschedule_cron() {
		wp_clear_scheduled_hook( 'alw_daily_ip_refresh' );
	}

	public static function cron_update() {
		self::update_ip_ranges();
	}
}