<?php

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class ALW_Request_Filter {

	const LOGGED_STATUS_CODES = array( 401, 403, 404, 500 );

	const SUSPICIOUS_USER_AGENT_PATTERNS = array(
		'python-requests',
		'python-urllib',
		'aiohttp',
		'curl',
		'Wget',
		'libwww-perl',
		'Go-http-client',
		'Java/',
		'okhttp',
		'node-fetch',
		'axios',
		'PostmanRuntime',
		'Scrapy',
		'HTTPie',
		'Apache-HttpClient',
		'GuzzleHttp',
		'Faraday',
		'RestSharp',
		'insomnia',
		'Jakarta Commons-HttpClient',
		'masscan',
		'Nmap',
		'Nikto',
		'sqlmap',
		'libcurl',
		'Ruby',
		'PHP/',
		'PycURL',
		'Zgrab',
		'Go-http-client',
		'Dart/',
		'Deno/',
	);

	public static function init() {
		add_action( 'shutdown', array( 'ALW_Request_Filter', 'maybe_log_response' ) );
	}

	public static function maybe_log_response() {
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			return;
		}

		if ( defined( 'DOING_CRON' ) && DOING_CRON ) {
			return;
		}

		$status_code = http_response_code();
		$status_matches = in_array( $status_code, self::LOGGED_STATUS_CODES, true );

		$user_agent = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
		$matched_suspicious_pattern = self::get_matched_suspicious_user_agent( $user_agent );

		$flags = self::get_missing_indicators();

		if ( '' !== $matched_suspicious_pattern ) {
			$flags[] = 'Suspicious User Agent (' . $matched_suspicious_pattern . ')';
		}

		if ( ! $status_matches && empty( $flags ) ) {
			return;
		}

		$client_ip = self::get_client_ip();
		$request_uri = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
		$request_method = self::get_request_method();
		$forbidden_headers = self::get_forbidden_headers();

		ALW_Logger::log( $client_ip, $request_uri, $user_agent, $forbidden_headers, $status_code, $flags, $request_method );
	}

	public static function get_matched_suspicious_user_agent( $user_agent ) {
		if ( '' === trim( $user_agent ) ) {
			return '';
		}

		foreach ( self::SUSPICIOUS_USER_AGENT_PATTERNS as $pattern ) {
			if ( false !== stripos( $user_agent, $pattern ) ) {
				return $pattern;
			}
		}

		return '';
	}

	public static function get_request_method() {
		if ( isset( $_SERVER['REQUEST_METHOD'] ) ) {
			return sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) );
		}
		return '';
	}

	public static function get_current_cloudflare_indicators() {
		$client_ip = self::get_client_ip();
		$ip_in_range = ! empty( $client_ip ) && self::is_cloudflare_ip( $client_ip );

		$forwarded_for_header = isset( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) : '';
		$xff_in_range = self::xff_contains_cloudflare_ip( $forwarded_for_header );

		$headers = array();

		foreach ( self::get_cloudflare_header_map() as $label => $server_key ) {
			$header_value = isset( $_SERVER[ $server_key ] ) ? sanitize_text_field( wp_unslash( $_SERVER[ $server_key ] ) ) : '';
			$headers[ $label ] = '' !== trim( $header_value );
		}

		return array(
			'ip_in_range'  => $ip_in_range,
			'xff_in_range' => $xff_in_range,
			'headers'      => $headers,
		);
	}

	public static function xff_contains_cloudflare_ip( $forwarded_for_header ) {
		if ( '' === trim( $forwarded_for_header ) ) {
			return false;
		}

		$candidate_ips = array_map( 'trim', explode( ',', $forwarded_for_header ) );

		foreach ( $candidate_ips as $candidate_ip ) {
			if ( '' === $candidate_ip ) {
				continue;
			}

			if ( self::is_cloudflare_ip( $candidate_ip ) ) {
				return true;
			}
		}

		return false;
	}

	public static function save_admin_indicators() {
		$indicators = self::get_current_cloudflare_indicators();
		update_option( 'alw_admin_cloudflare_indicators', $indicators );
	}

	public static function get_missing_indicators() {
		$baseline = get_option( 'alw_admin_cloudflare_indicators', array() );
		$current = self::get_current_cloudflare_indicators();

		$missing = array();

		if ( ! empty( $baseline['ip_in_range'] ) && empty( $current['ip_in_range'] ) ) {
			$missing[] = 'IP in Cloudflare range';
		}

		if ( ! empty( $baseline['xff_in_range'] ) && empty( $current['xff_in_range'] ) ) {
			$missing[] = 'X-Forwarded-For in Cloudflare range';
		}

		if ( ! empty( $baseline['headers'] ) && is_array( $baseline['headers'] ) ) {
			foreach ( $baseline['headers'] as $label => $was_present ) {
				$is_present_now = ! empty( $current['headers'][ $label ] );

				if ( $was_present && ! $is_present_now ) {
					$missing[] = $label . ' header';
				}

				if ( ! $was_present && $is_present_now ) {
					$missing[] = 'Unexpected ' . $label . ' header';
				}
			}
		}

		return $missing;
	}

	public static function get_cloudflare_header_map() {
		return array(
			'CF-Connecting-IP'   => 'HTTP_CF_CONNECTING_IP',
			'CF-Connecting-IPv6' => 'HTTP_CF_CONNECTING_IPV6',
			'CF-IPCountry'       => 'HTTP_CF_IPCOUNTRY',
			'CF-Ray'             => 'HTTP_CF_RAY',
			'CF-Visitor'         => 'HTTP_CF_VISITOR',
			'CF-Worker'          => 'HTTP_CF_WORKER',
			'CF-Device-Type'     => 'HTTP_CF_DEVICE_TYPE',
			'CDN-Loop'           => 'HTTP_CDN_LOOP',
			'CF-EW-Via'          => 'HTTP_CF_EW_VIA',
		);
	}

	public static function has_cloudflare_headers() {
		return ! empty( self::get_present_cloudflare_headers() );
	}

	public static function get_present_cloudflare_headers() {
		$present = array();

		foreach ( self::get_cloudflare_header_map() as $label => $server_key ) {
			if ( isset( $_SERVER[ $server_key ] ) ) {
				$value = sanitize_text_field( wp_unslash( $_SERVER[ $server_key ] ) );
				if ( '' !== trim( $value ) ) {
					$present[ $label ] = $value;
				}
			}
		}

		return $present;
	}

	public static function get_client_ip() {
		if ( isset( $_SERVER['REMOTE_ADDR'] ) ) {
			return sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) );
		}
		return '';
	}

    public static function get_forbidden_headers() {
		$header_map = array(
			'CF-Connecting-IP'    => 'HTTP_CF_CONNECTING_IP',
			'CF-Connecting-IPv6'  => 'HTTP_CF_CONNECTING_IPV6',
			'CF-IPCountry'        => 'HTTP_CF_IPCOUNTRY',
			'CF-Ray'              => 'HTTP_CF_RAY',
			'CF-Visitor'          => 'HTTP_CF_VISITOR',
			'CF-Worker'           => 'HTTP_CF_WORKER',
			'CF-Device-Type'      => 'HTTP_CF_DEVICE_TYPE',
			'CDN-Loop'            => 'HTTP_CDN_LOOP',
			'CF-EW-Via'           => 'HTTP_CF_EW_VIA',
			'True-Client-IP'      => 'HTTP_TRUE_CLIENT_IP',
			'X-Forwarded-For'     => 'HTTP_X_FORWARDED_FOR',
			'X-Real-IP'           => 'HTTP_X_REAL_IP',
			'Forwarded'           => 'HTTP_FORWARDED',
			'X-Client-IP'         => 'HTTP_X_CLIENT_IP',
			'X-Cluster-Client-IP' => 'HTTP_X_CLUSTER_CLIENT_IP',
		);

		$headers = array();

		foreach ( $header_map as $label => $server_key ) {
			if ( isset( $_SERVER[ $server_key ] ) ) {
				$headers[ $label ] = sanitize_text_field( wp_unslash( $_SERVER[ $server_key ] ) );
			}
		}

		return $headers;
	}

	public static function is_cloudflare_ip( $ip ) {
		$ranges = ALW_IP_Manager::get_ip_ranges();

		$is_ipv6 = strpos( $ip, ':' ) !== false;

		$cidr_list = $is_ipv6 ? $ranges['ipv6'] : $ranges['ipv4'];

		if ( empty( $cidr_list ) ) {
			return true;
		}

		foreach ( $cidr_list as $cidr ) {
			if ( self::is_ip_in_range( $ip, $cidr ) ) {
				return true;
			}
		}

		return false;
	}

	public static function is_ip_in_range( $ip, $cidr ) {
		if ( strpos( $cidr, '/' ) === false ) {
			return $ip === $cidr;
		}

		list( $subnet, $mask_bits ) = explode( '/', $cidr );
		$mask_bits = (int) $mask_bits;

		$is_ipv6 = strpos( $ip, ':' ) !== false;

		if ( $is_ipv6 ) {
			$ip_bin = @inet_pton( $ip );
			$subnet_bin = @inet_pton( $subnet );

			if ( false === $ip_bin || false === $subnet_bin ) {
				return false;
			}

			$ip_bits = '';
			$subnet_bits = '';

			foreach ( str_split( $ip_bin ) as $char ) {
				$ip_bits .= str_pad( decbin( ord( $char ) ), 8, '0', STR_PAD_LEFT );
			}

			foreach ( str_split( $subnet_bin ) as $char ) {
				$subnet_bits .= str_pad( decbin( ord( $char ) ), 8, '0', STR_PAD_LEFT );
			}

			$ip_prefix = substr( $ip_bits, 0, $mask_bits );
			$subnet_prefix = substr( $subnet_bits, 0, $mask_bits );

			return $ip_prefix === $subnet_prefix;
		} else {
			$ip_long = ip2long( $ip );
			$subnet_long = ip2long( $subnet );

			if ( false === $ip_long || false === $subnet_long ) {
				return false;
			}

			$mask = -1 << ( 32 - $mask_bits );
			$mask = $mask & 0xFFFFFFFF;

			return ( $ip_long & $mask ) === ( $subnet_long & $mask );
		}
	}
}