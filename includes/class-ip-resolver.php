<?php
/**
 * Client IP resolution and conversion helpers.
 *
 * @package AttackLog
 */

namespace AttackLog;

defined( 'ABSPATH' ) || exit;

/**
 * Resolves, validates and converts client IP addresses.
 */
class Ip_Resolver {

	/**
	 * Resolves the client IP address for the current request.
	 *
	 * Uses the CF-Connecting-IP header when present and valid, otherwise
	 * falls back to REMOTE_ADDR.
	 *
	 * @return string Resolved IP address, or an empty string if none is available.
	 */
	public function resolve_client_ip() {
		$client_ip = '';

		if ( ! empty( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ) {
			$candidate = sanitize_text_field( wp_unslash( $_SERVER['HTTP_CF_CONNECTING_IP'] ) );

			if ( $this->is_valid_ip( $candidate ) ) {
				$client_ip = $candidate;
			}
		}

		if ( '' === $client_ip ) {
			$client_ip = $this->resolve_remote_addr();
		}

		/**
		 * Filters the resolved client IP address.
		 *
		 * @param string $client_ip Resolved client IP address.
		 */
		return apply_filters( 'attacklog_client_ip', $client_ip );
	}

	/**
	 * Resolves the REMOTE_ADDR value for the current request.
	 *
	 * @return string Resolved REMOTE_ADDR, or an empty string if invalid or missing.
	 */
	public function resolve_remote_addr() {
		if ( empty( $_SERVER['REMOTE_ADDR'] ) ) {
			return '';
		}

		$remote_addr = sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) );

		return $this->is_valid_ip( $remote_addr ) ? $remote_addr : '';
	}

	/**
	 * Checks whether a string is a valid IPv4 or IPv6 address.
	 *
	 * @param string $ip IP address to validate.
	 *
	 * @return bool
	 */
	public function is_valid_ip( $ip ) {
		return false !== filter_var( $ip, FILTER_VALIDATE_IP );
	}

	/**
	 * Converts an IPv4-mapped IPv6 address to plain IPv4.
	 *
	 * @param string $ip IP address to normalize.
	 *
	 * @return string Normalized IP address.
	 */
	public function normalize_ipv4_mapped( $ip ) {
		if ( 0 === stripos( $ip, '::ffff:' ) ) {
			$mapped_ipv4 = substr( $ip, 7 );

			if ( false !== filter_var( $mapped_ipv4, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
				return $mapped_ipv4;
			}
		}

		return $ip;
	}

	/**
	 * Converts an IP address to its binary representation.
	 *
	 * @param string $ip IP address to convert.
	 *
	 * @return string|null Binary representation, or null if the address is invalid.
	 */
	public function to_binary( $ip ) {
		$normalized_ip = $this->normalize_ipv4_mapped( $ip );

		if ( ! $this->is_valid_ip( $normalized_ip ) ) {
			return null;
		}

		$binary_ip = inet_pton( $normalized_ip );

		return false !== $binary_ip ? $binary_ip : null;
	}

	/**
	 * Converts a binary IP address representation back to its readable form.
	 *
	 * @param string $binary Binary IP address.
	 *
	 * @return string|null Readable IP address, or null if the value is invalid.
	 */
	public function to_readable( $binary ) {
		$readable_ip = inet_ntop( $binary );

		return false !== $readable_ip ? $readable_ip : null;
	}
}