<?php

namespace AttackLog;

defined( 'ABSPATH' ) || exit;

class Ip_Resolver {

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

		return apply_filters( 'attacklog_client_ip', $client_ip );
	}

	public function resolve_remote_addr() {
		if ( empty( $_SERVER['REMOTE_ADDR'] ) ) {
			return '';
		}

		$remote_addr = sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) );

		return $this->is_valid_ip( $remote_addr ) ? $remote_addr : '';
	}

	public function is_valid_ip( $ip ) {
		return false !== filter_var( $ip, FILTER_VALIDATE_IP );
	}

	public function normalize_ipv4_mapped( $ip ) {
		if ( 0 === stripos( $ip, '::ffff:' ) ) {
			$mapped_ipv4 = substr( $ip, 7 );

			if ( false !== filter_var( $mapped_ipv4, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
				return $mapped_ipv4;
			}
		}

		return $ip;
	}

	public function to_binary( $ip ) {
		$normalized_ip = $this->normalize_ipv4_mapped( $ip );

		if ( ! $this->is_valid_ip( $normalized_ip ) ) {
			return null;
		}

		$binary_ip = inet_pton( $normalized_ip );

		return false !== $binary_ip ? $binary_ip : null;
	}

	public function to_readable( $binary ) {
		$readable_ip = inet_ntop( $binary );

		return false !== $readable_ip ? $readable_ip : null;
	}
}