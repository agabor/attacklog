<?php

namespace AttackLog\Rules;

use AttackLog\Request_Context;

defined( 'ABSPATH' ) || exit;

class Direct_Php_Rule {

	public function get_patterns() {
		$uploads_path = $this->get_uploads_path();

		$default_patterns = array(
			'^/wp-includes/.*\.(php\d?|phtml|phar)$',
			'^' . preg_quote( $uploads_path, '#' ) . '/.*\.(php\d?|phtml|phar)$',
		);

		return apply_filters( 'attacklog_direct_php_paths', $default_patterns );
	}

	private function get_uploads_path() {
		$upload_dir   = wp_upload_dir();
		$uploads_path = '';

		if ( ! empty( $upload_dir['baseurl'] ) ) {
			$uploads_path = (string) wp_parse_url( $upload_dir['baseurl'], PHP_URL_PATH );
		}

		if ( '' === $uploads_path ) {
			$uploads_path = '/wp-content/uploads';
		}

		return strtolower( $uploads_path );
	}

	public function matches( Request_Context $context ) {
		$normalized_path = $context->get_normalized_path();

		foreach ( $this->get_patterns() as $pattern_fragment ) {
			if ( preg_match( '#' . $pattern_fragment . '#i', $normalized_path ) ) {
				return true;
			}
		}

		return false;
	}

	public function get_detail( Request_Context $context ) {
		return null;
	}
}