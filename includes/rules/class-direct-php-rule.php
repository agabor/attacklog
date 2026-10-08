<?php
/**
 * Direct PHP Access classification rule.
 *
 * @package AttackLog
 */

namespace AttackLog\Rules;

use AttackLog\Request_Context;

defined( 'ABSPATH' ) || exit;

/**
 * Matches requests for PHP files inside wp-includes or the uploads
 * directory, places no legitimate visitor ever needs to request.
 */
class Direct_Php_Rule {

	/**
	 * Returns the protected-directory PHP file patterns.
	 *
	 * @return array
	 */
	public function get_patterns() {
		$uploads_path = $this->get_uploads_path();

		$default_patterns = array(
			'^/wp-includes/.*\.(php\d?|phtml|phar)$',
			'^' . preg_quote( $uploads_path, '#' ) . '/.*\.(php\d?|phtml|phar)$',
		);

		/**
		 * Filters the Direct PHP Access path patterns.
		 *
		 * @param array $default_patterns Direct PHP Access regex patterns.
		 */
		return apply_filters( 'attacklog_direct_php_paths', $default_patterns );
	}

	/**
	 * Resolves the normalized uploads directory path.
	 *
	 * @return string
	 */
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

	/**
	 * Checks whether the given request matches the Direct PHP Access rule.
	 *
	 * @param Request_Context $context Request context to evaluate.
	 *
	 * @return bool
	 */
	public function matches( Request_Context $context ) {
		$normalized_path = $context->get_normalized_path();

		foreach ( $this->get_patterns() as $pattern_fragment ) {
			if ( preg_match( '#' . $pattern_fragment . '#i', $normalized_path ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Returns the detail text for a matching request.
	 *
	 * @param Request_Context $context Request context that matched.
	 *
	 * @return string|null
	 */
	public function get_detail( Request_Context $context ) {
		return null;
	}
}