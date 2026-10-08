<?php
/**
 * Suspicious User Agent classification rule.
 *
 * @package AttackLog
 */

namespace AttackLog\Rules;

use AttackLog\Request_Context;

defined( 'ABSPATH' ) || exit;

/**
 * Matches requests whose User-Agent is missing, malformed, or belongs
 * to an HTTP library, a known scanner, or an outdated browser.
 */
class Suspicious_Ua_Rule {

	/**
	 * Placeholder User-Agent values treated as malformed.
	 *
	 * @var array
	 */
	private static $placeholder_values = array( '-', 'null', 'undefined', 'test' );

	/**
	 * Returns the suspicious User-Agent pattern groups, keyed by label.
	 *
	 * @return array
	 */
	public function get_pattern_groups() {
		$default_groups = array(
			'http-library' => array(
				'curl/',
				'Wget/',
				'python-requests',
				'Python-urllib',
				'python-httpx',
				'aiohttp',
				'Go-http-client',
				'okhttp',
				'Java/',
				'Apache-HttpClient',
				'libwww-perl',
				'PHP/',
				'GuzzleHttp',
				'node-fetch',
				'axios/',
				'undici',
				'Ruby',
				'PycURL',
				'Scrapy',
				'HeadlessChrome',
			),
			'scanner'      => array(
				'sqlmap',
				'nikto',
				'nmap',
				'masscan',
				'zgrab',
				'nuclei',
				'wpscan',
				'dirbuster',
				'gobuster',
				'ffuf',
				'feroxbuster',
				'acunetix',
				'nessus',
				'openvas',
				'whatweb',
				'wfuzz',
				'burp',
				'hydra',
				'CensysInspect',
			),
			'outdated'     => array(
				'MSIE [2-8]\.',
				'Windows NT 5\.',
				'Firefox/[1-3]\.',
			),
		);

		$stored_settings = get_option( 'attacklog_settings', array() );

		if ( ! empty( $stored_settings['extra_suspicious_ua_patterns'] ) ) {
			$extra_patterns = array_filter(
				array_map( 'trim', explode( "\n", $stored_settings['extra_suspicious_ua_patterns'] ) )
			);

			if ( ! empty( $extra_patterns ) ) {
				$default_groups['scanner'] = array_merge( $default_groups['scanner'], $extra_patterns );
			}
		}

		/**
		 * Filters the suspicious User-Agent pattern groups.
		 *
		 * @param array $default_groups Pattern groups keyed by label.
		 */
		return apply_filters( 'attacklog_suspicious_ua_patterns', $default_groups );
	}

	/**
	 * Checks whether the given request matches the Suspicious User Agent rule.
	 *
	 * @param Request_Context $context Request context to evaluate.
	 *
	 * @return bool
	 */
	public function matches( Request_Context $context ) {
		return null !== $this->get_matched_label_and_token( $context );
	}

	/**
	 * Finds the first suspicious User-Agent rule that matches the request.
	 *
	 * @param Request_Context $context Request context to evaluate.
	 *
	 * @return array|null Two-element array of [ label, token ], or null when no rule matches.
	 */
	public function get_matched_label_and_token( Request_Context $context ) {
		$user_agent = $context->get_user_agent();

		if ( null === $user_agent || '' === $user_agent ) {
			return array( 'missing', '' );
		}

		if ( $this->is_malformed( $user_agent ) ) {
			return array( 'malformed', $user_agent );
		}

		foreach ( $this->get_pattern_groups() as $group_label => $group_patterns ) {
			foreach ( $group_patterns as $pattern_fragment ) {
				if ( preg_match( '#' . $pattern_fragment . '#i', $user_agent, $pattern_matches ) ) {
					return array( $group_label, $pattern_matches[0] );
				}
			}
		}

		return null;
	}

	/**
	 * Checks whether a User-Agent string looks malformed.
	 *
	 * @param string $user_agent Sanitized User-Agent string.
	 *
	 * @return bool
	 */
	private function is_malformed( $user_agent ) {
		if ( strlen( $user_agent ) < 10 ) {
			return true;
		}

		if ( preg_match( '/^Mozilla\/5\.0$/i', $user_agent ) ) {
			return true;
		}

		if ( preg_match( '/[\x00-\x1F\x7F]/', $user_agent ) ) {
			return true;
		}

		if ( in_array( strtolower( $user_agent ), self::$placeholder_values, true ) ) {
			return true;
		}

		return false;
	}

	/**
	 * Returns the detail text for a matching request: the matched label
	 * and, when available, the token that matched.
	 *
	 * @param Request_Context $context Request context that matched.
	 *
	 * @return string|null
	 */
	public function get_detail( Request_Context $context ) {
		$matched_rule = $this->get_matched_label_and_token( $context );

		if ( null === $matched_rule ) {
			return null;
		}

		list( $matched_label, $matched_token ) = $matched_rule;

		if ( '' === $matched_token ) {
			return $matched_label;
		}

		return $matched_label . ': ' . $matched_token;
	}
}