<?php

namespace AttackLog\Rules;

use AttackLog\Request_Context;

defined( 'ABSPATH' ) || exit;

class Probe_Rule {

	private static $compiled_pattern = null;

	public function get_default_patterns() {
		return array(
			// Environment / secrets.
			'\.env(\..*)?$',
			'\.aws/credentials',
			'\.npmrc',
			'\.htpasswd',
			'config\.json$',
			'secrets?\.(ya?ml|json)$',
			// VCS / IDE.
			'\.git/',
			'\.svn/',
			'\.hg/',
			'\.DS_Store$',
			'\.vscode/',
			'\.idea/',
			// Backups / dumps.
			'\.(sql|sql\.gz|bak|old|orig|backup|swp|zip|tar|tar\.gz|7z|rar)$',
			'backup',
			'dump',
			'db\.sql',
			// WP config copies.
			'wp-config\.(php[~_.-].*|txt|bak|old|save)$',
			// Debug / info.
			'phpinfo\.php$',
			'info\.php$',
			'debug\.log$',
			'error_log$',
			'server-status',
			// Admin tools / shells.
			'phpmyadmin',
			'adminer\.php$',
			'shell\.php$',
			'c99\.php$',
			'r57\.php$',
			'xmlrpc\.php\.bak',
			// Other stacks.
			'/vendor/phpunit/',
			'/cgi-bin/',
			'\.asp(x)?$',
			'/actuator/',
			'/console/',
			'/solr/',
		);
	}


	public function get_patterns() {
		$default_patterns = $this->get_default_patterns();
		$stored_settings  = get_option( 'attacklog_settings', array() );
		$extra_patterns   = array();

		if ( ! empty( $stored_settings['extra_probe_patterns'] ) ) {
			$extra_patterns = array_filter(
				array_map( 'trim', explode( "\n", $stored_settings['extra_probe_patterns'] ) )
			);
		}

		$all_patterns = array_merge( $default_patterns, $extra_patterns );

		return apply_filters( 'attacklog_probe_patterns', $all_patterns );
	}

	public function get_compiled_pattern() {
		if ( null !== self::$compiled_pattern ) {
			return self::$compiled_pattern;
		}

		self::$compiled_pattern = '#(?:' . implode( '|', $this->get_patterns() ) . ')#i';

		return self::$compiled_pattern;
	}

	public function matches( Request_Context $context ) {
		if ( 404 !== $context->get_status_code() ) {
			return false;
		}

		return (bool) preg_match( $this->get_compiled_pattern(), $context->get_normalized_path() );
	}

	public function get_detail( Request_Context $context ) {
		$normalized_path = $context->get_normalized_path();

		foreach ( $this->get_patterns() as $pattern_fragment ) {
			if ( preg_match( '#' . $pattern_fragment . '#i', $normalized_path ) ) {
				return $pattern_fragment;
			}
		}

		return null;
	}
}