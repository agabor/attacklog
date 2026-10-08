<?php

namespace AttackLog;

use AttackLog\Rules\Cf_Bypass_Rule;
use AttackLog\Rules\Probe_Rule;
use AttackLog\Rules\Direct_Php_Rule;
use AttackLog\Rules\Xmlrpc_Rule;
use AttackLog\Rules\Suspicious_Ua_Rule;

defined( 'ABSPATH' ) || exit;


class Classifier {

	private $cf_bypass_rule;

	private $probe_rule;

	private $direct_php_rule;

	private $xmlrpc_rule;

	private $suspicious_ua_rule;

	private $whitelist;

	public function __construct(
		Cf_Bypass_Rule $cf_bypass_rule,
		Probe_Rule $probe_rule,
		Direct_Php_Rule $direct_php_rule,
		Xmlrpc_Rule $xmlrpc_rule,
		Suspicious_Ua_Rule $suspicious_ua_rule,
		Whitelist $whitelist
	) {
		$this->cf_bypass_rule     = $cf_bypass_rule;
		$this->probe_rule         = $probe_rule;
		$this->direct_php_rule    = $direct_php_rule;
		$this->xmlrpc_rule        = $xmlrpc_rule;
		$this->suspicious_ua_rule = $suspicious_ua_rule;
		$this->whitelist          = $whitelist;
	}

	public function should_skip( Request_Context $context ) {
		if ( function_exists( 'wp_doing_cron' ) && wp_doing_cron() ) {
			return true;
		}

		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			return true;
		}

		if ( $this->is_loopback_request( $context ) ) {
			return true;
		}

		if ( $this->is_logged_in_request() ) {
			return true;
		}

		return false;
	}

	private function is_loopback_request( Request_Context $context ) {
		$remote_addr = $context->get_remote_addr();

		if ( '' === $remote_addr ) {
			return false;
		}

		if ( in_array( $remote_addr, array( '127.0.0.1', '::1' ), true ) ) {
			return true;
		}

		$server_addr = isset( $_SERVER['SERVER_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['SERVER_ADDR'] ) ) : '';

		return '' !== $server_addr && $remote_addr === $server_addr;
	}

	private function is_logged_in_request() {
		if ( is_user_logged_in() ) {
			return true;
		}

		if ( empty( $_COOKIE[ LOGGED_IN_COOKIE ] ) ) {
			return false;
		}

		return (bool) wp_validate_auth_cookie( '', 'logged_in' );
	}

	public function evaluate( Request_Context $context ) {
		$target_matches = $this->evaluate_target_rules( $context );
		$origin_matches = $this->evaluate_origin_rules( $context );

		$all_matches = $target_matches + $origin_matches;

		return $this->filter_whitelisted( $all_matches, $context );
	}

	private function evaluate_target_rules( Request_Context $context ) {
		if ( $this->direct_php_rule->matches( $context ) ) {
			return array( Schema::ERROR_TYPE_DIRECT_PHP => $this->direct_php_rule->get_detail( $context ) );
		}

		if ( $this->xmlrpc_rule->matches( $context ) ) {
			return array( Schema::ERROR_TYPE_XMLRPC => $this->xmlrpc_rule->get_detail( $context ) );
		}

		if ( $this->probe_rule->matches( $context ) ) {
			return array( Schema::ERROR_TYPE_PROBING => $this->probe_rule->get_detail( $context ) );
		}

		return array();
	}

	private function evaluate_origin_rules( Request_Context $context ) {
		$origin_matches = array();

		if ( $this->cf_bypass_rule->matches( $context ) ) {
			$origin_matches[ Schema::ERROR_TYPE_CF_BYPASS ] = $this->cf_bypass_rule->get_detail( $context );
		}

		if ( $this->suspicious_ua_rule->matches( $context ) ) {
			$origin_matches[ Schema::ERROR_TYPE_SUSPICIOUS_UA ] = $this->suspicious_ua_rule->get_detail( $context );
		}

		return $origin_matches;
	}

	public function filter_whitelisted( array $matches, Request_Context $context ) {
		if ( empty( $matches ) ) {
			return $matches;
		}

		$suppressed_error_type_ids = $this->whitelist->get_suppressed_error_type_ids( $context );

		return array_diff_key( $matches, array_flip( $suppressed_error_type_ids ) );
	}
}