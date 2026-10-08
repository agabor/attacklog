<?php
/**
 * Request classification against all detection rules.
 *
 * @package AttackLog
 */

namespace AttackLog;

use AttackLog\Rules\Cf_Bypass_Rule;
use AttackLog\Rules\Probe_Rule;
use AttackLog\Rules\Direct_Php_Rule;
use AttackLog\Rules\Xmlrpc_Rule;
use AttackLog\Rules\Suspicious_Ua_Rule;

defined( 'ABSPATH' ) || exit;

/**
 * Applies the exclusion checks and the five detection rules to a request
 * context, combining their results per the Target/Origin precedence.
 */
class Classifier {

	/**
	 * Cloudflare Bypass rule instance.
	 *
	 * @var Cf_Bypass_Rule
	 */
	private $cf_bypass_rule;

	/**
	 * Probing rule instance.
	 *
	 * @var Probe_Rule
	 */
	private $probe_rule;

	/**
	 * Direct PHP Access rule instance.
	 *
	 * @var Direct_Php_Rule
	 */
	private $direct_php_rule;

	/**
	 * XML-RPC rule instance.
	 *
	 * @var Xmlrpc_Rule
	 */
	private $xmlrpc_rule;

	/**
	 * Suspicious User Agent rule instance.
	 *
	 * @var Suspicious_Ua_Rule
	 */
	private $suspicious_ua_rule;

	/**
	 * Constructor.
	 *
	 * @param Cf_Bypass_Rule     $cf_bypass_rule     Cloudflare Bypass rule instance.
	 * @param Probe_Rule         $probe_rule         Probing rule instance.
	 * @param Direct_Php_Rule    $direct_php_rule    Direct PHP Access rule instance.
	 * @param Xmlrpc_Rule        $xmlrpc_rule        XML-RPC rule instance.
	 * @param Suspicious_Ua_Rule $suspicious_ua_rule Suspicious User Agent rule instance.
	 */
	public function __construct(
		Cf_Bypass_Rule $cf_bypass_rule,
		Probe_Rule $probe_rule,
		Direct_Php_Rule $direct_php_rule,
		Xmlrpc_Rule $xmlrpc_rule,
		Suspicious_Ua_Rule $suspicious_ua_rule
	) {
		$this->cf_bypass_rule     = $cf_bypass_rule;
		$this->probe_rule         = $probe_rule;
		$this->direct_php_rule    = $direct_php_rule;
		$this->xmlrpc_rule        = $xmlrpc_rule;
		$this->suspicious_ua_rule = $suspicious_ua_rule;
	}

	/**
	 * Checks whether the request should be excluded from logging entirely,
	 * regardless of whether it would otherwise match a rule.
	 *
	 * @param Request_Context $context Request context to evaluate.
	 *
	 * @return bool
	 */
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

		if ( $this->is_ignored_path( $context ) ) {
			return true;
		}

		return false;
	}

	/**
	 * Checks whether the request is a loopback request, such as a WP-Cron
	 * spawn or a Site Health check calling the site directly.
	 *
	 * @param Request_Context $context Request context to evaluate.
	 *
	 * @return bool
	 */
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

	/**
	 * Checks whether the current request belongs to a logged-in user,
	 * either through the current user object or a valid logged-in cookie.
	 *
	 * @return bool
	 */
	private function is_logged_in_request() {
		if ( is_user_logged_in() ) {
			return true;
		}

		if ( empty( $_COOKIE[ LOGGED_IN_COOKIE ] ) ) {
			return false;
		}

		return (bool) wp_validate_auth_cookie( '', 'logged_in' );
	}

	/**
	 * Checks whether the request path is on the configurable ignore-list.
	 *
	 * @param Request_Context $context Request context to evaluate.
	 *
	 * @return bool
	 */
	private function is_ignored_path( Request_Context $context ) {
		/**
		 * Filters the list of paths that are never logged.
		 *
		 * @param array $ignored_paths Normalized paths to ignore.
		 */
		$ignored_paths = apply_filters( 'attacklog_ignored_paths', array() );

		if ( empty( $ignored_paths ) ) {
			return false;
		}

		return in_array( $context->get_normalized_path(), $ignored_paths, true );
	}

	/**
	 * Evaluates the request against all rules and returns the error types
	 * it matched, each with its detail text.
	 *
	 * @param Request_Context $context Request context to evaluate.
	 *
	 * @return array Map of error_type_id => detail (string or null).
	 */
	public function evaluate( Request_Context $context ) {
		$target_matches = $this->evaluate_target_rules( $context );
		$origin_matches = $this->evaluate_origin_rules( $context );

		$all_matches = $target_matches + $origin_matches;

		return $this->filter_whitelisted( $all_matches, $context );
	}

	/**
	 * Evaluates the Target group of rules (Direct PHP Access, XML-RPC,
	 * Probing), applying precedence so at most one matches.
	 *
	 * @param Request_Context $context Request context to evaluate.
	 *
	 * @return array Map of at most one error_type_id => detail.
	 */
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

	/**
	 * Evaluates the Origin group of rules (Cloudflare Bypass, Suspicious
	 * User Agent), independently of each other and of the Target group.
	 *
	 * @param Request_Context $context Request context to evaluate.
	 *
	 * @return array Map of error_type_id => detail.
	 */
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

	/**
	 * Removes whitelisted categories from the matched error types.
	 *
	 * Placeholder for M1: whitelist storage and matching are implemented
	 * in M3, so this currently returns the matches unchanged.
	 *
	 * @param array            $matches Map of error_type_id => detail.
	 * @param Request_Context  $context Request context being evaluated.
	 *
	 * @return array
	 */
	public function filter_whitelisted( array $matches, Request_Context $context ) {
		return $matches;
	}
}