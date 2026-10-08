<?php
/**
 * XML-RPC classification rule.
 *
 * @package AttackLog
 */

namespace AttackLog\Rules;

use AttackLog\Request_Context;

defined( 'ABSPATH' ) || exit;

/**
 * Matches every request to xmlrpc.php and collects details about what
 * the request tried to do: the method called, multicall counts and
 * failed logins.
 */
class Xmlrpc_Rule {

	/**
	 * Top-level or first multicall method name.
	 *
	 * @var string|null
	 */
	private static $method_name = null;

	/**
	 * Number of inner method calls executed, counted via xmlrpc_call.
	 *
	 * @var int
	 */
	private static $inner_call_count = 0;

	/**
	 * Number of failed login attempts, counted via xmlrpc_login_error.
	 *
	 * @var int
	 */
	private static $failed_login_count = 0;

	/**
	 * Whether the action/filter listeners have already been registered.
	 *
	 * @var bool
	 */
	private static $listeners_registered = false;

	/**
	 * Checks whether the given request matches the XML-RPC rule.
	 *
	 * @param Request_Context $context Request context to evaluate.
	 *
	 * @return bool
	 */
	public function matches( Request_Context $context ) {
		return $context->is_xmlrpc_request();
	}

	/**
	 * Registers the xmlrpc_call and xmlrpc_login_error listeners, and
	 * attempts to read the method name from the raw request body.
	 *
	 * @return void
	 */
	public function register_listeners() {
		if ( self::$listeners_registered ) {
			return;
		}

		self::$listeners_registered = true;

		add_action( 'xmlrpc_call', array( $this, 'on_xmlrpc_call' ) );
		add_filter( 'xmlrpc_login_error', array( $this, 'on_xmlrpc_login_error' ) );

		$this->capture_method_name_from_body();
	}

	/**
	 * Records a called XML-RPC method name and increments the inner-call
	 * counter.
	 *
	 * @param string $method_name Name of the XML-RPC method being executed.
	 *
	 * @return void
	 */
	public function on_xmlrpc_call( $method_name ) {
		++self::$inner_call_count;

		if ( null === self::$method_name ) {
			self::$method_name = $method_name;
		}
	}

	/**
	 * Increments the failed-login counter.
	 *
	 * @param mixed $error XML-RPC login error value, passed through unchanged.
	 *
	 * @return mixed
	 */
	public function on_xmlrpc_login_error( $error ) {
		++self::$failed_login_count;

		return $error;
	}

	/**
	 * Performs a bounded read of the raw request body and extracts the
	 * top-level methodName with a simple regex, avoiding a full XML parser.
	 *
	 * @return void
	 */
	public function capture_method_name_from_body() {
		if ( null !== self::$method_name ) {
			return;
		}

		$input_stream = fopen( 'php://input', 'rb' );

		if ( false === $input_stream ) {
			return;
		}

		$body_chunk = fread( $input_stream, 8192 );
		fclose( $input_stream );

		if ( false === $body_chunk || '' === $body_chunk ) {
			return;
		}

		if ( preg_match( '#<methodName>([^<]+)</methodName>#i', $body_chunk, $method_name_matches ) ) {
			self::$method_name = trim( $method_name_matches[1] );
		}
	}

	/**
	 * Returns the detail text for a matching request, describing the
	 * method called, the multicall count and any failed logins.
	 *
	 * @param Request_Context $context Request context that matched.
	 *
	 * @return string|null
	 */
	public function get_detail( Request_Context $context ) {
		$detail_parts = array();

		if ( self::$method_name && self::$inner_call_count > 1 ) {
			$detail_parts[] = self::$method_name . ' \u00d7' . self::$inner_call_count;
		} elseif ( self::$method_name ) {
			$detail_parts[] = self::$method_name;
		} else {
			$detail_parts[] = $context->get_method() . ' (recon)';
		}

		if ( self::$failed_login_count > 0 ) {
			$detail_parts[] = self::$failed_login_count . ' failed logins';
		}

		return implode( ' \u00b7 ', $detail_parts );
	}

	/**
	 * Resets the static counters, for reuse across requests in tests.
	 *
	 * @return void
	 */
	public function reset() {
		self::$method_name          = null;
		self::$inner_call_count     = 0;
		self::$failed_login_count   = 0;
		self::$listeners_registered = false;
	}
}