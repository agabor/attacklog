<?php

namespace AttackLog\Rules;

use AttackLog\Request_Context;

defined( 'ABSPATH' ) || exit;

class Xmlrpc_Rule {

	private static $method_name = null;

	private static $inner_call_count = 0;

	private static $failed_login_count = 0;

	private static $listeners_registered = false;

	public function matches( Request_Context $context ) {
		return $context->is_xmlrpc_request();
	}

	public function register_listeners() {
		if ( self::$listeners_registered ) {
			return;
		}

		self::$listeners_registered = true;

		add_action( 'xmlrpc_call', array( $this, 'on_xmlrpc_call' ) );
		add_filter( 'xmlrpc_login_error', array( $this, 'on_xmlrpc_login_error' ) );

		$this->capture_method_name_from_body();
	}

	public function on_xmlrpc_call( $method_name ) {
		++self::$inner_call_count;

		if ( null === self::$method_name ) {
			self::$method_name = $method_name;
		}
	}

	public function on_xmlrpc_login_error( $error ) {
		++self::$failed_login_count;

		return $error;
	}

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

	public function reset() {
		self::$method_name          = null;
		self::$inner_call_count     = 0;
		self::$failed_login_count   = 0;
		self::$listeners_registered = false;
	}
}