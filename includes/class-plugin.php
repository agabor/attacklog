<?php
/**
 * Central plugin wiring: hooks, service instances and request lifecycle.
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
 * Boots the plugin on plugins_loaded, builds the shared service instances
 * and wires up the runtime hooks that classify and log the request.
 */
class Plugin {

	/**
	 * Singleton instance.
	 *
	 * @var self|null
	 */
	private static $instance = null;

	/**
	 * Captured context for the current request.
	 *
	 * @var Request_Context
	 */
	private $request_context;

	/**
	 * Classifier instance for the current request.
	 *
	 * @var Classifier
	 */
	private $classifier;

	/**
	 * Repository instance for the current request.
	 *
	 * @var Repository
	 */
	private $repository;

	/**
	 * Logger instance for the current request.
	 *
	 * @var Logger
	 */
	private $logger;

	/**
	 * XML-RPC rule instance, kept to receive xmlrpc_call / xmlrpc_login_error
	 * notifications for the current request.
	 *
	 * @var Xmlrpc_Rule
	 */
	private $xmlrpc_rule;

	/**
	 * Prevents direct instantiation; use instance() instead.
	 */
	private function __construct() {}

	/**
	 * Returns the singleton Plugin instance.
	 *
	 * @return self
	 */
	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}

		return self::$instance;
	}

	/**
	 * Boots the plugin: upgrades the schema, captures the request context,
	 * builds the service instances and registers the runtime hooks.
	 *
	 * @return void
	 */
	public function boot() {
		Schema::create_or_upgrade();

		$this->request_context = Request_Context::capture();

		$cf_bypass_rule     = new Cf_Bypass_Rule();
		$probe_rule         = new Probe_Rule();
		$direct_php_rule    = new Direct_Php_Rule();
		$suspicious_ua_rule = new Suspicious_Ua_Rule();

		$this->xmlrpc_rule = new Xmlrpc_Rule();

		$this->classifier = new Classifier(
			$cf_bypass_rule,
			$probe_rule,
			$direct_php_rule,
			$this->xmlrpc_rule,
			$suspicious_ua_rule
		);

		$this->repository = new Repository();
		$this->logger      = new Logger( $this->classifier, $this->repository );

		if ( $this->request_context->is_xmlrpc_request() ) {
			$this->xmlrpc_rule->register_listeners();
		}

		$this->register_runtime_hooks();
	}

	/**
	 * Registers the hooks needed to capture the final status code,
	 * XML-RPC details, and to classify and log the request on shutdown.
	 *
	 * @return void
	 */
	public function register_runtime_hooks() {
		add_filter( 'status_header', array( $this, 'handle_status_header' ), 10, 2 );
		add_action( 'xmlrpc_call', array( $this, 'handle_xmlrpc_call' ) );
		add_filter( 'xmlrpc_login_error', array( $this, 'handle_xmlrpc_login_error' ) );
		add_action( 'shutdown', array( $this, 'handle_shutdown' ) );
	}

	/**
	 * Captures the final HTTP status code from the status_header filter.
	 *
	 * @param string $status_header Status header string, passed through unchanged.
	 * @param int    $code          Final HTTP status code.
	 *
	 * @return string
	 */
	public function handle_status_header( $status_header, $code ) {
		$this->request_context->set_status_code( $code );

		return $status_header;
	}

	/**
	 * Forwards an xmlrpc_call notification to the XML-RPC rule instance.
	 *
	 * @param string $method_name Name of the XML-RPC method being executed.
	 *
	 * @return void
	 */
	public function handle_xmlrpc_call( $method_name ) {
		$this->xmlrpc_rule->on_xmlrpc_call( $method_name );
	}

	/**
	 * Forwards an xmlrpc_login_error notification to the XML-RPC rule instance.
	 *
	 * @param mixed $error XML-RPC login error value, passed through unchanged.
	 *
	 * @return mixed
	 */
	public function handle_xmlrpc_login_error( $error ) {
		return $this->xmlrpc_rule->on_xmlrpc_login_error( $error );
	}

	/**
	 * Classifies and logs the current request on shutdown, falling back
	 * to http_response_code() if the status_header filter never fired.
	 *
	 * @return void
	 */
	public function handle_shutdown() {
		if ( 0 === $this->request_context->get_status_code() ) {
			$fallback_status_code = http_response_code();

			if ( false !== $fallback_status_code ) {
				$this->request_context->set_status_code( $fallback_status_code );
			}
		}

		$this->logger->handle( $this->request_context );
	}

	/**
	 * Returns the captured Request_Context for the current request.
	 *
	 * @return Request_Context
	 */
	public function get_request_context() {
		return $this->request_context;
	}
}