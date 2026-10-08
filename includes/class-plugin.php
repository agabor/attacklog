<?php

namespace AttackLog;

use AttackLog\Admin\Admin_Page;
use AttackLog\Admin\Log_Controller;
use AttackLog\Rules\Cf_Bypass_Rule;
use AttackLog\Rules\Probe_Rule;
use AttackLog\Rules\Direct_Php_Rule;
use AttackLog\Rules\Xmlrpc_Rule;
use AttackLog\Rules\Suspicious_Ua_Rule;

defined( 'ABSPATH' ) || exit;

class Plugin {

	private static $instance = null;

	private $request_context;

	private $classifier;

	private $repository;

	private $logger;

	private $xmlrpc_rule;

	private function __construct() {}

	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}

		return self::$instance;
	}

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

		if ( is_admin() ) {
			$this->boot_admin();
		}
	}

	private function boot_admin(): void {
		$admin_page     = new Admin_Page( $this->repository );
		$log_controller = new Log_Controller( $this->repository );

		$admin_page->register_hooks();
		$log_controller->register_hooks();
	}

	public function register_runtime_hooks() {
		add_filter( 'status_header', array( $this, 'handle_status_header' ), 10, 2 );
		add_action( 'xmlrpc_call', array( $this, 'handle_xmlrpc_call' ) );
		add_filter( 'xmlrpc_login_error', array( $this, 'handle_xmlrpc_login_error' ) );
		add_action( 'shutdown', array( $this, 'handle_shutdown' ) );
	}

	public function handle_status_header( $status_header, $code ) {
		$this->request_context->set_status_code( $code );

		return $status_header;
	}

	public function handle_xmlrpc_call( $method_name ) {
		$this->xmlrpc_rule->on_xmlrpc_call( $method_name );
	}

	public function handle_xmlrpc_login_error( $error ) {
		return $this->xmlrpc_rule->on_xmlrpc_login_error( $error );
	}

	public function handle_shutdown() {
		if ( 0 === $this->request_context->get_status_code() ) {
			$fallback_status_code = http_response_code();

			if ( false !== $fallback_status_code ) {
				$this->request_context->set_status_code( $fallback_status_code );
			}
		}

		$this->logger->handle( $this->request_context );
	}

	public function get_request_context() {
		return $this->request_context;
	}
}