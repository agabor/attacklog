<?php

namespace AttackLog;

defined( 'ABSPATH' ) || exit;

class Request_Context {

	private $method;

	private $raw_path;

	private $normalized_path;

	private $client_ip;

	private $remote_addr;

	private $user_agent;

	private $cf_ray;

	private $cf_ipcountry;

	private $cf_visitor;

	private $has_all_cf_headers;

	private $is_cloudflare_trusted;

	private $status_code = 0;

	private function __construct() {}

	public static function capture() {
		$request_context = new self();

		$ip_resolver = new Ip_Resolver();

		$request_context->method = isset( $_SERVER['REQUEST_METHOD'] )
			? strtoupper( sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) )
			: '';

		$request_context->raw_path = isset( $_SERVER['REQUEST_URI'] )
			? wp_unslash( $_SERVER['REQUEST_URI'] )
			: '';

		$request_context->normalized_path = self::normalize_path( $request_context->raw_path );

		$request_context->client_ip   = $ip_resolver->resolve_client_ip();
		$request_context->remote_addr = $ip_resolver->resolve_remote_addr();

		$raw_user_agent = isset( $_SERVER['HTTP_USER_AGENT'] )
			? wp_unslash( $_SERVER['HTTP_USER_AGENT'] )
			: null;

		$request_context->user_agent = self::sanitize_user_agent( $raw_user_agent );

		$request_context->cf_ray = ! empty( $_SERVER['HTTP_CF_RAY'] )
			? sanitize_text_field( wp_unslash( $_SERVER['HTTP_CF_RAY'] ) )
			: null;

		$request_context->cf_ipcountry = ! empty( $_SERVER['HTTP_CF_IPCOUNTRY'] )
			? sanitize_text_field( wp_unslash( $_SERVER['HTTP_CF_IPCOUNTRY'] ) )
			: null;

		$request_context->cf_visitor = ! empty( $_SERVER['HTTP_CF_VISITOR'] )
			? sanitize_text_field( wp_unslash( $_SERVER['HTTP_CF_VISITOR'] ) )
			: null;

		$request_context->has_all_cf_headers    = Cf_Detector::request_has_all_cf_headers();
		$request_context->is_cloudflare_trusted = Cf_Detector::is_cloudflare_trusted_request();

		return $request_context;
	}

	public function get_method() {
		return $this->method;
	}

	public function get_raw_path() {
		return $this->raw_path;
	}

	public function get_normalized_path() {
		return $this->normalized_path;
	}

	public function get_client_ip() {
		return $this->client_ip;
	}

	public function get_remote_addr() {
		return $this->remote_addr;
	}

	public function get_user_agent() {
		return $this->user_agent;
	}

	public function get_cf_ray() {
		return $this->cf_ray;
	}

	public function get_cf_ipcountry() {
		return $this->cf_ipcountry;
	}

	public function get_cf_visitor() {
		return $this->cf_visitor;
	}

	public function has_all_cf_headers() {
		return $this->has_all_cf_headers;
	}

	public function is_cloudflare_trusted() {
		return $this->is_cloudflare_trusted;
	}

	public function get_status_code() {
		return $this->status_code;
	}

	public function set_status_code( $status_code ) {
		$this->status_code = (int) $status_code;
	}

	public function is_xmlrpc_request() {
		return ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) || '/xmlrpc.php' === $this->normalized_path;
	}

	public static function normalize_path( $raw_uri ) {
		$path_without_query = wp_parse_url( $raw_uri, PHP_URL_PATH );

		if ( null === $path_without_query || false === $path_without_query ) {
			$path_without_query = $raw_uri;
		}

		$decoded_path    = rawurldecode( $path_without_query );
		$lowercased_path = strtolower( $decoded_path );
		$collapsed_path  = preg_replace( '#/+#', '/', $lowercased_path );

		$site_path = wp_parse_url( home_url(), PHP_URL_PATH );

		if ( ! empty( $site_path ) && '/' !== $site_path ) {
			$lowercased_site_path = strtolower( $site_path );

			if ( 0 === strpos( $collapsed_path, $lowercased_site_path ) ) {
				$collapsed_path = substr( $collapsed_path, strlen( $lowercased_site_path ) );
			}
		}

		if ( '' === $collapsed_path || '/' !== $collapsed_path[0] ) {
			$collapsed_path = '/' . $collapsed_path;
		}

		return substr( $collapsed_path, 0, 2048 );
	}

	public static function sanitize_user_agent( $raw_user_agent ) {
		if ( null === $raw_user_agent ) {
			return null;
		}

		$trimmed_user_agent = trim( $raw_user_agent );

		if ( '' === $trimmed_user_agent ) {
			return null;
		}

		$stripped_user_agent = preg_replace( '/[\x00-\x1F\x7F]/', '', $trimmed_user_agent );

		if ( null === $stripped_user_agent || '' === $stripped_user_agent ) {
			return null;
		}

		return substr( $stripped_user_agent, 0, 512 );
	}
}