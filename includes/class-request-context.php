<?php
/**
 * Immutable snapshot of the current HTTP request.
 *
 * @package AttackLog
 */

namespace AttackLog;

defined( 'ABSPATH' ) || exit;

/**
 * Captures and exposes the request data needed for classification:
 * method, path, Cloudflare headers, IP addresses and User-Agent.
 */
class Request_Context {

	/**
	 * HTTP method of the request.
	 *
	 * @var string
	 */
	private $method;

	/**
	 * Raw request URI as received.
	 *
	 * @var string
	 */
	private $raw_path;

	/**
	 * Normalized request path.
	 *
	 * @var string
	 */
	private $normalized_path;

	/**
	 * Resolved client IP address.
	 *
	 * @var string
	 */
	private $client_ip;

	/**
	 * Actual connecting IP address.
	 *
	 * @var string
	 */
	private $remote_addr;

	/**
	 * Sanitized User-Agent string, or null when missing.
	 *
	 * @var string|null
	 */
	private $user_agent;

	/**
	 * CF-Ray header value, or null when missing.
	 *
	 * @var string|null
	 */
	private $cf_ray;

	/**
	 * CF-IPCountry header value, or null when missing.
	 *
	 * @var string|null
	 */
	private $cf_ipcountry;

	/**
	 * CF-Visitor header value, or null when missing.
	 *
	 * @var string|null
	 */
	private $cf_visitor;

	/**
	 * Whether all three Cloudflare headers are present.
	 *
	 * @var bool
	 */
	private $has_all_cf_headers;

	/**
	 * Whether this request should be treated as having come through Cloudflare.
	 *
	 * @var bool
	 */
	private $is_cloudflare_trusted;

	/**
	 * Final HTTP status code, set once known.
	 *
	 * @var int
	 */
	private $status_code = 0;

	/**
	 * Prevents direct instantiation; use capture() instead.
	 */
	private function __construct() {}

	/**
	 * Builds a Request_Context instance from the current superglobals.
	 *
	 * @return self
	 */
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

	/**
	 * Returns the HTTP method of the request.
	 *
	 * @return string
	 */
	public function get_method() {
		return $this->method;
	}

	/**
	 * Returns the raw request URI as received.
	 *
	 * @return string
	 */
	public function get_raw_path() {
		return $this->raw_path;
	}

	/**
	 * Returns the normalized request path.
	 *
	 * @return string
	 */
	public function get_normalized_path() {
		return $this->normalized_path;
	}

	/**
	 * Returns the resolved client IP address.
	 *
	 * @return string
	 */
	public function get_client_ip() {
		return $this->client_ip;
	}

	/**
	 * Returns the actual connecting IP address.
	 *
	 * @return string
	 */
	public function get_remote_addr() {
		return $this->remote_addr;
	}

	/**
	 * Returns the sanitized User-Agent string.
	 *
	 * @return string|null
	 */
	public function get_user_agent() {
		return $this->user_agent;
	}

	/**
	 * Returns the CF-Ray header value.
	 *
	 * @return string|null
	 */
	public function get_cf_ray() {
		return $this->cf_ray;
	}

	/**
	 * Returns the CF-IPCountry header value.
	 *
	 * @return string|null
	 */
	public function get_cf_ipcountry() {
		return $this->cf_ipcountry;
	}

	/**
	 * Returns the CF-Visitor header value.
	 *
	 * @return string|null
	 */
	public function get_cf_visitor() {
		return $this->cf_visitor;
	}

	/**
	 * Checks whether all three Cloudflare headers are present on this request.
	 *
	 * @return bool
	 */
	public function has_all_cf_headers() {
		return $this->has_all_cf_headers;
	}

	/**
	 * Checks whether this request should be treated as having come through Cloudflare.
	 *
	 * @return bool
	 */
	public function is_cloudflare_trusted() {
		return $this->is_cloudflare_trusted;
	}

	/**
	 * Returns the final HTTP status code.
	 *
	 * @return int
	 */
	public function get_status_code() {
		return $this->status_code;
	}

	/**
	 * Sets the final HTTP status code once it is known.
	 *
	 * @param int $status_code Final HTTP status code.
	 *
	 * @return void
	 */
	public function set_status_code( $status_code ) {
		$this->status_code = (int) $status_code;
	}

	/**
	 * Checks whether this request is an XML-RPC request.
	 *
	 * @return bool
	 */
	public function is_xmlrpc_request() {
		return ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) || '/xmlrpc.php' === $this->normalized_path;
	}

	/**
	 * Normalizes a raw request URI into a comparable path.
	 *
	 * Strips the query string, URL-decodes once, lowercases, collapses
	 * repeated slashes, strips the site's subdirectory prefix, and
	 * truncates to 2048 characters.
	 *
	 * @param string $raw_uri Raw request URI, as received in REQUEST_URI.
	 *
	 * @return string
	 */
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

	/**
	 * Sanitizes a raw User-Agent header value.
	 *
	 * Trims whitespace, strips control characters, truncates to 512
	 * characters, and returns null when the result is empty.
	 *
	 * @param string|null $raw_user_agent Raw User-Agent header value.
	 *
	 * @return string|null
	 */
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