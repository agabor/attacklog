<?php
/**
 * Classification and persistence of logged requests.
 *
 * @package AttackLog
 */

namespace AttackLog;

defined( 'ABSPATH' ) || exit;

/**
 * Classifies the current request on shutdown and, when it matches at
 * least one error type, writes it to the database.
 */
class Logger {

	/**
	 * Classifier instance used to evaluate the request.
	 *
	 * @var Classifier
	 */
	private $classifier;

	/**
	 * Repository instance used to persist matched requests.
	 *
	 * @var Repository
	 */
	private $repository;

	/**
	 * Constructor.
	 *
	 * @param Classifier $classifier Classifier instance.
	 * @param Repository $repository Repository instance.
	 */
	public function __construct( Classifier $classifier, Repository $repository ) {
		$this->classifier = $classifier;
		$this->repository = $repository;
	}

	/**
	 * Classifies and, if needed, logs the given request context.
	 *
	 * Wrapped so a failure here can never break the site: any exception
	 * is caught and, when WP_DEBUG is enabled, written to the PHP error
	 * log instead of being allowed to propagate.
	 *
	 * @param Request_Context $context Request context to classify and log.
	 *
	 * @return void
	 */
	public function handle( Request_Context $context ) {
		try {
			$this->process( $context );
		} catch ( \Throwable $caught_exception ) {
			if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
				error_log( // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
					sprintf( 'Attack Log: %s', $caught_exception->getMessage() )
				);
			}
		}
	}

	/**
	 * Performs the actual classification and, if the request matched
	 * anything, writes it to the database.
	 *
	 * @param Request_Context $context Request context to classify and log.
	 *
	 * @return void
	 */
	private function process( Request_Context $context ) {
		if ( $this->classifier->should_skip( $context ) ) {
			return;
		}

		$matched_error_types = $this->classifier->evaluate( $context );

		if ( empty( $matched_error_types ) ) {
			return;
		}

		$this->write_log_entry( $context, $matched_error_types );
	}

	/**
	 * Writes one logged request and its matched error types to the
	 * database, in a single transaction.
	 *
	 * @param Request_Context $context             Request context being logged.
	 * @param array            $matched_error_types Map of error_type_id => detail.
	 *
	 * @return void
	 */
	private function write_log_entry( Request_Context $context, array $matched_error_types ) {
		global $wpdb;

		$ip_resolver = new Ip_Resolver();

		$request_type_id = $this->repository->upsert_request_type(
			$context->get_method(),
			$context->get_normalized_path()
		);

		$user_agent_id = $this->repository->upsert_user_agent( $context->get_user_agent() );

		$client_ip_binary = '' !== $context->get_client_ip()
			? $ip_resolver->to_binary( $context->get_client_ip() )
			: null;

		$remote_addr_binary = '' !== $context->get_remote_addr()
			? $ip_resolver->to_binary( $context->get_remote_addr() )
			: null;

		$wpdb->query( 'START TRANSACTION' ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching

		$request_id = $this->repository->insert_request(
			array(
				'request_type_id' => $request_type_id,
				'return_code'     => $context->get_status_code(),
				'cf_ray'          => $context->get_cf_ray(),
				'cf_ipcountry'    => $context->get_cf_ipcountry(),
				'cf_visitor'      => $context->get_cf_visitor(),
				'client_ip'       => $client_ip_binary,
				'remote_addr'     => $remote_addr_binary,
				'user_agent_id'   => $user_agent_id,
				'created_at'      => gmdate( 'Y-m-d H:i:s' ),
			)
		);

		$this->repository->insert_request_errors( $request_id, $matched_error_types );

		$wpdb->query( 'COMMIT' ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
	}
}