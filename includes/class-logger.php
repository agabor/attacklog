<?php
namespace AttackLog;

defined( 'ABSPATH' ) || exit;

class Logger {

	private $classifier;

	private $repository;

	public function __construct( Classifier $classifier, Repository $repository ) {
		$this->classifier = $classifier;
		$this->repository = $repository;
	}

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

		$wpdb->query( 'START TRANSACTION' );

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

		$wpdb->query( 'COMMIT' );
	}
}