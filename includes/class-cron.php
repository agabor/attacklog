<?php

namespace AttackLog;

defined( 'ABSPATH' ) || exit;

class Cron {

	const HOOK = 'attacklog_purge';

	const DEFAULT_KEEP_DAYS = 30;

	const MIN_KEEP_DAYS = 1;

	const MAX_KEEP_DAYS = 365;

	private $repository;

	public function __construct( Repository $repository ) {
		$this->repository = $repository;
	}

	public function register_hooks(): void {
		add_action( self::HOOK, array( $this, 'run' ) );
		add_action( 'plugins_loaded', array( $this, 'ensure_scheduled' ) );
	}

	public function ensure_scheduled(): void {
		if ( ! wp_next_scheduled( self::HOOK ) ) {
			wp_schedule_event( time(), 'daily', self::HOOK );
		}
	}

	public function run(): int {
		try {
			return $this->repository->delete_requests_older_than( $this->get_keep_days() );
		} catch ( \Throwable $caught_exception ) {
			if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
				error_log(
					sprintf( 'Attack Log: %s', $caught_exception->getMessage() )
				);
			}

			return 0;
		}
	}

	public function get_keep_days(): int {
		$stored_settings = get_option( 'attacklog_settings', array() );
		$keep_days       = self::DEFAULT_KEEP_DAYS;

		if ( is_array( $stored_settings ) && ! empty( $stored_settings['keep_days'] ) && is_numeric( $stored_settings['keep_days'] ) ) {
			$keep_days = (int) $stored_settings['keep_days'];
		}

		return max( self::MIN_KEEP_DAYS, min( self::MAX_KEEP_DAYS, $keep_days ) );
	}
}