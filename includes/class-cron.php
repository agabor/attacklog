<?php

namespace AttackLog;

defined( 'ABSPATH' ) || exit;

class Cron {

	const HOOK = 'attacklog_purge';

	const KEEP_DAYS = 30;

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
		return self::KEEP_DAYS;
	}
}