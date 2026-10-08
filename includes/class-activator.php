<?php

namespace AttackLog;

defined( 'ABSPATH' ) || exit;

class Activator {

	public static function activate() {
		Schema::create_or_upgrade();

		Cf_Detector::maybe_auto_set_on_activation();

		if ( ! wp_next_scheduled( 'attacklog_purge' ) ) {
			wp_schedule_event( time(), 'daily', 'attacklog_purge' );
		}
	}
}