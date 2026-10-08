<?php

namespace AttackLog;

defined( 'ABSPATH' ) || exit;

class Deactivator {

	public static function deactivate() {
		wp_clear_scheduled_hook( 'attacklog_purge' );
	}
}