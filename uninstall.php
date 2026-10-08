<?php

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

require_once plugin_dir_path( __FILE__ ) . 'includes/class-schema.php';

function attacklog_uninstall_site(): void {
	global $wpdb;

	$table_suffixes_children_first = array(
		'request_errors',
		'requests',
		'request_types',
		'user_agents',
		'error_types',
	);

	foreach ( $table_suffixes_children_first as $table_suffix ) {
		$table_name = \AttackLog\Schema::get_table_name( $table_suffix );

		$wpdb->query( "DROP TABLE IF EXISTS {$table_name}" );
	}

	$option_names = array(
		'attacklog_cf_status',
		'attacklog_settings',
		'attacklog_whitelist',
		'attacklog_db_version',
	);

	foreach ( $option_names as $option_name ) {
		delete_option( $option_name );
	}

	wp_clear_scheduled_hook( 'attacklog_purge' );

	wp_cache_delete( 'cache_version', 'attacklog' );
}

function attacklog_uninstall_users(): void {
	delete_metadata( 'user', 0, 'attacklog_last_tab', '', true );
}

function attacklog_uninstall(): void {
	if ( is_multisite() ) {
		$site_ids = get_sites(
			array(
				'fields' => 'ids',
				'number' => 0,
			)
		);

		foreach ( $site_ids as $site_id ) {
			switch_to_blog( (int) $site_id );

			attacklog_uninstall_site();

			restore_current_blog();
		}
	} else {
		attacklog_uninstall_site();
	}

	attacklog_uninstall_users();
}

attacklog_uninstall();