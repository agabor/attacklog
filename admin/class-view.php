<?php

namespace AttackLog\Admin;

defined( 'ABSPATH' ) || exit;

final class View {

	public static function render( string $template, array $data = array() ): void {
		$template_path = ATTACKLOG_PLUGIN_DIR . 'admin/views/' . $template . '.php';

		if ( ! file_exists( $template_path ) ) {
			return;
		}

		self::load_template( $template_path, $data );
	}

	public static function render_to_string( string $template, array $data = array() ): string {
		ob_start();

		self::render( $template, $data );

		return (string) ob_get_clean();
	}

	private static function load_template( string $template_path, array $data ): void {
		extract( $data, EXTR_SKIP );

		require $template_path;
	}
}