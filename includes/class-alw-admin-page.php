<?php

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class ALW_Admin_Page {

	public static function init() {
		add_action( 'admin_menu', array( 'ALW_Admin_Page', 'add_menu' ) );
		add_action( 'admin_post_alw_clear_logs', array( 'ALW_Admin_Page', 'handle_clear_logs' ) );
	}

	public static function add_menu() {
		add_management_page(
			'Attack Log',
			'Attack Log',
			'manage_options',
			'attacklog',
			array( 'ALW_Admin_Page', 'render_page' )
		);
	}

	public static function render_page() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		ALW_Request_Filter::save_admin_indicators();

		$logs = ALW_Logger::get_logs();
		$current_ip = ALW_Request_Filter::get_client_ip();
		$current_ip_is_cloudflare = ! empty( $current_ip ) ? ALW_Request_Filter::is_cloudflare_ip( $current_ip ) : false;
		$present_cloudflare_headers = ALW_Request_Filter::get_present_cloudflare_headers();
		$has_cloudflare_headers = ! empty( $present_cloudflare_headers );

		$forwarded_for_header = isset( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) : '';

		$forwarded_for_has_cloudflare_ip = ALW_Request_Filter::xff_contains_cloudflare_ip( $forwarded_for_header );

		$baseline_indicators = get_option( 'alw_admin_cloudflare_indicators', array() );

		?>
		<div class="wrap">
			<h1>Attack Log</h1>

			<h2>Cloudflare Indicators</h2>
			<p>
				<strong>IP Address:</strong> <?php echo esc_html( $current_ip ); ?><br />
				<strong>X-Forwarded-For:</strong> <?php echo esc_html( $forwarded_for_header ); ?><br />
				<strong>Within Cloudflare's IP Range:</strong>
				<?php echo $current_ip_is_cloudflare ? 'Yes' : 'No'; ?><br />
				<?php if ( '' !== $forwarded_for_header ) : ?>
					<strong>X-Forwarded-For Contains Cloudflare IP:</strong>
					<?php echo $forwarded_for_has_cloudflare_ip ? 'Yes' : 'No'; ?><br />
				<?php endif; ?>
				<strong>Cloudflare Headers Present:</strong>
				<?php echo $has_cloudflare_headers ? 'Yes' : 'No'; ?>
				<?php if ( $has_cloudflare_headers ) : ?>
					<br />
					<?php echo self::format_log_headers( $present_cloudflare_headers ); ?>
				<?php endif; ?>
			</p>

			<h2>Baseline Indicators (Admin)</h2>
			<p>
				<strong>IP in Cloudflare range:</strong>
				<?php echo ! empty( $baseline_indicators['ip_in_range'] ) ? 'Yes' : 'No'; ?><br />
				<strong>X-Forwarded-For in Cloudflare range:</strong>
				<?php echo ! empty( $baseline_indicators['xff_in_range'] ) ? 'Yes' : 'No'; ?><br />
				<?php if ( ! empty( $baseline_indicators['headers'] ) && is_array( $baseline_indicators['headers'] ) ) : ?>
					<?php foreach ( $baseline_indicators['headers'] as $label => $was_present ) : ?>
						<strong><?php echo esc_html( $label ); ?> header:</strong>
						<?php echo $was_present ? 'Yes' : 'No'; ?><br />
					<?php endforeach; ?>
				<?php endif; ?>
			</p>

			<h2>Forbidden Request Logs</h2>
			<table class="wp-list-table widefat fixed striped">
				<thead>
					<tr>
						<th>Timestamp</th>
						<th>IP Address</th>
						<th>Request URI</th>
						<th>User Agent</th>
						<th>HTTP Status</th>
						<th>Cloudflare Status</th>
						<th>Headers</th>
						<th>Missing Indicators</th>
					</tr>
				</thead>
				<tbody>
					<?php if ( empty( $logs ) ) : ?>
						<tr>
							<td colspan="8">No logs found.</td>
						</tr>
					<?php else : ?>
						<?php foreach ( $logs as $entry ) : ?>
							<tr>
								<td><?php echo esc_html( $entry['timestamp'] ); ?></td>
								<td><?php echo esc_html( $entry['ip'] ); ?></td>
								<td><?php echo esc_html( $entry['uri'] ); ?></td>
								<td><?php echo esc_html( isset( $entry['user_agent'] ) ? $entry['user_agent'] : '' ); ?></td>
								<td><?php echo esc_html( isset( $entry['status'] ) ? $entry['status'] : '' ); ?></td>
								<td><?php echo esc_html( isset( $entry['cf_status'] ) ? $entry['cf_status'] : '' ); ?></td>
								<td><?php echo self::format_log_headers( isset( $entry['headers'] ) ? $entry['headers'] : array() ); ?></td>
								<td><?php echo self::format_missing_indicators( isset( $entry['missing_indicators'] ) ? $entry['missing_indicators'] : array() ); ?></td>
							</tr>
						<?php endforeach; ?>
					<?php endif; ?>
				</tbody>
			</table>

			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<input type="hidden" name="action" value="alw_clear_logs" />
				<?php wp_nonce_field( 'alw_clear_logs_action', 'alw_clear_logs_nonce' ); ?>
				<p class="submit">
					<input type="submit" class="button button-secondary" value="Clear Logs" />
				</p>
			</form>
		</div>
		<?php
	}

	private static function format_log_headers( $headers ) {
		if ( empty( $headers ) || ! is_array( $headers ) ) {
			return '';
		}

		$lines = array();

		foreach ( $headers as $label => $value ) {
			$lines[] = '<strong>' . esc_html( $label ) . ':</strong> ' . esc_html( $value );
		}

		return implode( '<br />', $lines );
	}

	private static function format_missing_indicators( $missing_indicators ) {
		if ( empty( $missing_indicators ) || ! is_array( $missing_indicators ) ) {
			return '';
		}

		$lines = array();

		foreach ( $missing_indicators as $label ) {
			$lines[] = esc_html( $label );
		}

		return implode( '<br />', $lines );
	}

	public static function handle_clear_logs() {
		if ( ! isset( $_POST['alw_clear_logs_nonce'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['alw_clear_logs_nonce'] ) ), 'alw_clear_logs_action' ) ) {
			wp_die( 'Security check failed.' );
		}

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'You do not have permission to perform this action.' );
		}

		ALW_Logger::clear_logs();

		wp_safe_redirect( admin_url( 'tools.php?page=attacklog' ) );
		exit;
	}
}