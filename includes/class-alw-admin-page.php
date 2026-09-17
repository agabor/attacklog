<?php

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class ALW_Admin_Page {

	public static function init() {
		add_action( 'admin_menu', array( 'ALW_Admin_Page', 'add_menu' ) );
		add_action( 'admin_post_alw_clear_logs', array( 'ALW_Admin_Page', 'handle_clear_logs' ) );
		add_action( 'admin_post_alw_update_security_mode', array( 'ALW_Admin_Page', 'handle_update_security_mode' ) );
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

		$logs = ALW_Logger::get_logs();
		$current_security_mode = ALW_Request_Filter::get_security_mode();
		$current_ip = ALW_Request_Filter::get_client_ip();
		$current_ip_is_cloudflare = ! empty( $current_ip ) ? ALW_Request_Filter::is_cloudflare_ip( $current_ip ) : false;
		$present_cloudflare_headers = ALW_Request_Filter::get_present_cloudflare_headers();
		$has_cloudflare_headers = ! empty( $present_cloudflare_headers );

		$forwarded_for_header = isset( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) : '';

		if ( $current_ip_is_cloudflare ) {
			$suggested_mode = 'strict';
		} elseif ( $has_cloudflare_headers ) {
			$suggested_mode = 'reduced';
		} else {
			$suggested_mode = 'none';
		}

		$suggested_mode_labels = array(
			'strict'  => 'Strict',
			'reduced' => 'Reduced',
			'none'    => 'None',
		);

		?>
		<div class="wrap">
			<h1>Attack Log</h1>

			<h2>Logging Level</h2>
			<div class="notice notice-warning inline">
				<p><strong>Warning:</strong> The <code>CF-Connecting-IP</code>, <code>CF-IPCountry</code>, <code>CF-Ray</code>, and <code>CF-Visitor</code> headers are normally only set by Cloudflare, but they can be forged by visitors unless your infrastructure guarantees that requests cannot bypass Cloudflare and reach your origin directly. Enabling the Reduced level may allow attackers to bypass Cloudflare IP restrictions by spoofing these headers. Only enable this if you understand the risks and have verified that your origin server is not directly reachable, bypassing Cloudflare.</p>
			</div>
			<p>
				<strong>IP Address:</strong> <?php echo esc_html( $current_ip ); ?><br />
				<strong>X-Forwarded-For:</strong> <?php echo esc_html( $forwarded_for_header ); ?><br />
				<strong>Within Cloudflare's IP Range:</strong>
				<?php echo $current_ip_is_cloudflare ? 'Yes' : 'No'; ?><br />
				<strong>Cloudflare Headers Present:</strong>
				<?php echo $has_cloudflare_headers ? 'Yes' : 'No'; ?>
				<?php if ( $has_cloudflare_headers ) : ?>
					<br />
					<?php echo self::format_log_headers( $present_cloudflare_headers ); ?>
				<?php endif; ?>
				<br />
				<strong>Suggested level:</strong> <?php echo esc_html( $suggested_mode_labels[ $suggested_mode ] ); ?>
			</p>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<input type="hidden" name="action" value="alw_update_security_mode" />
				<?php wp_nonce_field( 'alw_update_security_mode_action', 'alw_update_security_mode_nonce' ); ?>
				<p>
					<label>
						<input type="radio" name="alw_security_mode" value="strict" <?php checked( 'strict', $current_security_mode ); ?> />
						Strict
					</label>
					<br />
					<label>
						<input type="radio" name="alw_security_mode" value="reduced" <?php checked( 'reduced', $current_security_mode ); ?> />
						Reduced
					</label>
					<br />
					<label>
						<input type="radio" name="alw_security_mode" value="none" <?php checked( 'none', $current_security_mode ); ?> />
						None
					</label>
				</p>
				<p class="submit">
					<input type="submit" class="button button-primary" value="Save" />
				</p>
			</form>

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
					</tr>
				</thead>
				<tbody>
					<?php if ( empty( $logs ) ) : ?>
						<tr>
							<td colspan="7">No logs found.</td>
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

	public static function handle_update_security_mode() {
		if ( ! isset( $_POST['alw_update_security_mode_nonce'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['alw_update_security_mode_nonce'] ) ), 'alw_update_security_mode_action' ) ) {
			wp_die( 'Security check failed.' );
		}

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'You do not have permission to perform this action.' );
		}

		$requested_security_mode = isset( $_POST['alw_security_mode'] ) ? sanitize_text_field( wp_unslash( $_POST['alw_security_mode'] ) ) : 'strict';

		if ( ! in_array( $requested_security_mode, array( 'strict', 'reduced', 'none' ), true ) ) {
			$requested_security_mode = 'strict';
		}

		update_option( 'alw_security_mode', $requested_security_mode );

		wp_safe_redirect( admin_url( 'tools.php?page=attacklog' ) );
		exit;
	}
}