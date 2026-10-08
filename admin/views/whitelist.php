<?php

defined( 'ABSPATH' ) || exit;

$entries    = $view_data['entries'];
$current_ip = $view_data['current_ip'];
?>
<div class="wrap attacklog-wrap">
	<h1 class="attacklog-title"><?php esc_html_e( 'Attack Log', 'attack-log' ); ?></h1>

	<?php require ATTACKLOG_PLUGIN_DIR . 'admin/views/section-nav.php'; ?>

	<div class="attacklog-wl-toolbar">
		<button type="button" class="button button-primary" id="attacklog-wl-add"><?php esc_html_e( 'Add entry', 'attack-log' ); ?></button>
		<button
			type="button"
			class="button"
			id="attacklog-wl-add-current-ip"
			data-current-ip="<?php echo esc_attr( $current_ip ); ?>"
			<?php disabled( '' === $current_ip ); ?>
		><?php esc_html_e( 'Add my current IP', 'attack-log' ); ?></button>
	</div>

	<?php
	$whitelist_form_is_modal = false;

	require ATTACKLOG_PLUGIN_DIR . 'admin/views/whitelist-form.php';
	?>

	<div class="attacklog-card attacklog-wl-card">
		<?php if ( empty( $entries ) ) : ?>
			<p class="attacklog-empty"><?php esc_html_e( 'No whitelist entries yet. Whitelisted IPs and User-Agents are not logged.', 'attack-log' ); ?></p>
		<?php else : ?>
			<div class="attacklog-table-scroll">
				<table class="attacklog-table attacklog-wl-table">
					<thead>
						<tr>
							<th scope="col"><?php esc_html_e( 'Type', 'attack-log' ); ?></th>
							<th scope="col"><?php esc_html_e( 'Value (exact)', 'attack-log' ); ?></th>
							<th scope="col"><?php esc_html_e( 'Applies to', 'attack-log' ); ?></th>
							<th scope="col"><?php esc_html_e( 'Note', 'attack-log' ); ?></th>
							<th scope="col"><?php esc_html_e( 'Actions', 'attack-log' ); ?></th>
						</tr>
					</thead>
					<tbody>
						<?php foreach ( $entries as $entry ) : ?>
							<tr>
								<td class="attacklog-cell">
									<span class="attacklog-wl-type attacklog-wl-type--<?php echo esc_attr( $entry['type'] ); ?>"><?php echo esc_html( $entry['type_label'] ); ?></span>
								</td>
								<td class="attacklog-cell attacklog-cell--value">
									<span class="attacklog-mono attacklog-ellipsis" title="<?php echo esc_attr( $entry['value'] ); ?>"><?php echo esc_html( $entry['value'] ); ?></span>
								</td>
								<td class="attacklog-cell"><?php echo esc_html( $entry['applies_to'] ); ?></td>
								<td class="attacklog-cell">
									<span><?php echo esc_html( $entry['note'] ); ?></span>
									<?php if ( '' !== $entry['created_at'] ) : ?>
										<span class="attacklog-second-line attacklog-wl-meta">
											<?php
											echo esc_html(
												'' !== $entry['created_by']
													? sprintf(
														/* translators: 1: user display name, 2: date and time. */
														__( 'Added by %1$s, %2$s', 'attack-log' ),
														$entry['created_by'],
														$entry['created_at']
													)
													: $entry['created_at']
											);
											?>
										</span>
									<?php endif; ?>
								</td>
								<td class="attacklog-cell attacklog-wl-row-actions">
									<button type="button" class="button attacklog-wl-edit" data-entry="<?php echo esc_attr( $entry['entry_json'] ); ?>"><?php esc_html_e( 'Edit', 'attack-log' ); ?></button>
									<button type="button" class="button button-link-delete attacklog-wl-delete" data-entry="<?php echo esc_attr( $entry['entry_json'] ); ?>"><?php esc_html_e( 'Delete', 'attack-log' ); ?></button>
								</td>
							</tr>
						<?php endforeach; ?>
					</tbody>
				</table>
			</div>
		<?php endif; ?>
	</div>
</div>