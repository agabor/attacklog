<?php

defined( 'ABSPATH' ) || exit;
?>
<div class="wrap attacklog-wrap">
	<h1 class="attacklog-title"><?php esc_html_e( 'Attack Log', 'attacklog' ); ?></h1>

	<?php \AttackLog\Admin\View::render( 'section-nav', array( 'sections' => $sections ) ); ?>

	<div class="attacklog-card attacklog-cf-card">
		<p class="attacklog-cf-note attacklog-cf-note--<?php echo esc_attr( $cloudflare['live_note']['status'] ); ?>">
			<span class="attacklog-cf-note__icon" aria-hidden="true"><?php echo esc_html( $cloudflare['live_note_icon'] ); ?></span>
			<span class="attacklog-cf-note__text"><?php echo esc_html( $cloudflare['live_note']['message'] ); ?></span>
		</p>

		<?php if ( ! empty( $cloudflare['hint'] ) ) : ?>
			<p class="attacklog-cf-hint"><?php echo esc_html( $cloudflare['hint'] ); ?></p>
		<?php endif; ?>

		<div class="attacklog-cf-switch">
			<span class="attacklog-cf-switch__label" id="attacklog-cf-switch-label"><?php esc_html_e( 'Cloudflare bypass detection', 'attacklog' ); ?></span>
			<button
				type="button"
				class="attacklog-switch<?php echo ! empty( $cloudflare['enabled'] ) ? ' is-on' : ''; ?>"
				id="attacklog-cf-switch"
				role="switch"
				aria-checked="<?php echo ! empty( $cloudflare['enabled'] ) ? 'true' : 'false'; ?>"
				aria-labelledby="attacklog-cf-switch-label"
				data-enabled="<?php echo ! empty( $cloudflare['enabled'] ) ? '1' : '0'; ?>"
			>
				<span class="attacklog-switch__knob"></span>
				<span class="attacklog-switch__state"><?php echo ! empty( $cloudflare['enabled'] ) ? esc_html__( 'On', 'attacklog' ) : esc_html__( 'Off', 'attacklog' ); ?></span>
			</button>
		</div>

		<p class="attacklog-cf-footer" id="attacklog-cf-set-by"><?php echo esc_html( $cloudflare['description'] ); ?></p>
	</div>

	<nav class="attacklog-tabs" aria-label="<?php esc_attr_e( 'Error types', 'attacklog' ); ?>">
		<?php foreach ( $tabs as $tab ) : ?>
			<a
				class="<?php echo esc_attr( $tab['css_classes'] ); ?>"
				href="<?php echo esc_url( $tab['url'] ); ?>"
				<?php echo ! empty( $tab['is_active'] ) ? 'aria-current="page"' : ''; ?>
			>
				<span class="attacklog-tab__label"><?php echo esc_html( $tab['label'] ); ?></span>
				<span class="attacklog-tab__count"<?php echo '' !== $tab['tooltip'] ? ' title="' . esc_attr( $tab['tooltip'] ) . '"' : ''; ?>><?php echo esc_html( number_format_i18n( (int) $tab['count'] ) ); ?></span>
				<?php if ( ! empty( $tab['is_detection_off'] ) ) : ?>
					<span class="attacklog-tab__note"><?php esc_html_e( 'detection off', 'attacklog' ); ?></span>
				<?php endif; ?>
			</a>
		<?php endforeach; ?>
	</nav>

	<div class="attacklog-card attacklog-log-card">
		<?php if ( empty( $rows ) ) : ?>
			<p class="attacklog-empty"><?php echo esc_html( $current_tab['empty_message'] ); ?></p>
		<?php else : ?>
			<div class="attacklog-table-scroll">
				<table class="attacklog-table">
					<thead>
						<tr>
							<th scope="col">
								<a class="attacklog-sort" href="<?php echo esc_url( $sort['time_url'] ); ?>">
									<?php esc_html_e( 'Time', 'attacklog' ); ?>
									<span class="attacklog-sort__indicator" aria-hidden="true"><?php echo esc_html( $sort['time_indicator'] ); ?></span>
								</a>
							</th>
							<th scope="col"><?php esc_html_e( 'Method', 'attacklog' ); ?></th>
							<th scope="col"><?php esc_html_e( 'Path', 'attacklog' ); ?></th>
							<th scope="col">
								<a class="attacklog-sort" href="<?php echo esc_url( $sort['code_url'] ); ?>">
									<?php esc_html_e( 'Code', 'attacklog' ); ?>
									<span class="attacklog-sort__indicator" aria-hidden="true"><?php echo esc_html( $sort['code_indicator'] ); ?></span>
								</a>
							</th>
							<th scope="col"><?php esc_html_e( 'IP', 'attacklog' ); ?></th>
							<th scope="col"><?php echo esc_html( $badge_column_label ); ?></th>
							<th scope="col"><?php esc_html_e( 'Whitelist', 'attacklog' ); ?></th>
						</tr>
					</thead>
					<tbody>
						<?php foreach ( $rows as $attacklog_row ) : ?>
							<tr>
								<td class="attacklog-cell attacklog-cell--time"><?php echo esc_html( $attacklog_row['time'] ); ?></td>
								<td class="attacklog-cell attacklog-cell--method"><?php echo esc_html( $attacklog_row['method'] ); ?></td>
								<td class="attacklog-cell attacklog-cell--path">
									<span class="attacklog-mono attacklog-ellipsis" title="<?php echo esc_attr( $attacklog_row['path'] ); ?>"><?php echo esc_html( $attacklog_row['path'] ); ?></span>
									<span class="attacklog-second-line attacklog-mono attacklog-ellipsis" title="<?php echo esc_attr( $attacklog_row['second_line'] ); ?>"><?php echo esc_html( $attacklog_row['second_line'] ); ?></span>
								</td>
								<td class="attacklog-cell attacklog-cell--code"><span class="attacklog-code <?php echo esc_attr( $attacklog_row['status_class'] ); ?>"><?php echo esc_html( (string) $attacklog_row['status_code'] ); ?></span></td>
								<td class="attacklog-cell attacklog-cell--ip">
									<span class="attacklog-mono"><?php echo '' !== $attacklog_row['client_ip'] ? esc_html( $attacklog_row['client_ip'] ) : '—'; ?></span>
									<?php if ( ! empty( $attacklog_row['addresses_differ'] ) ) : ?>
										<span class="attacklog-remote-addr attacklog-mono is-different" title="<?php esc_attr_e( 'Actual connecting address differs from the client IP', 'attacklog' ); ?>"><?php echo esc_html( $attacklog_row['remote_addr'] ); ?></span>
									<?php endif; ?>
								</td>
								<td class="attacklog-cell attacklog-cell--types">
									<?php foreach ( $attacklog_row['badges'] as $attacklog_badge ) : ?>
										<a class="attacklog-badge <?php echo esc_attr( $attacklog_badge['badge_class'] ); ?>" href="<?php echo esc_url( $attacklog_badge['url'] ); ?>"><?php echo esc_html( $attacklog_badge['label'] ); ?></a>
									<?php endforeach; ?>
								</td>
								<td class="attacklog-cell attacklog-cell--whitelist">
									<?php foreach ( $attacklog_row['whitelist'] as $attacklog_button_kind => $attacklog_whitelist_button ) : ?>
										<button
											type="button"
											class="button button-small attacklog-wl-row-button<?php echo ! empty( $attacklog_whitelist_button['exists'] ) ? ' is-existing' : ''; ?>"
											data-kind="<?php echo esc_attr( $attacklog_button_kind ); ?>"
											data-prefill="<?php echo esc_attr( $attacklog_whitelist_button['prefill_json'] ); ?>"
											data-existing="<?php echo esc_attr( $attacklog_whitelist_button['existing_json'] ); ?>"
											title="<?php echo esc_attr( $attacklog_whitelist_button['title'] ); ?>"
											<?php disabled( ! empty( $attacklog_whitelist_button['disabled'] ) ); ?>
										><?php echo esc_html( ( ! empty( $attacklog_whitelist_button['exists'] ) ? '✓ ' : '+ ' ) . $attacklog_whitelist_button['label'] ); ?></button>
									<?php endforeach; ?>
								</td>
							</tr>
						<?php endforeach; ?>
					</tbody>
				</table>
			</div>
		<?php endif; ?>

		<?php if ( $total_pages > 1 ) : ?>
			<div class="attacklog-pagination">
				<?php
				echo wp_kses_post(
					paginate_links(
						array(
							'base'      => $pagination_base,
							'format'    => '',
							'current'   => $page,
							'total'     => $total_pages,
							'prev_text' => '‹',
							'next_text' => '›',
							'type'      => 'plain',
						)
					)
				);
				?>
			</div>
		<?php endif; ?>

		<div class="attacklog-footer">
			<p class="attacklog-footer__count">
				<?php
				echo esc_html(
					sprintf(
						/* translators: %s: number of logged requests. */
						_n( '%s request', '%s requests', $total_items, 'attacklog' ),
						number_format_i18n( $total_items )
					)
				);
				?>
			</p>

			<div class="attacklog-footer__actions">
				<?php if ( ! $is_all_tab ) : ?>
					<button
						type="button"
						class="button attacklog-clear-type"
						data-type-id="<?php echo esc_attr( (string) (int) $current_tab['error_type_id'] ); ?>"
						data-label="<?php echo esc_attr( $current_tab['label'] ); ?>"
					>
						<?php
						echo esc_html(
							sprintf(
								/* translators: %s: error type name. */
								__( 'Clear %s', 'attacklog' ),
								$current_tab['label']
							)
						);
						?>
					</button>
				<?php endif; ?>
				<button type="button" class="button button-link-delete attacklog-clear-all"><?php esc_html_e( 'Clear all', 'attacklog' ); ?></button>
			</div>

			<p class="attacklog-footer__autoclean">
				<?php
				echo esc_html(
					sprintf(
						/* translators: %s: number of days. */
						_n(
							'Auto-clean: entries older than %s day are removed daily.',
							'Auto-clean: entries older than %s days are removed daily.',
							$keep_days,
							'attacklog'
						),
						number_format_i18n( $keep_days )
					)
				);
				?>
			</p>
		</div>
	</div>

	<?php
	\AttackLog\Admin\View::render(
		'whitelist-form',
		array(
			'category_options' => $category_options,
			'ua_hint'          => $ua_hint,
			'is_modal'         => true,
		)
	);
	?>
</div>