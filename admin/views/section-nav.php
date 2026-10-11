<?php
/**
 * Section navigation partial.
 *
 * Expected input: $sections, a list of arrays with the keys label, url and is_active.
 */

defined( 'ABSPATH' ) || exit;
?>
<nav class="attacklog-sections" aria-label="<?php esc_attr_e( 'Attack Log sections', 'attacklog' ); ?>">
	<?php foreach ( $sections as $attacklog_section ) : ?>
		<a
			class="attacklog-section-link<?php echo ! empty( $attacklog_section['is_active'] ) ? ' is-active' : ''; ?>"
			href="<?php echo esc_url( $attacklog_section['url'] ); ?>"
			<?php echo ! empty( $attacklog_section['is_active'] ) ? 'aria-current="page"' : ''; ?>
		><?php echo esc_html( $attacklog_section['label'] ); ?></a>
	<?php endforeach; ?>
</nav>