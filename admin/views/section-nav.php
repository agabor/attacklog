<?php

defined( 'ABSPATH' ) || exit;

$sections = $view_data['sections'];
?>
<nav class="attacklog-sections" aria-label="<?php esc_attr_e( 'Attack Log sections', 'attack-log' ); ?>">
	<?php foreach ( $sections as $section ) : ?>
		<a
			class="attacklog-section-link<?php echo ! empty( $section['is_active'] ) ? ' is-active' : ''; ?>"
			href="<?php echo esc_url( $section['url'] ); ?>"
			<?php echo ! empty( $section['is_active'] ) ? 'aria-current="page"' : ''; ?>
		><?php echo esc_html( $section['label'] ); ?></a>
	<?php endforeach; ?>
</nav>