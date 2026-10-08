<?php

namespace AttackLog\Rules;

use AttackLog\Request_Context;
use AttackLog\Cf_Detector;

defined( 'ABSPATH' ) || exit;

/**
 * Matches requests that reach the origin without all three Cloudflare
 * headers, while Cloudflare bypass detection is enabled.
 */
class Cf_Bypass_Rule {

	public function matches( Request_Context $context ) {
		return Cf_Detector::is_bypass_detection_enabled() && ! $context->has_all_cf_headers();
	}

	public function get_detail( Request_Context $context ) {
		return null;
	}
}