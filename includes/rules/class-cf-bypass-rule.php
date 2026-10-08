<?php

namespace AttackLog\Rules;

use AttackLog\Request_Context;
use AttackLog\Cf_Detector;

defined( 'ABSPATH' ) || exit;

class Cf_Bypass_Rule {

	public function matches( Request_Context $context ) {
		return Cf_Detector::is_bypass_detection_enabled() && ! $context->has_all_cf_headers();
	}

	public function get_detail( Request_Context $context ) {
		return null;
	}
}