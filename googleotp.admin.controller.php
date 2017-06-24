<?php
class googleotpAdminController extends googleotp
{
	function init()
	{
	}

	function procGoogleotpAdminInsertConfig()
	{
		$vars = Context::getRequestVars();

		$oModuleController = getController('module');
		$oModuleController->updateModuleConfig('googleotp', $vars);
		if(!in_array(Context::getRequestMethod(),array('XMLRPC','JSON')))
		{
			$returnUrl = Context::get('success_return_url') ? Context::get('success_return_url') : getNotEncodedUrl('', 'module', 'admin', 'act', 'dispGoogleotpAdminConfig');
			header('location: ' . $returnUrl);
			return;
		}
	}
}
