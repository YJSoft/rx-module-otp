<?php
class googleotpAdminView extends googleotp
{
	function init()
	{
		$this->setTemplatePath($this->module_path.'tpl');
		$this->setTemplateFile(strtolower(str_replace('dispGoogleotpAdmin', '', $this->act)));
	}

	function dispGoogleotpAdminConfig()
	{
		$oGoogleotpModel = getModel('googleotp');
		$module_config = $oGoogleotpModel->getConfig();
		Context::set('config', $module_config);
	}

	function dispGoogleotpAdminTabEx()
	{
		//tab
	}
}
