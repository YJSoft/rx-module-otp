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
		//Config
	}
}
