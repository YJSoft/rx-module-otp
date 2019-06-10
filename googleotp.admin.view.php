<?php
class googleotpAdminView extends googleotp
{
	function init()
	{
		$this->setTemplatePath($this->module_path.'tpl');
		$this->setTemplateFile(strtolower(str_replace('dispGoogleotpAdmin', '', $this->act)));
	}

	public function dispGoogleotpAdminConfig()
	{
		// 현재 설정 상태 불러오기
		$config = $this->getConfig();

		$oModuleModel = getModel('module');
		$skin_list = $oModuleModel->getSkins($this->module_path);

		// Context에 세팅
		Context::set('googleotp_config', $config);
		Context::set('skin_list',$skin_list);

		// 스킨 파일 지정
		$this->setTemplateFile('config');
	}
}
