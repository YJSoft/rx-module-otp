<?php

/**
 * @class googleotpAdminController
 * @author YJSoft
 * @brief Google OTP 2차 인증 모듈의 관리자 컨트롤러 클래스
 */
class googleotpAdminController extends googleotp
{
	/**
	 * 관리자 컨트롤러 초기화 함수.
	 *
	 * @return void
	 */
	function init()
	{
	}

	/**
	 * 관리자 모듈 설정을 저장하는 함수.
	 *
	 * @return BaseObject|void
	 */
	public function procGoogleotpAdminInsertConfig()
	{
		// 현재 설정 상태 불러오기
		$config = $this->getConfig();

		// 제출받은 데이터 불러오기
		$vars = Context::getRequestVars();

		$config->skins = $vars->skins;
		$config->allow_issue_type = $vars->allow_issue_type;
		$config->auth_retry_hour = $vars->auth_retry_hour;
		$config->auth_retry_limit = $vars->auth_retry_limit;
		$config->use_captcha = $vars->use_captcha ? 'Y' : 'N';
		$config->auth_key_vaild_hour = $vars->auth_key_vaild_hour;
		$config->multiple_auth_key_process = $vars->multiple_auth_key_process;
		$config->force_use_otp = $vars->force_use_otp ? 'Y' : 'N';
		$config->bypass_auto_login = $vars->bypass_auto_login ? 'Y' : 'N';
		$config->use_trusted_device = $vars->use_trusted_device ? 'Y' : 'N';
		$config->trusted_device_duration = intval($vars->trusted_device_duration) ?: 30;
		
		$output = $this->setConfig($config);
		if (!$output->toBool())
		{
			return $output;
		}

		// 설정 화면으로 리다이렉트
		$this->setMessage('success_registed');
		$this->setRedirectUrl(Context::get('success_return_url'));
	}
	
	/**
	 * 관리자가 개별 사용자의 OTP 설정을 변경하는 함수.
	 *
	 * @return BaseObject|void
	 */
	public function procGoogleotpAdminUpdateConfig()
	{
		$obj = Context::getRequestVars();
		$args = new stdClass();
		$args->srl = $obj->srl;
		$args->use = $obj->use;
		$args->issue_type = $obj->issue_type;
		$output = executeQuery('googleotp.updateGoogleotpuserconfigbySrl', $args);
		if(!$output->toBool())
		{
			return $output;
		}
		$this->setMessage('success_registed');
		$this->setRedirectUrl(Context::get('success_return_url'));
	}

	/**
	 * 관리자가 신뢰할 수 있는 기기를 삭제하는 함수.
	 *
	 * @return BaseObject|void
	 */
	public function procGoogleotpAdminDeleteTrustedDevice()
	{
		$idx = intval(Context::get('device_idx'));
		$member_srl = intval(Context::get('target_member_srl'));

		if(!$idx || !$member_srl) return $this->createObject(-1, "잘못된 요청입니다.");

		$oGoogleOTPModel = googleotpModel::getInstance();
		if(!$oGoogleOTPModel->deleteTrustedDevice($idx, $member_srl))
		{
			return $this->createObject(-1, "기기 삭제에 실패했습니다.");
		}

		$this->setMessage('success_deleted');
		$this->setRedirectUrl(Context::get('success_return_url') ?: getNotEncodedUrl('', 'module', 'admin', 'act', 'dispGoogleotpAdminTrustedDeviceList'));
	}
}
