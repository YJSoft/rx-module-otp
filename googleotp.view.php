<?php

/**
 * @class googleotpView
 * @author YJSoft
 * @brief Google OTP 2차 인증 모듈의 뷰 클래스
 */
class googleotpView extends googleotp
{
	/**
	 * 뷰 초기화 함수.
	 *
	 * 스킨 경로를 설정하고 템플릿 파일을 지정한다.
	 *
	 * @return void
	 */
	function init()
	{
		$config = $this->getConfig();
		
		$template_path = sprintf("%sskins/%s/", $this->module_path, $config->skin);
		if (!is_dir($template_path) || !$config->skin)
		{
			$config->skin = 'default';
			$template_path = sprintf("%sskins/%s/", $this->module_path, $config->skin);
		}
		
		$this->setTemplatePath($template_path);
		$this->setTemplateFile(strtolower(str_replace('dispGoogleotp', '', $this->act)));
	}

	/**
	 * 사용자 OTP 설정 화면을 출력하는 함수.
	 *
	 * QR 코드 및 설정 상태를 표시한다.
	 *
	 * @return BaseObject|void
	 */
	function dispGoogleotpUserConfig()
	{
		if (!Context::get("is_logged"))
		{
			return $this->createObject(-1, "로그인해주세요");
		}

		$logged_info = Context::get("logged_info");
		if ($logged_info->is_admin === "Y")
		{
			$member_srl = Context::get('member_srl') ? Context::get('member_srl') : $logged_info->member_srl;
		}
		else
		{
			$member_srl = $logged_info->member_srl;
		}

		$oGoogleOTPModel = googleotpModel::getInstance();
		$domain = parse_url(getFullUrl());

		if(!$oGoogleOTPModel->checkUserConfig($member_srl)) {
			$oGoogleOTPModel->insertNewConfig($member_srl, $oGoogleOTPModel->createGASecret());
		}

		$config = $this->getConfig();
		$userconfig = $oGoogleOTPModel->getUserConfig($member_srl);

		if(!$userconfig || empty($userconfig->otp_id))
		{
			$oGoogleOTPModel->generateNewOTP($member_srl);
			$userconfig = $oGoogleOTPModel->getUserConfig($member_srl);
		}

		if(!$userconfig || empty($userconfig->otp_id))
		{
			return $this->createObject(-1, "OTP 설정을 불러올 수 없습니다.");
		}

		$userconfig->qrcode = $oGoogleOTPModel->generateQRCode($domain['host'], $logged_info->user_id, $userconfig->otp_id);

		Context::set("member_srl", $member_srl);
		Context::set("force_use_otp", $config->force_use_otp === "Y");
		Context::set("user_config", $userconfig);
		Context::set("user_mail", $logged_info->email_address);
		Context::set("user_phone", $logged_info->phone_number ?: '설정 안됨');
		Context::set("googleotp_config", $this->getConfig());

		// 패스키 관련 데이터
		$passkey_list = $oGoogleOTPModel->getPasskeyList($member_srl);
		Context::set("passkey_list", $passkey_list);
		Context::set("has_passkey", !empty($passkey_list));
	}

	/**
	 * OTP 인증번호 입력 화면을 출력하는 함수.
	 *
	 * 이메일 또는 SMS 인증 방식인 경우 인증번호를 발송하고,
	 * 캡챠 설정이 활성화된 경우 캡챠를 초기화한다.
	 *
	 * @return BaseObject|void
	 */
	function dispGoogleotpInputotp()
	{
		if (!Context::get("is_logged"))
		{
			return $this->createObject(-1, "로그인해주세요");
		}

		if($_SESSION['googleotp_passed'])
		{
			$redirect_url = $_SESSION['beforeaddress'] ?: getNotEncodedUrl('');
			header("Location: " . $redirect_url);
			Context::close();
			die();
		}

		$config = $this->getConfig();
		$logged_info = Context::get("logged_info");
		$member_srl = $logged_info->member_srl;
		$oGoogleOTPModel = googleotpModel::getInstance();
		$userconfig = $oGoogleOTPModel->getUserConfig($member_srl);

		// 현재 활성화된 인증 방식 결정 (세션에서 선택한 방식 또는 기본 방식)
		$active_issue_type = $_SESSION['googleotp_active_type'] ?? $oGoogleOTPModel->getDefaultIssueType($userconfig);

		// 대체 인증 방식 목록
		$alternative_types = $oGoogleOTPModel->getAlternativeIssueTypes($userconfig, $active_issue_type);

		if($active_issue_type == 'email')
		{
			if($oGoogleOTPModel->AvailableToSendEmail($member_srl)) // 인증 메일을 보낼 수 있을 경우
			{
				$result = $oGoogleOTPModel->sendAuthEmail($member_srl, rand(100000, 999999));
				Context::set('email_sent', $result);
			}
		}
		else if($active_issue_type == 'sms')
		{
			if($oGoogleOTPModel->AvailableToSendSMS($member_srl)) // 인증 SMS를 보낼 수 있을 경우
			{
				$result = $oGoogleOTPModel->sendAuthSMS($member_srl, rand(100000, 999999));
				Context::set('sms_sent', $result);
			}
		}

		$spamfilter_config = ModuleModel::getModuleConfig('spamfilter');
		if (
			$config->use_captcha == 'Y'
			&& isset($spamfilter_config) && isset($spamfilter_config->captcha)
			&& $spamfilter_config->captcha->type === 'recaptcha'
			&& $logged_info->is_admin !== 'Y'
		)
		{
			include_once RX_BASEDIR . 'modules/spamfilter/spamfilter.lib.php';
			spamfilter_reCAPTCHA::init($spamfilter_config->captcha);
			Context::set('captcha', new spamfilter_reCAPTCHA());
		}

		Context::set("member_srl", $member_srl);
		Context::set("logged_info", $logged_info);
		Context::set("user_config", $userconfig);
		Context::set("googleotp_config", $config);
		Context::set("active_issue_type", $active_issue_type);
		Context::set("alternative_types", $alternative_types);

		// 패스키 인증용 데이터 준비
		if($active_issue_type == 'passkey')
		{
			$has_passkey = $oGoogleOTPModel->hasPasskey($member_srl);
			Context::set("has_passkey", $has_passkey);
		}
	}

	/**
	 * 신뢰할 수 있는 기기 관리 화면을 출력하는 함수.
	 *
	 * @return BaseObject|void
	 */
	function dispGoogleotpTrustedDevices()
	{
		if (!Context::get("is_logged"))
		{
			return $this->createObject(-1, "로그인해주세요");
		}

		$logged_info = Context::get("logged_info");
		$member_srl = $logged_info->member_srl;

		$oGoogleOTPModel = googleotpModel::getInstance();
		$config = $this->getConfig();

		if($config->use_trusted_device !== 'Y')
		{
			return $this->createObject(-1, "신뢰할 수 있는 기기 기능이 비활성화되어 있습니다.");
		}

		$page = Context::get('page') ?: 1;
		$output = $oGoogleOTPModel->getTrustedDeviceList($member_srl, $page);

		Context::set('device_list', $output->data);
		Context::set('total_count', $output->total_count);
		Context::set('total_page', $output->total_page);
		Context::set('page', $output->page);
		Context::set('page_navigation', $output->page_navigation);
		Context::set('googleotp_config', $config);

		$this->setTemplateFile('trusteddevices');
	}
}
