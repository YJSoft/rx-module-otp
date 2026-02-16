<?php

/**
 * @class googleotpController
 * @author YJSoft
 * @brief Google OTP 2차 인증 모듈의 컨트롤러 클래스
 */
class googleotpController extends googleotp
{
	/**
	 * 컨트롤러 초기화 함수.
	 *
	 * @return void
	 */
	function init()
	{
	}

	/**
	 * 사용자 OTP 설정을 처리하는 함수.
	 *
	 * 2차 인증 사용 여부 및 인증 방식을 설정한다.
	 *
	 * @return BaseObject|void
	 */
	function procGoogleotpUserConfig()
	{
		$oGoogleOTPModel = googleotpModel::getInstance();
		if(!Context::get("is_logged")) return $this->createObject(-1, "로그인해주세요");
		$member_srl = Context::get('logged_info')->member_srl;

		if(!$oGoogleOTPModel->checkUserConfig($member_srl)) {
			$otp_id = $oGoogleOTPModel->createGASecret();
			$oGoogleOTPModel->insertNewConfig($member_srl, $otp_id);
		} else {
			$user_config = $oGoogleOTPModel->getUserConfig($member_srl);
			$otp_id = $user_config->otp_id;
		}
		$test_auth_key = Context::get("test_auth_key");
		$test_auth_key = explode(" ", $test_auth_key);
	    $test_auth_key = implode("", $test_auth_key);

		$cond = new stdClass();
		$cond->srl = $member_srl;
		$cond->use = Context::get("use") === "Y" ? "Y" : "N";
		$cond->issue_type = Context::get("issue_type") ?: 'none';

		if($cond->use == 'Y' && !in_array($cond->issue_type, array('otp', 'email', 'sms', 'passkey'))) {
			return $this->createObject(-1, "2차 인증 방식을 선택해주세요.");
		}

		if($cond->use == 'Y' && $cond->issue_type == 'otp') {
			if(!$test_auth_key) {
				return $this->createObject(-1, "확인용 인증코드를 입력해주세요.");
			}

			if(!$oGoogleOTPModel->checkGAOTPNumber($otp_id, $test_auth_key)) {
				return $this->createObject(-1, "확인용 인증코드가 잘못되었습니다.");
			}
		}

		if($cond->use == 'Y' && $cond->issue_type == 'passkey') {
			if(!$oGoogleOTPModel->hasPasskey($member_srl)) {
				return $this->createObject(-1, "패스키를 먼저 등록해주세요.");
			}
		}

		$output = executeQuery('googleotp.updateGoogleotpuserconfigbySrl', $cond);
		if(!$output->toBool()) return $this->createObject(-1, "ERROR #1 : 관리자에게 문의하세요.");

		if($cond->use === "Y")
		{
			$_SESSION['googleotp_passed'] = TRUE;
		}

		// alert a message
		if(Context::get('xeVirtualRequestMethod') !== 'xml')
		{
			$this->setMessage('success_updated');
			$this->setRedirectUrl(Context::get('error_return_url') ?: getNotEncodedUrl('', 'act', 'dispGoogleotpUserConfig'));
		}
	}

	/**
	 * OTP 인증번호를 입력받아 검증하는 함수.
	 *
	 * @return BaseObject|void
	 */
	function procGoogleotpInputotp()
	{
		if(!Context::get("is_logged")) return $this->createObject(-1,"로그인하지 않았습니다.");
		if($_SESSION['googleotp_passed']) return $this->createObject(-1,"이미 인증했습니다.");

		$config = $this->getConfig();
		if ( $config->use_captcha === 'Y' )
		{
			$spamfilter_config = ModuleModel::getModuleConfig('spamfilter');
			$logged_info = Context::get('logged_info');
			if (
				$config->use_captcha == 'Y'
				&& isset($spamfilter_config) && isset($spamfilter_config->captcha)
				&& $spamfilter_config->captcha->type === 'recaptcha'
				&& $logged_info->is_admin !== 'Y'
			)
			{
				include_once RX_BASEDIR . 'modules/spamfilter/spamfilter.lib.php';
				spamfilter_reCAPTCHA::init($spamfilter_config->captcha);
				spamfilter_reCAPTCHA::check();
			}
		}
		
		$otpnumber = Context::get("otpinput");
		
		// change 111 111 to 111111
	    $otpnumber = explode(" ",$otpnumber);
	    $otpnumber = implode("",$otpnumber);

		if(!$otpnumber) return $this->createObject(-1,"인증번호를 입력해주세요.");
	    
		$member_srl = Context::get('logged_info')->member_srl;

		$oGoogleOTPModel = googleotpModel::getInstance();
		$userconfig = $oGoogleOTPModel->getUserConfig($member_srl);
		$issue_type = $userconfig->issue_type;
		
		if($oGoogleOTPModel->checkOTPNumber($member_srl,$otpnumber))
		{
		    if(!$oGoogleOTPModel->checkUsedNumber($member_srl,$otpnumber))
		    {
		        return $this->createObject(-1,"이미 인증에 사용된 번호입니다. 다른 번호를 사용해주세요.");
		    }
		    else
		    {
		      $oGoogleOTPModel->insertAuthlog($member_srl, $otpnumber, "Y", $issue_type);
			    $_SESSION['googleotp_passed'] = TRUE;

			    // 신뢰할 수 있는 기기 등록 처리
			    $trust_device = Context::get("trust_device");
			    if($trust_device === 'Y' && $config->use_trusted_device === 'Y')
			    {
			        $trust_days = intval($config->trusted_device_duration) ?: 30;
			        $device_token = $oGoogleOTPModel->registerTrustedDevice($member_srl, $trust_days);
			        if($device_token)
			        {
			            $cookie_expire = time() + ($trust_days * 86400);
			            $is_https = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');
			            setcookie('googleotp_trusted_device', $device_token, [
			                'expires' => $cookie_expire,
			                'path' => '/',
			                'secure' => $is_https,
			                'httponly' => true,
			                'samesite' => 'Lax',
			            ]);
			        }
			    }

			    $this->setRedirectUrl($_SESSION['beforeaddress']);
		    }
		}
		else
		{
		  $oGoogleOTPModel->insertAuthlog($member_srl, $otpnumber, "N", $issue_type);
			$this->setError(-1);
			$this->setMessage("잘못된 인증 번호입니다");
			$this->setRedirectUrl(Context::get('error_return_url') ?: getNotEncodedUrl('', 'act', 'dispGoogleotpInputotp'));
		}
	}

	/**
	 * 인증 메시지를 재발송하는 함수.
	 *
	 * 이메일 또는 SMS로 인증번호를 재발송한다.
	 *
	 * @return BaseObject
	 */
	function procGoogleotpResendauthmessage()
	{
		Context::setResponseMethod('JSON');
		if($_SESSION['googleotp_passed']) return $this->createObject(-1,"이미 인증했습니다.");

		$member_srl = Context::get('member_srl');
		$oGoogleOTPModel = googleotpModel::getInstance();
		$userconfig = $oGoogleOTPModel->getUserConfig($member_srl);

		if($userconfig->issue_type == 'email')
		{
			if($oGoogleOTPModel->AvailableToSendEmail($member_srl)) // 인증 메일을 보낼 수 있을 경우
			{
				$result = $oGoogleOTPModel->sendAuthEmail($member_srl, rand(100000, 999999));
				return $this->createObject(0, "인증 메일을 재발송했습니다.");
			}
			else
			{
				return $this->createObject(-1, "인증 메일을 재발송할 수 없습니다.\n\n관리자에게 문의하세요.");
			}
		}
		elseif($userconfig->issue_type == 'sms')
		{
			if($oGoogleOTPModel->AvailableToSendSMS($member_srl)) // 인증 SMS를 보낼 수 있을 경우
			{
				$result = $oGoogleOTPModel->sendAuthSMS($member_srl, rand(100000, 999999));
				return $this->createObject(0, "인증 문자를 재발송했습니다.");
			}
			else
			{
				return $this->createObject(-1, "인증 문자를 재발송할 수 없습니다.\n\n관리자에게 문의하세요.");
			}
		}
	}

	/**
	 * 회원 메뉴에 2차 인증 설정 메뉴를 추가하는 트리거 함수.
	 *
	 * @return BaseObject
	 */
	function triggerAddMemberMenu()
	{
		$logged_info = Context::get('logged_info');
		if(!Context::get('is_logged')) return $this->createObject();

		$oMemberController = memberController::getInstance();
		$oMemberController->addMemberMenu('dispGoogleotpUserConfig', "로그인 2차 인증 설정");
		if($logged_info->is_admin== 'Y')
		{
			$target_srl = Context::get('target_srl');

			$url = getUrl('','act','dispGoogleotpUserConfig','member_srl',$target_srl);
			$oMemberController->addMemberPopupMenu($url, '유저 로그인 2차 인증 관리', '');
		}
		return $this->createObject();
	}

	/**
	 * 로그인 시 2차 인증 화면으로 리다이렉트하는 트리거 함수.
	 *
	 * OTP 인증이 필요한 사용자가 인증을 완료하지 않은 경우
	 * 허용된 액션 외의 접근을 차단하고 인증 화면으로 이동시킨다.
	 *
	 * @param object $obj 모듈 핸들러 객체
	 * @return void
	 */
	function triggerHijackLogin($obj) {
		if(!Context::get("is_logged") || $obj->act === "dispMemberLogout") {
			unset($_SESSION['googleotp_passed']);
			return;
		}

		$config = $this->getConfig();
		$oGoogleOTPModel = googleotpModel::getInstance();
		$member_srl = Context::get('logged_info')->member_srl;
		$userconfig = $oGoogleOTPModel->getUserConfig($member_srl);

		// 신뢰할 수 있는 기기 확인
		if($config->use_trusted_device === 'Y' && !$_SESSION['googleotp_passed'])
		{
			$device_token = $_COOKIE['googleotp_trusted_device'] ?? '';
			if($device_token && $oGoogleOTPModel->checkTrustedDevice($member_srl, $device_token))
			{
				$_SESSION['googleotp_passed'] = TRUE;
			}
		}

		if($userconfig->use === "Y") {
			$allowedact = array("dispGoogleotpInputotp","procGoogleotpInputotp","procMemberLogin","dispMemberLogout","procGoogleotpResendauthmessage","getMember_divideList","procGoogleotpPasskeyLoginChallenge","procGoogleotpPasskeyAuthenticate");
			if(!in_array($obj->act, $allowedact) && !$_SESSION['googleotp_passed'])
			{
				$_SESSION['beforeaddress'] = getNotEncodedUrl();
				header("Location: " . getNotEncodedUrl('act','dispGoogleotpInputotp'));
				Context::close();
				die();
			}
		} elseif($config->force_use_otp === "Y") {
			$allowedact = array("dispGoogleotpUserConfig","procGoogleotpUserConfig","procMemberLogin","dispMemberLogout","procGoogleotpResendauthmessage","getMember_divideList");
			if(!in_array($obj->act, $allowedact) && (!$oGoogleOTPModel->checkUserConfig($member_srl) || $userconfig->use !== "Y"))
			{
				$_SESSION['beforeaddress'] = getNotEncodedUrl();
				header("Location: " . getNotEncodedUrl('act','dispGoogleotpUserConfig'));
				Context::close();
				die();
			}
		}
	}

	/**
	 * 자동 로그인 시 2차 인증을 우회하는 트리거 함수.
	 *
	 * 설정에서 자동 로그인 시 우회가 활성화된 경우 OTP 인증을 건너뛴다.
	 *
	 * @param object $obj 자동 로그인 객체
	 * @return void
	 */
	function triggerAutoLoginBypass($obj) {
		$config = $this->getConfig();
		if($config->bypass_auto_login === "Y") {
			$_SESSION['googleotp_passed'] = TRUE;
		}
	}

	/**
	 * 신뢰할 수 있는 기기를 삭제하는 함수.
	 *
	 * @return BaseObject|void
	 */
	function procGoogleotpDeleteTrustedDevice()
	{
		if(!Context::get("is_logged")) return $this->createObject(-1, "로그인해주세요");

		$logged_info = Context::get('logged_info');
		$member_srl = $logged_info->member_srl;
		$idx = intval(Context::get('device_idx'));

		if(!$idx) return $this->createObject(-1, "잘못된 요청입니다.");

		$oGoogleOTPModel = googleotpModel::getInstance();

		// 관리자는 다른 회원의 기기도 삭제 가능
		if($logged_info->is_admin === 'Y' && Context::get('target_member_srl'))
		{
			$member_srl = intval(Context::get('target_member_srl'));
		}

		if(!$oGoogleOTPModel->deleteTrustedDevice($idx, $member_srl))
		{
			return $this->createObject(-1, "기기 삭제에 실패했습니다.");
		}

		$this->setMessage('success_deleted');
		if(Context::get('success_return_url'))
		{
			$this->setRedirectUrl(Context::get('success_return_url'));
		}
		else
		{
			$this->setRedirectUrl(getNotEncodedUrl('', 'act', 'dispGoogleotpTrustedDevices'));
		}
	}

	/**
	 * 모든 신뢰할 수 있는 기기를 삭제하는 함수.
	 *
	 * @return BaseObject|void
	 */
	function procGoogleotpDeleteAllTrustedDevices()
	{
		if(!Context::get("is_logged")) return $this->createObject(-1, "로그인해주세요");

		$logged_info = Context::get('logged_info');
		$member_srl = $logged_info->member_srl;

		$oGoogleOTPModel = googleotpModel::getInstance();

		// 관리자는 다른 회원의 기기도 삭제 가능
		if($logged_info->is_admin === 'Y' && Context::get('target_member_srl'))
		{
			$member_srl = intval(Context::get('target_member_srl'));
		}

		if(!$oGoogleOTPModel->deleteAllTrustedDevices($member_srl))
		{
			return $this->createObject(-1, "기기 삭제에 실패했습니다.");
		}

		// 쿠키 삭제
		$is_https = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');
		setcookie('googleotp_trusted_device', '', [
			'expires' => time() - 3600,
			'path' => '/',
			'secure' => $is_https,
			'httponly' => true,
			'samesite' => 'Lax',
		]);

		$this->setMessage('success_deleted');
		if(Context::get('success_return_url'))
		{
			$this->setRedirectUrl(Context::get('success_return_url'));
		}
		else
		{
			$this->setRedirectUrl(getNotEncodedUrl('', 'act', 'dispGoogleotpTrustedDevices'));
		}
	}

	/**
	 * 패스키 등록 챌린지를 생성하는 함수.
	 *
	 * @return BaseObject
	 */
	function procGoogleotpPasskeyRegisterChallenge()
	{
		Context::setResponseMethod('JSON');
		if(!Context::get("is_logged")) return $this->createObject(-1, "로그인해주세요");

		$logged_info = Context::get('logged_info');
		$member_srl = $logged_info->member_srl;

		$oGoogleOTPModel = googleotpModel::getInstance();
		$challenge = $oGoogleOTPModel->preparePasskeyRegistration($logged_info->nick_name, $member_srl);

		$this->add('challenge', $challenge);
		return $this->createObject(0, 'success');
	}

	/**
	 * 패스키 등록을 처리하는 함수.
	 *
	 * @return BaseObject
	 */
	function procGoogleotpPasskeyRegister()
	{
		Context::setResponseMethod('JSON');
		if(!Context::get("is_logged")) return $this->createObject(-1, "로그인해주세요");

		$logged_info = Context::get('logged_info');
		$member_srl = $logged_info->member_srl;
		$info = Context::get('passkey_info');
		$key_name = Context::get('key_name') ?: 'Passkey';

		if(!$info) return $this->createObject(-1, "패스키 데이터가 없습니다.");

		$oGoogleOTPModel = googleotpModel::getInstance();
		$result = $oGoogleOTPModel->registerPasskey($member_srl, $info, $key_name);

		if(!$result) return $this->createObject(-1, "패스키 등록에 실패했습니다.");

		return $this->createObject(0, '패스키가 등록되었습니다.');
	}

	/**
	 * 패스키 인증 챌린지를 생성하는 함수 (로그인 시).
	 *
	 * @return BaseObject
	 */
	function procGoogleotpPasskeyLoginChallenge()
	{
		Context::setResponseMethod('JSON');
		if(!Context::get("is_logged")) return $this->createObject(-1, "로그인하지 않았습니다.");

		$member_srl = Context::get('logged_info')->member_srl;

		$oGoogleOTPModel = googleotpModel::getInstance();
		$challenge = $oGoogleOTPModel->preparePasskeyLogin($member_srl);

		if(!$challenge) return $this->createObject(-1, "등록된 패스키가 없습니다.");

		$this->add('challenge', $challenge);
		return $this->createObject(0, 'success');
	}

	/**
	 * 패스키 인증을 수행하는 함수 (로그인 시).
	 *
	 * @return BaseObject|void
	 */
	function procGoogleotpPasskeyAuthenticate()
	{
		Context::setResponseMethod('JSON');
		if(!Context::get("is_logged")) return $this->createObject(-1, "로그인하지 않았습니다.");
		if($_SESSION['googleotp_passed']) return $this->createObject(-1, "이미 인증했습니다.");

		$member_srl = Context::get('logged_info')->member_srl;
		$info = Context::get('passkey_info');

		if(!$info) return $this->createObject(-1, "패스키 데이터가 없습니다.");

		$oGoogleOTPModel = googleotpModel::getInstance();
		$config = $this->getConfig();

		if($oGoogleOTPModel->authenticatePasskey($member_srl, $info))
		{
			$oGoogleOTPModel->insertAuthlog($member_srl, 'passkey', "Y", "passkey");
			$_SESSION['googleotp_passed'] = TRUE;

			// 신뢰할 수 있는 기기 등록 처리
			$trust_device = Context::get("trust_device");
			if($trust_device === 'Y' && $config->use_trusted_device === 'Y')
			{
				$trust_days = intval($config->trusted_device_duration) ?: 30;
				$device_token = $oGoogleOTPModel->registerTrustedDevice($member_srl, $trust_days);
				if($device_token)
				{
					$cookie_expire = time() + ($trust_days * 86400);
					$is_https = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');
					setcookie('googleotp_trusted_device', $device_token, [
						'expires' => $cookie_expire,
						'path' => '/',
						'secure' => $is_https,
						'httponly' => true,
						'samesite' => 'Lax',
					]);
				}
			}

			$this->add('redirect_url', $_SESSION['beforeaddress'] ?: getNotEncodedUrl(''));
			return $this->createObject(0, '패스키 인증에 성공했습니다.');
		}
		else
		{
			$oGoogleOTPModel->insertAuthlog($member_srl, 'passkey', "N", "passkey");
			return $this->createObject(-1, "패스키 인증에 실패했습니다.");
		}
	}

	/**
	 * 패스키를 삭제하는 함수.
	 *
	 * @return BaseObject|void
	 */
	function procGoogleotpDeletePasskey()
	{
		if(!Context::get("is_logged")) return $this->createObject(-1, "로그인해주세요");

		$logged_info = Context::get('logged_info');
		$member_srl = $logged_info->member_srl;
		$idx = intval(Context::get('passkey_idx'));

		if(!$idx) return $this->createObject(-1, "잘못된 요청입니다.");

		$oGoogleOTPModel = googleotpModel::getInstance();

		// 2차 인증이 패스키 방식으로 활성화된 경우, 마지막 패스키는 삭제 불가
		$user_config = $oGoogleOTPModel->getUserConfig($member_srl);
		if($user_config && $user_config->use === 'Y' && $user_config->issue_type === 'passkey')
		{
			$passkey_list = $oGoogleOTPModel->getPasskeyList($member_srl);
			if(count($passkey_list) <= 1)
			{
				return $this->createObject(-1, "패스키를 모두 삭제하려면 2차 인증을 비활성화하세요.");
			}
		}

		if(!$oGoogleOTPModel->deletePasskey($idx, $member_srl))
		{
			return $this->createObject(-1, "패스키 삭제에 실패했습니다.");
		}

		$this->setMessage('success_deleted');
		if(Context::get('success_return_url'))
		{
			$this->setRedirectUrl(Context::get('success_return_url'));
		}
		else
		{
			$this->setRedirectUrl(getNotEncodedUrl('', 'act', 'dispGoogleotpUserConfig'));
		}
	}
}
