<?php

/**
 * @class googleotpModel
 * @author YJSoft
 * @brief Google OTP 2차 인증 모듈의 모델 클래스
 */
require_once(_XE_PATH_.'modules/googleotp/libs/SimpleAuthenticator.php');
require_once(_XE_PATH_.'modules/googleotp/vendor/autoload.php');
use SebastianDevs\SimpleAuthenticator;
use Davidearl\WebAuthn\WebAuthn;

class googleotpModel extends googleotp
{
	/**
	 * 모델 초기화 함수.
	 *
	 * @return void
	 */
	function init()
	{
	}

	/**
	 * Google Authenticator 시크릿 키를 생성하는 함수.
	 *
	 * @return string 생성된 시크릿 키
	 */
	function createGASecret() {
		$ga = new SimpleAuthenticator();
		return $ga->createSecret();
	}

	/**
	 * 신규 사용자의 OTP 설정을 생성하는 함수.
	 *
	 * @param int $member_srl 회원 번호
	 * @param string $otp_id OTP 시크릿 키
	 * @return bool 성공 여부
	 */
	function insertNewConfig($member_srl, $otp_id)
	{
		if($this->checkUserConfig($member_srl)) return FALSE;

		$cond = new stdClass();
		$cond->srl = $member_srl;
		$cond->otp_id = $otp_id;
		$cond->use = "N";
		$output = executeQuery('googleotp.insertGoogleotpuserconfig', $cond);
		return $output->toBool();
	}
	
	/**
	 * 인증 시도 로그를 기록하는 함수.
	 *
	 * @param int $member_srl 회원 번호
	 * @param string $number 입력한 인증번호
	 * @param string $issuccess 인증 성공 여부 ('Y' 또는 'N')
	 * @param string $issue_type 인증 방식 ('otp', 'email', 'sms')
	 * @return object|bool 쿼리 결과 또는 FALSE
	 */
	function insertAuthlog($member_srl,$number,$issuccess,$issue_type="unknown") {
	    if(!$this->checkUserConfig($member_srl)) return FALSE;

		$cond = new stdClass();
		$cond->srl = $member_srl;
		$cond->number = $number;
		$cond->issue_type = $issue_type;
		$cond->issuccess = $issuccess;
		$cond->time = time();
		$output = executeQuery('googleotp.insertGoogleotpauthlog', $cond);
		return $output;
	}

	/**
	 * 사용자의 OTP 설정이 존재하는지 확인하는 함수.
	 *
	 * @param int $member_srl 회원 번호
	 * @return bool OTP 설정 존재 여부
	 */
	function checkUserConfig($member_srl)
	{
		$cond = new stdClass();
		$cond->srl = $member_srl;
		$output = executeQuery('googleotp.getGoogleotpuserconfigbySrl', $cond);
		if(!isset($output->data->otp_id)) return FALSE;
		if(!$output->data->otp_id) $this->generateNewOTP($member_srl);
		return TRUE;
	}
	
	/**
	 * 이미 사용된 인증번호인지 확인하는 함수.
	 *
	 * 5분 이내에 같은 인증번호로 성공한 기록이 있으면 사용 불가로 판단한다.
	 *
	 * @param int $member_srl 회원 번호
	 * @param string $number 인증번호
	 * @return bool 사용 가능 여부 (TRUE: 사용 가능, FALSE: 이미 사용됨)
	 */
	function checkUsedNumber($member_srl,$number) {
	    // 5분전 입력한 인증코드 이후만 조회함
	    $cond = new stdClass();
		$cond->srl = $member_srl;
		$cond->number = $number;
		$cond->issuccess = "Y";
		$cond->time = time() - 300;
		
		$output = executeQueryArray('googleotp.getGoogleotpauthlogbySrl', $cond);
		if(!isset($output->data[0])) return TRUE;
		else return FALSE;
	}

	/**
	 * QR 코드 URL을 생성하는 함수.
	 *
	 * @param string $domain 도메인 이름
	 * @param string $user_id 사용자 ID
	 * @param string $key OTP 시크릿 키
	 * @return string QR 코드 이미지 URL
	 */
	function generateQRCode($domain, $user_id, $key)
	{
		$ga = new SimpleAuthenticator();
		return $ga->getQRCodeGoogleUrl($key, $user_id, $domain);
	}

	/**
	 * 새로운 OTP 시크릿 키를 생성하여 업데이트하는 함수.
	 *
	 * @param int $member_srl 회원 번호
	 * @return bool 성공 여부
	 */
	function generateNewOTP($member_srl)
	{
		$cond = new stdClass();
		$cond->srl = $member_srl;
		$cond->otp_id = $this->createGASecret();
		$output = executeQuery('googleotp.updateGoogleotpkeybySrl', $cond);
		return $output->toBool();
	}

	/**
	 * OTP 인증번호를 검증하는 함수.
	 *
	 * 인증 방식(OTP, 이메일, SMS)에 따라 적절한 검증 로직을 수행한다.
	 *
	 * @param int $member_srl 회원 번호
	 * @param string $number 입력한 인증번호
	 * @param string $active_issue_type 현재 사용 중인 인증 방식 (지정하지 않으면 기본 인증 방식 사용)
	 * @return bool 인증 성공 여부
	 */
	function checkOTPNumber($member_srl,$number,$active_issue_type=null)
	{
		$user_config = $this->getUserConfig($member_srl);
		$config = $this->getConfig();

		if($active_issue_type === null)
		{
			$active_issue_type = $this->getDefaultIssueType($user_config);
		}

		if($active_issue_type == 'otp')
		{
			$ga = new SimpleAuthenticator();
			return $ga->verifyCode($user_config->otp_id, $number, 2);
		}
		else if($active_issue_type == 'email' || $active_issue_type == 'sms')
		{
			if($config->multiple_auth_key_process == 0) // 유효기간 내 전부 허용
			{
				$args = new stdClass();
				$args->member_srl = $member_srl;
				$args->issue_type = $active_issue_type;
				$args->time = time() - ($config->auth_key_vaild_hour * 3600);
				$output = executeQueryArray('googleotp.getAuthSendLog', $args);
				if(!$output->toBool()) return FALSE;

				foreach($output->data as $key => $val) // 유효시간내 전송한 데이터 전체 확인
				{
					if($val->number == $number) return TRUE;
				}

				return FALSE;
			}
			else if($config->multiple_auth_key_process == 1) // 가장 최근에 발행된 키만 허용
			{
				$args = new stdClass();
				$args->member_srl = $member_srl;
				$args->issue_type = $active_issue_type;
				$args->time = time() - ($config->auth_key_vaild_hour * 3600);
				$output = executeQuery('googleotp.getLatestAuthSendLog', $args);
				if(!$output->toBool()) return FALSE;
				if(empty($output->data)) return FALSE;
				if($output->data->number == $number) return TRUE;

				return FALSE;
			}
		}
		else
		{
			return FALSE;
		}
	}

	/**
	 * Google Authenticator OTP 번호를 검증하는 함수.
	 *
	 * @param string $otp_id OTP 시크릿 키
	 * @param string $number 입력한 인증번호
	 * @return bool 인증 성공 여부
	 */
	function checkGAOTPNumber($otp_id, $number)
	{
		$ga = new SimpleAuthenticator();
		return $ga->verifyCode($otp_id, $number, 2);
	}

	/**
	 * 사용자의 OTP 설정 정보를 가져오는 함수.
	 *
	 * @param int $member_srl 회원 번호
	 * @return object|bool 사용자 OTP 설정 객체 또는 FALSE
	 */
	function getUserConfig($member_srl)
	{
		//srl로 회원 조회
		$cond = new stdClass();
		$cond->srl = $member_srl;
		$output = executeQuery('googleotp.getGoogleotpuserconfigbySrl', $cond);
		if(!$output->toBool()) return FALSE;
		else return $output->data;
	}

	/**
	 * 인증 이메일 발송 가능 여부를 확인하는 함수.
	 *
	 * 최대 발송 횟수 초과 또는 최종 발송 후 1분 미경과 시 발송 불가로 판단한다.
	 *
	 * @param int $member_srl 회원 번호
	 * @return bool 발송 가능 여부
	 */
	public function AvailableToSendEmail($member_srl)
	{
		$config = $this->getConfig();

		// 이메일 최대 발송 횟수 확인
		$args = new stdClass();
		$args->member_srl = $member_srl;
		$args->issue_type = 'email';
		$args->time = time() - ($config->auth_retry_hour * 3600);
		$output = executeQuery('googleotp.getAuthSendLogCount', $args);
		if(!$output->toBool()) return FALSE;
		if($output->data->count >= $config->auth_retry_limit) return FALSE;

		// 최종 이메일 발송 시간으로부터 1분이 지났는지 확인
		$args = new stdClass();
		$args->member_srl = $member_srl;
		$args->issue_type = 'email';
		$output = executeQuery('googleotp.getLastSentTime', $args);
		if(!$output->toBool()) return FALSE;
		if($output->data->time > time() - (60)) return FALSE;

		return TRUE;
	}

	/**
	 * 인증 SMS 발송 가능 여부를 확인하는 함수.
	 *
	 * 최대 발송 횟수 초과 또는 최종 발송 후 1분 미경과 시 발송 불가로 판단한다.
	 *
	 * @param int $member_srl 회원 번호
	 * @return bool 발송 가능 여부
	 */
	public function AvailableToSendSMS($member_srl)
	{
		$config = $this->getConfig();

		// SMS 최대 발송 횟수 확인
		$args = new stdClass();
		$args->member_srl = $member_srl;
		$args->issue_type = 'sms';
		$args->time = time() - ($config->auth_retry_hour * 3600);
		$output = executeQuery('googleotp.getAuthSendLogCount', $args);
		if(!$output->toBool()) return FALSE;
		if($output->data->count >= $config->auth_retry_limit) return FALSE;

		// 최종 SMS 발송 시간으로부터 1분이 지났는지 확인
		$args = new stdClass();
		$args->member_srl = $member_srl;
		$args->issue_type = 'sms';
		$output = executeQuery('googleotp.getLastSentTime', $args);
		if(!$output->toBool()) return FALSE;
		if($output->data->time > time() - (60)) return FALSE;

		return TRUE;
	}

	/**
	 * 인증 이메일을 발송하는 함수.
	 *
	 * @param int $member_srl 회원 번호
	 * @param int $auth_number 인증번호
	 * @return bool 발송 성공 여부
	 */
	public static function sendAuthEmail($member_srl, $auth_number)
	{
		$oMemberModel = memberModel::getInstance();
		$member_info = $oMemberModel->getMemberInfoByMemberSrl($member_srl);

		$mail_address = $member_info->email_address;
		$mail_title = "2차 인증 메일입니다.";
		$mail_content = "2차 인증 번호는 [".$auth_number."] 입니다.";

		$oMail = new \Rhymix\Framework\Mail();
		$oMail->setSubject($mail_title);
		$oMail->setBody($mail_content);
		$oMail->addTo($member_info->email_address, $member_info->nick_name);
		$send_status = $oMail->send();

		$args = new stdClass();
		$args->member_srl = $member_srl;
		$args->number = $auth_number;
		$args->issue_type = 'email';
		$args->address = $member_info->email_address;
		$args->send_status = $send_status ? 'Y' : 'N';
		$args->time = time();
		$output = executeQuery('googleotp.insertAuthSendLog', $args);

		return $send_status;
	}

	/**
	 * 인증 SMS를 발송하는 함수.
	 *
	 * @param int $member_srl 회원 번호
	 * @param int $auth_number 인증번호
	 * @return bool 발송 성공 여부
	 */
	public static function sendAuthSMS($member_srl, $auth_number)
	{
		$oMemberModel = memberModel::getInstance();
		$member_info = $oMemberModel->getMemberInfoByMemberSrl($member_srl);

		$sms_content = "2차 인증 번호는 [".$auth_number."] 입니다.";

		$oSmsHandler = new Rhymix\Framework\SMS();
		$phone_country = $member_info->phone_country;
		$phone_number = $member_info->phone_number;

		$send_status = true;
		if(empty($phone_number))
		{
			$send_status = false;
		}

		// Sending SMS outside of Korea is currently not supported.
		if($phone_country !== 'KOR')
		{
			$send_status = false;
		}

		$phone_format = Rhymix\Framework\Korea::isValidPhoneNumber($phone_number);
		if($phone_format === false)
		{
			$send_status = false;
		}

		$oSmsHandler->addTo($phone_number);
		$oSmsHandler->setContent($sms_content);
		if($send_status) $send_status = $oSmsHandler->send();

		$args = new stdClass();
		$args->member_srl = $member_srl;
		$args->number = $auth_number;
		$args->issue_type = 'sms';
		$args->address = $member_info->phone_number;
		$args->send_status = $send_status ? 'Y' : 'N';
		$args->time = time();
		$output = executeQuery('googleotp.insertAuthSendLog', $args);

		return $send_status;
	}

	/**
	 * 신뢰할 수 있는 기기를 등록하는 함수.
	 *
	 * @param int $member_srl
	 * @param int $trust_days
	 * @return string|false 생성된 device_token 또는 실패시 false
	 */
	public function registerTrustedDevice($member_srl, $trust_days = 30)
	{
		$device_token = bin2hex(random_bytes(32));
		$device_name = $this->getDeviceName();

		$args = new stdClass();
		$args->member_srl = $member_srl;
		$args->device_token = hash('sha256', $device_token);
		$args->device_name = $device_name;
		$args->ipaddress = defined('RX_CLIENT_IP') ? RX_CLIENT_IP : $_SERVER['REMOTE_ADDR'];
		$args->created_at = time();
		$args->expires_at = time() + ($trust_days * 86400);

		$output = executeQuery('googleotp.insertTrustedDevice', $args);
		if(!$output->toBool()) return false;

		return $device_token;
	}

	/**
	 * 신뢰할 수 있는 기기인지 확인하는 함수.
	 *
	 * @param int $member_srl
	 * @param string $device_token
	 * @return bool
	 */
	public function checkTrustedDevice($member_srl, $device_token)
	{
		if(empty($device_token)) return false;

		$args = new stdClass();
		$args->member_srl = $member_srl;
		$args->device_token = hash('sha256', $device_token);
		$args->current_time = time();

		$output = executeQuery('googleotp.getTrustedDevice', $args);
		if(!$output->toBool() || empty($output->data)) return false;

		return true;
	}

	/**
	 * 회원의 신뢰할 수 있는 기기 목록을 가져오는 함수.
	 *
	 * @param int $member_srl
	 * @param int $page
	 * @return object
	 */
	public function getTrustedDeviceList($member_srl, $page = 1)
	{
		$args = new stdClass();
		$args->member_srl = $member_srl;
		$args->page = $page;
		$args->list_count = 20;
		$args->page_count = 10;

		return executeQueryArray('googleotp.getTrustedDeviceList', $args);
	}

	/**
	 * 신뢰할 수 있는 기기를 삭제하는 함수.
	 *
	 * @param int $idx
	 * @param int $member_srl
	 * @return bool
	 */
	public function deleteTrustedDevice($idx, $member_srl)
	{
		$args = new stdClass();
		$args->idx = $idx;
		$args->member_srl = $member_srl;

		$output = executeQuery('googleotp.deleteTrustedDevice', $args);
		return $output->toBool();
	}

	/**
	 * 회원의 모든 신뢰할 수 있는 기기를 삭제하는 함수.
	 *
	 * @param int $member_srl
	 * @return bool
	 */
	public function deleteAllTrustedDevices($member_srl)
	{
		$args = new stdClass();
		$args->member_srl = $member_srl;

		$output = executeQuery('googleotp.deleteAllTrustedDevices', $args);
		return $output->toBool();
	}

	/**
	 * 만료된 신뢰할 수 있는 기기를 정리하는 함수.
	 *
	 * @return bool
	 */
	public function cleanupExpiredTrustedDevices()
	{
		$args = new stdClass();
		$args->current_time = time();

		$output = executeQuery('googleotp.deleteExpiredTrustedDevices', $args);
		return $output->toBool();
	}

	/**
	 * User-Agent를 기반으로 기기 이름을 생성하는 함수.
	 *
	 * @return string
	 */
	public function getDeviceName()
	{
		$ua = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';

		// 브라우저 판별
		$browser = 'Unknown Browser';
		if(preg_match('/Edg\//i', $ua)) $browser = 'Edge';
		elseif(preg_match('/OPR\//i', $ua)) $browser = 'Opera';
		elseif(preg_match('/Chrome\//i', $ua)) $browser = 'Chrome';
		elseif(preg_match('/Firefox\//i', $ua)) $browser = 'Firefox';
		elseif(preg_match('/Safari\//i', $ua) && !preg_match('/Chrome/i', $ua)) $browser = 'Safari';
		elseif(preg_match('/MSIE|Trident/i', $ua)) $browser = 'Internet Explorer';

		// OS 판별
		$os = 'Unknown OS';
		if(preg_match('/Windows/i', $ua)) $os = 'Windows';
		elseif(preg_match('/Macintosh|Mac OS/i', $ua)) $os = 'macOS';
		elseif(preg_match('/Android/i', $ua)) $os = 'Android';
		elseif(preg_match('/iPhone|iPad/i', $ua)) $os = 'iOS';
		elseif(preg_match('/Linux/i', $ua)) $os = 'Linux';

		return $browser . ' / ' . $os;
	}

	/**
	 * WebAuthn 인스턴스를 생성하는 함수.
	 *
	 * @return WebAuthn
	 */
	public function getWebAuthn()
	{
		$domain = parse_url(getFullUrl(), PHP_URL_HOST);
		return new WebAuthn($domain);
	}

	/**
	 * 패스키 등록을 위한 챌린지를 생성하는 함수.
	 *
	 * @param string $username 사용자 이름
	 * @param string $userid 사용자 고유 ID
	 * @return string JSON 형식의 챌린지 데이터
	 */
	public function preparePasskeyRegistration($username, $userid)
	{
		$webauthn = $this->getWebAuthn();
		$challenge = $webauthn->prepareChallengeForRegistration($username, strval($userid));
		$_SESSION['webauthn_challenge'] = $challenge;
		return $challenge;
	}

	/**
	 * 패스키 등록을 처리하는 함수.
	 *
	 * @param int $member_srl 회원 번호
	 * @param string $info 브라우저에서 전달된 인증 데이터 (JSON)
	 * @param string $key_name 패스키 이름
	 * @return bool 등록 성공 여부
	 */
	public function registerPasskey($member_srl, $info, $key_name = 'Passkey')
	{
		$webauthn = $this->getWebAuthn();

		// 기존 등록된 패스키 데이터 가져오기
		$existing = $this->getPasskeyWebauthnData($member_srl);

		try {
			$webauthn_data = $webauthn->register($info, $existing);
		} catch (\Exception $e) {
			return false;
		}

		// 새로 등록된 키만 추출 (기존 키 제외)
		$all_keys = json_decode($webauthn_data, true);
		if($existing)
		{
			$existing_keys = json_decode($existing, true);
			$existing_ids = [];
			if(is_array($existing_keys))
			{
				foreach($existing_keys as $ek)
				{
					if(isset($ek['id'])) $existing_ids[] = $ek['id'];
				}
			}
			$new_keys = [];
			if(is_array($all_keys))
			{
				foreach($all_keys as $key)
				{
					if(isset($key['id']) && !in_array($key['id'], $existing_ids))
					{
						$new_keys[] = $key;
					}
				}
			}
			$new_key_data = json_encode($new_keys ?: $all_keys);
		}
		else
		{
			$new_key_data = $webauthn_data;
		}

		// 항상 새로운 행으로 삽입
		$decoded = json_decode($info);
		$credential_id = isset($decoded->id) ? $decoded->id : '';

		$args = new stdClass();
		$args->member_srl = $member_srl;
		$args->credential_id = $credential_id;
		$args->webauthn_data = $new_key_data;
		$args->key_name = $key_name ?: 'Passkey';
		$args->created_at = time();
		$output = executeQuery('googleotp.insertPasskey', $args);

		return $output->toBool();
	}

	/**
	 * 패스키 인증을 위한 챌린지를 생성하는 함수.
	 *
	 * @param int $member_srl 회원 번호
	 * @return string|false JSON 형식의 챌린지 데이터 또는 실패시 false
	 */
	public function preparePasskeyLogin($member_srl)
	{
		$webauthn = $this->getWebAuthn();
		$webauthn_data = $this->getPasskeyWebauthnData($member_srl);

		if(empty($webauthn_data)) return false;

		$challenge = $webauthn->prepareForLogin($webauthn_data);

		// 챌린지 생성 후 업데이트된 webauthn_data 저장 (리플레이 공격 방지)
		$args = new stdClass();
		$args->member_srl = $member_srl;
		$args->webauthn_data = $webauthn_data;
		executeQuery('googleotp.updatePasskeyWebauthnData', $args);

		$_SESSION['webauthn_login_challenge'] = $challenge;
		return $challenge;
	}

	/**
	 * 패스키 인증을 수행하는 함수.
	 *
	 * @param int $member_srl 회원 번호
	 * @param string $info 브라우저에서 전달된 인증 데이터 (JSON)
	 * @return bool 인증 성공 여부
	 */
	public function authenticatePasskey($member_srl, $info)
	{
		$webauthn = $this->getWebAuthn();
		$webauthn_data = $this->getPasskeyWebauthnData($member_srl);

		if(empty($webauthn_data)) return false;

		try {
			$result = $webauthn->authenticate($info, $webauthn_data);
		} catch (\Exception $e) {
			return false;
		}

		if($result)
		{
			// 인증 후 업데이트된 webauthn_data 저장 (리플레이 공격 방지)
			$args = new stdClass();
			$args->member_srl = $member_srl;
			$args->webauthn_data = $webauthn_data;
			executeQuery('googleotp.updatePasskeyWebauthnData', $args);
		}

		return $result;
	}

	/**
	 * 회원의 WebAuthn 데이터를 가져오는 함수.
	 *
	 * @param int $member_srl 회원 번호
	 * @return string|null WebAuthn 데이터 (JSON) 또는 null
	 */
	public function getPasskeyWebauthnData($member_srl)
	{
		$args = new stdClass();
		$args->member_srl = $member_srl;
		$output = executeQueryArray('googleotp.getPasskeysByMemberSrl', $args);
		if(!$output->toBool() || empty($output->data)) return null;

		// 모든 패스키의 webauthn_data를 합쳐서 하나의 JSON 배열로 반환
		$all_keys = [];
		foreach($output->data as $passkey)
		{
			$keys = json_decode($passkey->webauthn_data);
			if(is_array($keys) && !empty($keys))
			{
				$all_keys = array_merge($all_keys, $keys);
			}
		}

		return empty($all_keys) ? null : json_encode($all_keys);
	}

	/**
	 * 회원의 패스키 목록을 가져오는 함수.
	 *
	 * @param int $member_srl 회원 번호
	 * @return array 패스키 목록
	 */
	public function getPasskeyList($member_srl)
	{
		$args = new stdClass();
		$args->member_srl = $member_srl;
		$output = executeQueryArray('googleotp.getPasskeysByMemberSrl', $args);
		if(!$output->toBool() || empty($output->data)) return [];
		return $output->data;
	}

	/**
	 * 패스키를 삭제하는 함수.
	 *
	 * @param int $idx 패스키 인덱스
	 * @param int $member_srl 회원 번호
	 * @return bool 성공 여부
	 */
	public function deletePasskey($idx, $member_srl)
	{
		$args = new stdClass();
		$args->idx = $idx;
		$args->member_srl = $member_srl;
		$output = executeQuery('googleotp.deletePasskey', $args);
		return $output->toBool();
	}

	/**
	 * 회원의 모든 패스키를 삭제하는 함수.
	 *
	 * @param int $member_srl 회원 번호
	 * @return bool 성공 여부
	 */
	public function deleteAllPasskeys($member_srl)
	{
		$args = new stdClass();
		$args->member_srl = $member_srl;
		$output = executeQuery('googleotp.deleteAllPasskeysByMemberSrl', $args);
		return $output->toBool();
	}

	/**
	 * 회원에게 등록된 패스키가 있는지 확인하는 함수.
	 *
	 * @param int $member_srl 회원 번호
	 * @return bool 패스키 존재 여부
	 */
	public function hasPasskey($member_srl)
	{
		$data = $this->getPasskeyWebauthnData($member_srl);
		return !empty($data);
	}

	/**
	 * 사용자 설정에서 활성화된 인증 방식 목록을 배열로 반환하는 함수.
	 *
	 * @param object $user_config 사용자 OTP 설정 객체
	 * @return array 활성화된 인증 방식 배열
	 */
	public function getIssueTypes($user_config)
	{
		if(!$user_config || empty($user_config->issue_type) || $user_config->issue_type === 'none')
		{
			return [];
		}
		return array_filter(explode(',', $user_config->issue_type), function($v) { return $v !== ''; });
	}

	/**
	 * 사용자 설정에서 기본 인증 방식을 반환하는 함수.
	 *
	 * default_issue_type이 설정되어 있으면 해당 값을,
	 * 아니면 issue_type 목록의 첫 번째를 반환한다.
	 *
	 * @param object $user_config 사용자 OTP 설정 객체
	 * @return string 기본 인증 방식
	 */
	public function getDefaultIssueType($user_config)
	{
		if(!empty($user_config->default_issue_type) && $user_config->default_issue_type !== 'none')
		{
			return $user_config->default_issue_type;
		}
		$types = $this->getIssueTypes($user_config);
		return !empty($types) ? $types[0] : 'none';
	}

	/**
	 * 특정 인증 방식이 사용자에게 활성화되어 있는지 확인하는 함수.
	 *
	 * @param object $user_config 사용자 OTP 설정 객체
	 * @param string $type 확인할 인증 방식
	 * @return bool 활성화 여부
	 */
	public function hasIssueType($user_config, $type)
	{
		$types = $this->getIssueTypes($user_config);
		return in_array($type, $types);
	}

	/**
	 * 사용자가 사용할 수 있는 대체 인증 방식 목록을 반환하는 함수.
	 *
	 * 현재 사용 중인 방식을 제외한 나머지 활성화된 인증 방식을 반환한다.
	 *
	 * @param object $user_config 사용자 OTP 설정 객체
	 * @param string $current_type 현재 사용 중인 인증 방식
	 * @return array 대체 인증 방식 배열
	 */
	public function getAlternativeIssueTypes($user_config, $current_type)
	{
		$types = $this->getIssueTypes($user_config);
		return array_values(array_filter($types, function($t) use ($current_type) {
			return $t !== $current_type;
		}));
	}
}
