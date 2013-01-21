<?php if ( ! defined('BASEPATH')) exit('No direct script access allowed');

/*
 * Tumblr V2 API Library for Codeigniter
 * by Ronald A. Richardson
 * www.ronaldarichardson.com
 * theprestig3@gmail.com
 *
 * based off of Abraham Williams Twitter's REST API Library for CodeIgniter
 * Abraham Williams (abraham@abrah.am) http://abrah.am
 */
 
require_once(APPPATH.'/third_party/OAuth.php');

class Tumblr {

	/* Contains the last HTTP status code returned. */
	public $http_code;
	
	/* Contains the last API call. */
	public $url;
	
	/* Set up the API root URL. */
	public $host = "https://api.tumblr.com/v2/";
	
	/* Set timeout default. */
	public $timeout = 30;
	
	/* Set connect timeout. */
	public $connecttimeout = 30; 
	
	/* Verify SSL Cert. */
	public $ssl_verifypeer = FALSE;
	
	/* Respons format. */
	public $format = 'json';
	
	/* Decode returned json data. */
	public $decode_json = TRUE;
	
	/* Contains the last HTTP headers returned. */
	public $http_info;
	
	/* Set the useragnet. */
	public $useragent = 'Tumblr for CodeIgniter';
	
	/* Immediately retry the API call if the response was not successful. */
	public $retry = TRUE;
	
	/* Tumblr blog url */
	public $tumblr_url = '';
	
	/**
	 * Let's get started...
	 */
	function __construct($params = array())
	{
		$this->ci =& get_instance();
		
		if (count($params) > 0)
		{
			$this->initialize($params);
		}
		
		$this->ci->config->load('tumblr');
		if(!isset($this->tumblr_consumer_key)) {
			$this->tumblr_consumer_key = $this->ci->config->item('tumblr_consumer_key');
		}
		
		if(!isset($this->tumblr_secret_key)) {
			$this->tumblr_secret_key = $this->ci->config->item('tumblr_secret_key');
		}
		
		if(!isset($this->tumblr_url)) {
			$this->tumblr_url = $this->config->ci->item('tumblr_url');
		}

		log_message('debug', "Tumblr Class Initialized");
	}
	
	/**
	 * Initialize Preferences
	 * @param	array	initialization parameters
	 * @return	void
	 */
	function initialize($params = array())
	{
		if (count($params) > 0)
		{
			foreach ($params as $key => $val)
			{
				if (isset($this->$key))
				{
					$this->$key = $val;
				}
			}
		} 
	}
	
	/**
	 * Set API URLS
	 */
	function access_token_url()	
	{ 
		return 'http://www.tumblr.com/oauth/access_token'; 
	}
	
	function authorize_url()		
	{ 
		return 'http://www.tumblr.com/oauth/authorize'; 
	}
	
	function request_token_url() 
	{ 
		return 'http://www.tumblr.com/oauth/request_token'; 
	}

	/**
	 * Debug helpers
	 */
	function last_status_code() 
	{ 
		return $this->http_status; 
	}
	
	function last_api_call() 
	{ 
		return $this->last_api_call; 
	}

	/**
	 * construct TumblrOAuth object
	 */
	function create($consumer_key, $consumer_secret, $oauth_token = NULL, $oauth_token_secret = NULL) 
	{
		$this->sha1_method = new OAuthSignatureMethod_HMAC_SHA1();
		$this->consumer = new OAuthConsumer($consumer_key, $consumer_secret);
		if (!empty($oauth_token) && !empty($oauth_token_secret)) {
			$this->token = new OAuthConsumer($oauth_token, $oauth_token_secret);
		} else {
			$this->token = NULL;
		}
		return $this;
	}


	/**
	 * Get a request_token from Tumblr
	 *
	 * @returns a key/value array containing oauth_token and oauth_token_secret
	 */
	function get_request_token($oauth_callback = NULL) 
	{
		$parameters = array();
		if (!empty($oauth_callback)) {
			$parameters['oauth_callback'] = $oauth_callback;
		}
		$request = $this->oauth_request($this->request_token_url(), 'POST', $parameters);
		$token = OAuthUtil::parse_parameters($request);
		$this->token = new OAuthConsumer($token['oauth_token'], $token['oauth_token_secret']);
		return $token;
	}

	/**
	 * Get the authorize URL
	 *
	 * @returns a string
	 */
	function get_authorize_url($token) 
	{
		if (is_array($token)) {
			$token = $token['oauth_token'];
		}

		return $this->authorize_url() . "?oauth_token={$token}";
	}

	/**
	 * Exchange request token and secret for an access token and
	 * secret, to sign API calls.
	 *
	 * @returns array("oauth_token" => "the-access-token",
	 *								"oauth_token_secret" => "the-access-secret",
	 *								"user_id" => "9436992",
	 *								"screen_name" => "abraham")
	 */
	function get_access_token($oauth_verifier = FALSE) 
	{
		$parameters = array();
		if (!empty($oauth_verifier)) {
			$parameters['oauth_verifier'] = $oauth_verifier;
		}
		$request = $this->oauth_request($this->access_token_url(), 'GET', $parameters);
		$token = OAuthUtil::parse_parameters($request);
		$this->token = new OAuthConsumer($token['oauth_token'], $token['oauth_token_secret']);
		return $token;
	}

	/**
	 * One time exchange of username and password for access token and secret.
	 *
	 * @returns array("oauth_token" => "the-access-token",
	 *								"oauth_token_secret" => "the-access-secret",
	 *								"user_id" => "9436992",
	 *								"screen_name" => "abraham",
	 *								"x_auth_expires" => "0")
	 */	
	function get_xauth_token($username, $password) 
	{
		$parameters = array();
		$parameters['x_auth_username'] = $username;
		$parameters['x_auth_password'] = $password;
		$parameters['x_auth_mode'] = 'client_auth';
		$request = $this->oauth_request($this->access_token_url(), 'POST', $parameters);
		$token = OAuthUtil::parse_parameters($request);
		$this->token = new OAuthConsumer($token['oauth_token'], $token['oauth_token_secret']);
		return $token;
	}

	/**
	 * GET wrapper for oauth_request.
	 */
	function get($url, $parameters = array()) 
	{
		$response = $this->oauth_request($url, 'GET', $parameters);
		if ($this->format === 'json' && $this->decode_json) {
			return json_decode($response);
		}
		return $response;
	}
	
	/**
	 * POST wrapper for oauth_request.
	 */
	function post($url, $parameters = array()) 
	{
		$response = $this->oauth_request($url, 'POST', $parameters);
		if ($this->format === 'json' && $this->decode_json) {
			return json_decode($response);
		}
		return $response;
	}

	/**
	 * DELETE wrapper for oauth_request.
	 */
	function delete($url, $parameters = array()) 
	{
		$response = $this->oauth_request($url, 'DELETE', $parameters);
		if ($this->format === 'json' && $this->decode_json) {
			return json_decode($response);
		}
		return $response;
	}

	/**
	 * Format and sign an OAuth / API request
	 */
	function oauth_request($url, $method, $parameters) 
	{
		if (strrpos($url, 'https://') !== 0 && strrpos($url, 'http://') !== 0) {
			$url = "{$this->host}{$url}.{$this->format}";
		}
		$request = OAuthRequest::from_consumer_and_token($this->tumblr_consumer_key, $this->token, $method, $url, $parameters);
		$request->sign_request($this->sha1_method, $this->tumblr_consumer_key, $this->token);
		switch ($method) {
		case 'GET':
			return $this->http($request->to_url(), 'GET');
		default:
			return $this->http($request->get_normalized_http_url(), $method, $request->to_postdata());
		}
	}

	/**
	 * Make an HTTP request
	 *
	 * @return API results
	 */
	function http($url, $method, $postfields = NULL) 
	{
		$this->http_info = array();
		$ci = curl_init();
		/* Curl settings */
		curl_setopt($ci, CURLOPT_USERAGENT, $this->useragent);
		curl_setopt($ci, CURLOPT_CONNECTTIMEOUT, $this->connecttimeout);
		curl_setopt($ci, CURLOPT_TIMEOUT, $this->timeout);
		curl_setopt($ci, CURLOPT_RETURNTRANSFER, TRUE);
		curl_setopt($ci, CURLOPT_HTTPHEADER, array('Expect:'));
		curl_setopt($ci, CURLOPT_SSL_VERIFYPEER, $this->ssl_verifypeer);
		curl_setopt($ci, CURLOPT_HEADERFUNCTION, array($this, 'get_header'));
		curl_setopt($ci, CURLOPT_HEADER, FALSE);

		switch ($method) {
			case 'POST':
				curl_setopt($ci, CURLOPT_POST, TRUE);
				if (!empty($postfields)) {
					curl_setopt($ci, CURLOPT_POSTFIELDS, $postfields);
				}
				break;
			case 'DELETE':
				curl_setopt($ci, CURLOPT_CUSTOMREQUEST, 'DELETE');
				if (!empty($postfields)) {
					$url = "{$url}?{$postfields}";
				}
			case 'GET':
				$postfields = http_build_query($postfields);
				curl_setopt($ci, CURLOPT_CUSTOMREQUEST, 'GET');
				if (!empty($postfields)) {
					$url = "{$url}?{$postfields}";
				}
		}

		curl_setopt($ci, CURLOPT_URL, $url);
		$response = curl_exec($ci);
		$this->http_code = curl_getinfo($ci, CURLINFO_HTTP_CODE);
		$this->http_info = array_merge($this->http_info, curl_getinfo($ci));
		$this->url = $url;
		curl_close ($ci);
		return $response;
	}

	/**
	 * Get the header info to store.
	 */
	function get_header($ch, $header) 
	{
		$i = strpos($header, ':');
		if (!empty($i)) {
			$key = str_replace('-', '_', strtolower(substr($header, 0, $i)));
			$value = trim(substr($header, $i + 2));
			$this->http_header[$key] = $value;
		}
		return strlen($header);
	}
	
	/*******************************************************************
	 * API Methods
	 *******************************************************************/
	 
	/**
	 * Info
	 * Retreive blog info
	 */
	function blog_info()
	{
		return json_decode($this->http($this->host . 'blog/' . $this->tumblr_url . '/info', 'GET', array('api_key' => $this->tumblr_consumer_key)))->response->blog;
	}
}