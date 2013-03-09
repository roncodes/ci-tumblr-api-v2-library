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
	
	/* Connection */
	public $connection = NULL;
	
	/* Immediately retry the API call if the response was not successful. */
	public $retry = TRUE;
	
	/* Tumblr blog url */
	public $tumblr_url = '';
	
	/* Authenticated ? */
	public $authenticated = FALSE;
	
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
			$this->tumblr_url = $this->ci->config->item('tumblr_url');
		}
		
		if(!isset($this->callback_url)) {
			$this->callback_url = $this->ci->config->item('callback_url');
		}
		
		if(!isset($this->auth_callback)) {
			$this->auth_callback = $this->ci->config->item('auth_callback');
		}
		
		/*
		 * Establish a connection
		 */
		if($this->ci->session->userdata('access_token') && $this->ci->session->userdata('access_token_secret'))
		{
			// If user already logged in
			$this->authenticated = true;
			$this->connection = $this->create($this->tumblr_consumer_key, $this->tumblr_secret_key, $this->ci->session->userdata('access_token'),  $this->ci->session->userdata('access_token_secret'));
		}
		elseif($this->ci->session->userdata('request_token') && $this->ci->session->userdata('request_token_secret'))
		{
			// If user in process of authentication
			$this->authenticated = 'processing';
			$this->connection = $this->create($this->tumblr_consumer_key, $this->tumblr_secret_key, $this->ci->session->userdata('request_token'), $this->ci->session->userdata('request_token_secret'));
		}
		else
		{
			// Unknown user
			$this->authenticated = false;
			$this->connection = $this->create($this->tumblr_consumer_key, $this->tumblr_secret_key);
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
			$parameters['oauth_consumer_key'] = $this->tumblr_consumer_key;
			$parameters['oauth_secret_key'] = $this->tumblr_secret_key;
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
		
		$request = OAuthRequest::from_consumer_and_token($this->consumer, $this->token, $method, $url, $parameters);
		$request->sign_request($this->sha1_method, $this->consumer, $this->token);
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
			case '_GET':
				if(count($postfields)) {
					$postfields = http_build_query($postfields);
				}
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
	
	function handle_auth()
	{
		if(!is_bool($this->authenticated)) {
			$this->handle_callback();
		}
		if($this->ci->session->userdata('access_token') && $this->ci->session->userdata('access_token_secret'))
		{
			return;
		}
		else
		{
			// Making a request for request_token
			$request_token = $this->get_request_token(base_url($this->callback_url));

			$this->ci->session->set_userdata('request_token', $request_token['oauth_token']);
			$this->ci->session->set_userdata('request_token_secret', $request_token['oauth_token_secret']);
			
			if($this->connection->http_code == 200)
			{
				$url = $this->connection->get_authorize_url($request_token);
				redirect($url);
			}
			else
			{
				// An error occured. Make sure to put your error notification code here.
				redirect(base_url());
			}
		}
	}
	
	/**
	 * Handle the api callback
	 */
	function handle_callback()
	{
		if($this->ci->input->get('oauth_token') && $this->ci->session->userdata('request_token') !== $this->ci->input->get('oauth_token'))
		{
			$this->reset_session();
			redirect(base_url($this->auth_callback));
		}
		else
		{
			$access_token = $this->connection->get_access_token($this->ci->input->get('oauth_verifier'));
		
			if ($this->connection->http_code == 200)
			{
				$this->ci->session->set_userdata('access_token', $access_token['oauth_token']);
				$this->ci->session->set_userdata('access_token_secret', $access_token['oauth_token_secret']);

				$this->ci->session->unset_userdata('request_token');
				$this->ci->session->unset_userdata('request_token_secret');
				
				redirect(base_url('/'));
			}
			else
			{
				// An error occured. Add your notification code here.
				redirect(base_url('/'));
			}
		}
	} 
	
	/**
	 * Reset the current session data
	 */
	private function reset_session()
	{
		$this->ci->session->unset_userdata('access_token');
		$this->ci->session->unset_userdata('access_token_secret');
		$this->ci->session->unset_userdata('request_token');
		$this->ci->session->unset_userdata('request_token_secret');
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
		return json_decode($this->http($this->host . 'blog/' . $this->tumblr_url . '/info', '_GET', array('api_key' => $this->tumblr_consumer_key)))->response->blog;
	}

	/**
	* Get tagged posts
	*/
	function tagged($tag, $before = NULL)
	{
		return json_decode($this->http($this->host . 'tagged/', '_GET', array('api_key' => $this->tumblr_consumer_key, 'tag' => $tag, 'before' => $before)))->response;
	}

	/**
	* Posts from a blog, with offset and amount to return, as well as reblog and notes flags
	*/
	function posts($blog_name, $offset = 0, $amount = 20, $reblog_info = FALSE, $notes = FALSE)
	{
		return json_decode($this->http($this->host . 'blog/' .  $blog_name . '/posts' , '_GET', array('api_key' => $this->tumblr_consumer_key, 'limit' => $amount, 'offset' => $offset, 'reblog_info' => $reblog_info, 'notes_info' => $notes)));
	}

	/** 
	* Get posts of a specific type
	*/
	function posts_type($blog_name, $type, $offset = 0, $amount = 20, $reblog_info = FALSE, $notes = FALSE)
	{
		return json_decode($this->http($this->host . 'blog/' . $blog_name . '/posts/' . $type, '_GET', array('api_key' => $this->tumblr_consumer_key, 'limit' => $amount, 'offset' => $offset, 'reblog_info' => $reblog_info, 'notes_info' => $notes)))->response;
	}
	
	/**
	 * Post
	 * Creates a new blog post
	 */
	function blog_post($post_data = array())
	{
		if($this->ci->session->userdata('access_token') && $this->ci->session->userdata('access_token_secret'))
		{
			return $this->connection->post('blog/' . $this->tumblr_url . '/post', $post_data);
		}
		else
		{
			// User is not authenticated.
			$this->handle_auth();
		}
	}
}