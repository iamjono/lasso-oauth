<?Lassoscript
/* these test endpoints were used in testing and developing this communication. The defaults can be overridden during init of the type, or can be changed by editing the tag definitions below.
	http://term.ie/oauth/example/index.php is a live example of the php code found in http://oauth.googlecode.com/svn/code/php/example/.

The endpoints are: http://term.ie/oauth/example/request_token.php http://term.ie/oauth/example/access_token.php http://term.ie/oauth/example/echo_api.php

The consumer key and secret are: Consumer Key: key Consumer Secret: secret

The tokens returned are:

Request token: requestkey Request secret: requestsecret

Access token: accesskey Access secret: accesssecret
*/
define oauth_consumer_key => 'key'
define oauth_consumer_secret => 'secret'
define oauth_request_token => 'requestkey'
define oauth_request_secret => 'requestsecret'
define oauth_access_token => 'accesskey'
define oauth_access_secret => 'accesssecret'
define oauth_realm => 'http://term.ie/'
define oauth_request_endpoint => {return 'http://term.ie/oauth/example/request_token.php'}
define oauth_access_endpoint => 'http://term.ie/oauth/example/access_token.php'
define oauth_echo_endpoint => 'http://term.ie/oauth/example/echo_api.php'
define oauth_userauth_endpoint => ''

define intuit_token_endpoint => 'https://oauth.intuit.com/oauth/v1/get_request_token'

define lasso_oauth => type {
	data public oauth_request_endpoint
	data public oauth_access_endpoint
	data public oauth_userauth_endpoint
	
	data public oauth_consumer_key
	data public oauth_consumer_secret
	data public oauth_signature_method
	//The signature method the Consumer used to sign the request.
	data public oauth_signature
	//The signature as defined in Signing Requests.
	data public oauth_timestamp
	//As defined in Nonce and Timestamp.
	data public oauth_nonce
	//As defined in Nonce and Timestamp.
	data public oauth_version
	//OPTIONAL. If present, value MUST be 1.0 . Service Providers MUST assume the protocol version to be 1.0 if this parameter is not present. Service Providers' response to non-1.0 value is left undefined.
	data public oauth_callback
	//An absolute URL to which the Service Provider will redirect the User back when the Obtaining User Authorization step is completed. If the Consumer is unable to receive callbacks or a callback URL has been established via other means, the parameter value MUST be set to oob (case sensitive), to indicate an out-of-band configuration.
	data public oauth_token = ''
	data public oauth_token_secret = ''
	data public oauth_verifier = ''
	data public curr_arguments
	data public realmID = ''
	
	public onCreate() => {
		.'oauth_consumer_key' = oauth_consumer_key
		.'oauth_signature_method' = 'HMAC-SHA1'
		.'oauth_request_endpoint' = oauth_request_endpoint
		.'oauth_access_endpoint' = oauth_access_endpoint
		session_start('ipp_oauth_ua', -useCookie, -expire=15)
		if(var_defined('oauth_keys'))
			.'oauth_token' = $oauth_keys->find('ua_token')
	          .'oauth_token_secret' = $oauth_keys->find('ua_secret')
	          
		/if
		
	}
	
	public updatekeys(consumer_key, consumer_secret, sig_method) => {
		.'oauth_consumer_key' = #consumer_key
		.'oauth_consumer_secret' = #consumer_secret
		.'oauth_signature_method' = #sig_method
	
	}
	
	public updateendpoints(request='', access='', userauth='', callback='' ) => {
		#request !='' ? .'oauth_request_endpoint' = #request
		#access !='' ? .'oauth_access_endpoint' = #access
		#userauth !='' ? .'oauth_userauth'= #userauth
		#callback !='' ? .'oauth_callback' = #callback
	}
	
	public constructSig(endpoint, arguments, method, additional=array) => {
		local('sig_args' = #arguments->asCopy)
		#sig_args->merge(#additional)
		#sig_args->sort
          local('sig_string' = #method+'&'+encode_stricturl(#endpoint)+'&')
          local('temp_string' = '')
          #sig_args->foreachPair =>{
          	local('p' = #1->second)
          	#temp_string += (#p->first+'='+#p->second+'&')
          	}
          #temp_string->removetrailing('&')
          #sig_string += encode_stricturl(#temp_string)
          
          return #sig_string
	}
	
	public requestSPToken(method, callback ='') =>{
		session_start('ipp_oauth_ua', -useCookie, -expire=5)
		
          local('arguments' = array('oauth_consumer_key' = .'oauth_consumer_key',
          						'oauth_signature_method' = .'oauth_signature_method',
          						'oauth_timestamp' = date()->asinteger,
          						'oauth_nonce' = encrypt_md5(date()->asinteger),
          						'oauth_version'= '1.0',
          						'oauth_callback' = encode_stricturl(.'oauth_callback')
          						))
          .'curr_arguments' = #arguments->asCopy	
          local('sig_string' = .constructSig(.'oauth_request_endpoint', #arguments, #method))
          
          if(.'oauth_signature_method' == 'HMAC-SHA1')
          	local('enc_sig' = encrypt_HMAC(-password=(.'oauth_consumer_secret'+'&'+.'oauth_token_secret'), -token=#sig_string, -digest='SHA1', -base64))
          else
          	local('enc_sig' = '')
          	log_critical('no sig method matches')
          /if
          
          #arguments->insert('oauth_signature' = encode_stricturl(#enc_sig))
		/*
		//Create custom Authorization header
		local('authstring' = ' ')
		with key in #arguments
			do {
     			#authstring+=(#key->first+'="'+#key->second+'", ')
			}
		#authstring->removetrailing(', ')
		local('auth_header' = array('Authorization' = 'OAUTH'+#authstring))  
		*/
		
          local('auth_header' = .createAuthHeader(#arguments))
          
		local('tokenstring' = include_url(.'oauth_request_endpoint', -sendMIMEheaders=#auth_header, -options = array(CURLOPT_CUSTOMREQUEST='POST')))
		  /*      
          select(#method)
          	case('POST')
          		local('tokenstring' = include_url(#requestURL, -sendMIMEheaders=#auth_header, -options = array(CURLOPT_CUSTOMREQUEST='POST')))
          	case('GET')
          		local('tokenstring' = include_url(#requestURL, -GETparams=#arguments))
          	case('HEAD')
          		local('tokenstring' = include_url(#requestURL, -sendMIMEheaders=#auth_header))
          /select
          */
          
          local('request_tokens' = #tokenstring->split('&'))
          if(#request_tokens->size == 2)
	          .'oauth_token' = #request_tokens->get(1)->split('=')->get(2)
	          .'oauth_token_secret' = #request_tokens->get(2)->split('=')->get(2)
          else
          	local('tokens' = .parseTokenResponse(#tokenstring->asString))
          	.'oauth_token' = #tokens->find('oauth_token')
	          .'oauth_token_secret' = #tokens->find('oauth_token_secret')
	          !var_defined('oauth_keys') ? session_addvar('ipp_oauth_ua', 'oauth_keys')
          	var('oauth_keys'=map('ua_token' = #tokens->find('oauth_token'), 'ua_secret' = #tokens->find('oauth_token_secret')))
          	
          	return .'oauth_token'
          /if
          
		return .'oauth_token'
	}
	
	public userAuthRefer() => {
		
		redirect_url(.'oauth_userauth_endpoint'+'?oauth_token='+.'oauth_token')
	}
	
	public requestAccessToken(verifier, realmID, method) => {
		local('debug_string' = '')
		local('arguments' = array('oauth_consumer_key' = .'oauth_consumer_key',
								'oauth_token' = .'oauth_token',
          						'oauth_signature_method' = 'HMAC-SHA1',
          						'oauth_timestamp' = date()->asinteger,
          						'oauth_nonce' = encrypt_md5(date()->asinteger),
          						'oauth_version'= '1.0',
          						'oauth_verifier'=#verifier
          						))
          #debug_string+=('<br> oauth token: '+.'oauth_token'+' key: '+.'oauth_consumer_key')
          local('additional' = array('realmID' = #realmID))				
          local('sig_string' = .constructSig(.'oauth_access_endpoint', #arguments, #method, #additional))
          local('enc_sig' = encrypt_HMAC(-password=(.'oauth_consumer_secret'+'&'+.'oauth_token_secret'), -token=#sig_string, -digest='SHA1', -base64))
          #debug_string+=('<br>Sig string: '#sig_string)
          #debug_string+=('<br>Enc Sig: '+#enc_sig)
          
          #arguments->insert('oauth_signature' = encode_stricturl(#enc_sig))
          local('auth_header' = .createAuthHeader(#arguments, #realmID))
          select(#method)
          	case('POST')
          		local('tokenstring' = include_url(.'oauth_access_endpoint', -sendMIMEheaders=#auth_header, -POSTparams= #additional))
          	case('GET')
          		local('tokenstring' = include_url(.'oauth_access_endpoint', -GETparams=#arguments))
          	case('HEAD')
          		local('tokenstring' = include_url(.'oauth_access_endpoint', -sendMIMEheaders=#arguments))
          /select
          #debug_string+=('<br>AuthHeader: '+#auth_header)
          #debug_string+=('<br>Test string: '+#tokenstring)
          
          local('access_tokens' = #tokenstring->split('&'))
          if(false)
          	local('tokens' = .parseTokenResponse(#tokenstring->asString))
          	.'oauth_token' = #tokens->find('oauth_token')
	          .'oauth_token_secret' = #tokens->find('oauth_token_secret')
	          
          	return #debug_string
          else
          	local('tokens' = .parseTokenResponse(#tokenstring->asString))
          	.'oauth_token' = #tokens->find('oauth_token')
	          .'oauth_token_secret' = #tokens->find('oauth_token_secret')
	          
          	return #tokens
          /if
          
		return .'oauth_token'
		
	}
	
	public protectedRequest(request_url, method, request_args) => {
		local('debug_string' = 'Params: '+params)
		local('arguments' = array('oauth_consumer_key' = .'oauth_consumer_key',
								'oauth_token' = .'oauth_token',
          						'oauth_signature_method' = 'HMAC-SHA1',
          						'oauth_timestamp' = date()->asinteger,
          						'oauth_nonce' = encrypt_md5(date()->asinteger),
          						'oauth_version'= '1.0'
          						))
          //#arguments->merge(#request_args)	
          #debug_string+=('<br>args: '+#arguments)				
          local('additional' = array('realmID' = .'realmID'))	
          local('sig_string' = .constructSig(#request_url, #arguments, #method, #additional))
          local('enc_sig' = encrypt_HMAC(-password=(.'oauth_consumer_secret'+'&'+.'oauth_token_secret'), -token=#sig_string, -digest='SHA1', -base64))
          #debug_string+=('<br>additional: '+#additional+'<br>sig: '+#sig_string+'<br>enc_sig: '+#enc_sig)
          #arguments->insert('oauth_signature' = encode_stricturl(#enc_sig))
          local('auth_header' = .createAuthHeader(#arguments, .'realmID'))
          select(#method)
          	case('POST')
          		local('tokenstring' = include_url(#request_url, -sendMIMEheaders=#auth_header, -POSTparams=#additional))
          	case('GET')
          		local('tokenstring' = include_url(#request_url, -GETparams=#arguments))
          	case('HEAD')
          		local('tokenstring' = include_url(#request_url, -sendMIMEheaders=#arguments))
          /select
          #debug_string+=('<br>response: '+#tokenstring)
          
          if(false)
          	
          	return #debug_string
          else
	          return #tokenstring
	     /if
	}
	
	public curr_token_secret => .'oauth_token_secret'
	
	public parseTokenResponse(tokenresponse) => {
		
		local('token_array' = #tokenresponse->split('&'))
		local('tokensplit' = map())
		with token in #token_array 
			do {
				local('split' = #token->split('='))
				#tokensplit->insert(#split->get(1) = #split->get(2))
				
			}
		return #tokensplit
	}
	
	public createAuthHeader(arguments) => {
		//Create custom Authorization header
		local('authstring' = ' ')
		with key in #arguments
			do {
     			#authstring+=(#key->first+'="'+#key->second+'", ')
			}
		#authstring->removetrailing(', ')
		local('auth_header' = array('Authorization' = 'OAUTH'+#authstring))
		
		return #auth_header
	}
}

define ipp_oauth => type {
	
	parent lasso_oauth
	
	//data public myauth = lasso_oauth()
	data private app_token = 'your Intuit app token goes here'

	data private ipp_consumer_key = 'your IPP consumer key goes here'
	data private ipp_consumer_secret = 'your IPP consumer secret goes here'
	data private ipp_endpoints = map('requestToken' = 'https://oauth.intuit.com/oauth/v1/get_request_token', 'accessToken' = 'https://oauth.intuit.com/oauth/v1/get_access_token', 'callbackURL' = 'http://qb.lassoconsultant.com/oauth/access_test.lasso')
	
	public oncreate() => {
		..onCreate()
		.updateKeys(.'ipp_consumer_key', .'ipp_consumer_secret', 'HMAC-SHA1')
		.updateendpoints(.'ipp_endpoints'->find('requestToken'), .'ipp_endpoints'->find('accessToken'), '', .'ipp_endpoints'->find('callbackURL'))
		session_start('ipp_auth', -useCookie, -expires=(60*24*90))
		if(var_defined('ipp_tokens'))
			.'oauth_token' = $ipp_tokens->find('key')
			.'oauth_token_secret' = $ipp_tokens->find('secret')
			.'realmID' = $ipp_tokens->find('reamlID')
		/if
	}
	
	public requestUAToken() => {
		local('tokenresponse' = .requestSPToken('POST'))
		//#tokenstring->split('&')->size ==1 ? return #tokenstring
		
		return #tokenresponse
	}
	
	public requestAccess(verifier, realmID) => {
		local('accessresponse' = .requestAccessToken(#verifier, #realmID, 'POST'))
		.saveAccessTokens(#accessresponse)
		return #accessresponse
	}
	
	public saveAccessTokens(tokens) => {
		
		session_start('ipp_auth', -useCookie, -expires=(60*24*90))
		session_addvar('ipp_auth', 'ipp_tokens')
		var('ipp_tokens' = map('key' = #tokens->find('oauth_token'), 'secret' = #tokens->find('oauth_token_secret'), 'realmID' = #tokens->find('realmID')))
		
	}
	
	public restRequest(url, method) => {
		
		return .protectedRequest(#url, #method, '')
		
	}
}
?>