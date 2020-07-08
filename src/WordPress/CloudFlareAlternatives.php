<?php

namespace CF\WordPress;

use CF\API\APIInterface;
use CF\Integration;

class CloudFlareAlternatives
{
    protected $config;
    protected $hasWarmup = false;
    protected $wordPressWrapper;
    protected $securityKey = 'the_secret_kingdom';
    const NDG_CF_SECRET_KEY = "newdream_secret_key_cf";
    const WP_HOOKS_LOG = true;
    const WP_HOOKS_LOGPATH = "/www/wwwroot/{dir-host}/wp-content/cf.log"; 
    const CF_PURGE_LIMIT_URLS = 30;

    public function __construct()
    {
        $this->config = new Integration\DefaultConfig(file_get_contents(CLOUDFLARE_PLUGIN_DIR.'config.js', true));    
        $this->wordPressWrapper = new WordPressWrapper();
        $this->securityKey = get_option(self::NDG_CF_SECRET_KEY, "empty");
        $this->hasWarmup = $this->config->getValue('warmup');
        
    }

    /*
    * Log to alternative file on disk     
    * 
    */
    public function cfLog($msg){

        if(!self::WP_HOOKS_LOG) return;

        @file_put_contents(self::WP_HOOKS_LOGPATH, $msg . "\n", FILE_APPEND | LOCK_EX);
    }

    /*
    * Change domain of defined constants on array of urls
    * 
    */
    public function changeDomainPurged($urls, $searchHost,  $replaceHost){
        
        for($n=0;$n < count($urls); $n++){
            $urls[$n] = str_replace($searchHost, $replaceHost,$urls[$n]);
        }
        
        return $urls;

    }

    /*
    * Iterate on all defined sites to purge all defined urls
    * 
    */
    public function clearAlternativeSites($urls, $domainActive){

        $this->cfLog("\n======================== clearAlternativeSites ========================");
        $sites = $this->config->getValue('alternativeSites');
        if(!isEmpty($sites) && !is_null($sites)){
            foreach($sites as $site){
                $purged = false;
                $this->cfLog("\nSite: ". $site["host"] . " ========================");            

                foreach(array_chunk($urls, self::CF_PURGE_LIMIT_URLS) as $fileGroup) {

                    $cacheCFUrl = $this->convertUrlsToCF($fileGroup,$domainActive, $site["host"]);
                    $fields = '{"files": [' . $cacheCFUrl . ']}';
                    $this->cfLog("\n" . $fields);
                    $purged = $this->clearSiteCacheUrls($site, $fields);

                    
                }  
                
                if($purged){
                    if($this->hasWarmup){
                        $warmuUrl = str_replace($domainActive,$site["host"],$urls[count($urls)-1]); //get the last element of the list, that one is the url of page
                        $this->warmUpUrl($warmuUrl);
                    }    
                }
                
            }

           
        }else{
            $this->cfLog("\nERROR: Not key 'alternativeSites' in ./config.js");

        }
        $this->cfLog("\n======================== ======================== ========================");

    }

    /*
    * Replace base hosts of urls to some defined host
    * and create the strings structure for CF of urls to purge
    */
    public function convertUrlsToCF($urls, $searchHost,  $replaceHost){

        $cacheCFUrl = "";
        for($n=0;$n < count($urls); $n++){
			
			if($cacheCFUrl!=""){
				$cacheCFUrl .= ",\n";
			}

			$cacheCFUrl .= "\"" . str_replace($searchHost,$replaceHost,$urls[$n]) . "\"";
			
        }	

        return $cacheCFUrl;


    }

    /*
    * Connect to CF and make a request to purge all defined urls using CF API endpoint
    * 
    */
    public function clearSiteCacheUrls($config, $fields){
        try{

            if(isEmpty($this->securityKey) || is_null($this->securityKey)){
                
                $this->cfLog("ERROR: not security key '{self::NDG_CF_SECRET_KEY}'defined in wp_option table");
                return false;
            }
            

            $cf_zone = $this->tokenCrypt($config["zoneId"], "d");
            $cf_email = $this->tokenCrypt($config["email"], "d");
            $cf_apikey = $this->tokenCrypt($config["apiKey"], "d");

            $this->cfLog($cf_zone . " | " . $cf_email . " | " . $cf_apikey );

            if($cf_zone=="" || $cf_email=="" || $cf_apikey==""){
                return false;
            }

            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, "https://api.cloudflare.com/client/v4/zones/" . $cf_zone . "/purge_cache");
            curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type: application/json',
                                                        "X-Auth-Email: " . $cf_email,
                                                        "X-Auth-Key: " . $cf_apikey));
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);
            curl_setopt($ch, CURLOPT_HEADER, FALSE);
            curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'POST');
            curl_setopt($ch, CURLOPT_POSTFIELDS, $fields);
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, FALSE);
            
            $response = curl_exec($ch);
            curl_close($ch);

            //'{"result":{"id":"87866a7923e87eb8891317b9d4c2a2e3"},"success":true,"errors":[],"messages":[]}' 
            $obj = json_decode($response);

            if (!$obj->success){

                $this->cfLog($response);

            }
                
            $this->cfLog("ClearCacheCF Response:" . $response);

            return ($obj->success);

        } catch (\RuntimeException $e) {
            $this->cfLog("ClearCacheCF:" . $e->getMessage());            
        }

        return false;
    }

    
    protected function tokenCrypt( $string, $action) {
        
        $secret_key = trim($this->securityKey);
        $secret_iv = "wpcrypt";

        $output = false;
        $encrypt_method = "AES-256-CBC";
        $key = hash( 'sha256', $secret_key );
        $iv = substr( hash( 'sha256', $secret_iv ), 0, 16 );
    
        if( $action == 'e' ) {
            $output = base64_encode( openssl_encrypt( $string, $encrypt_method, $key, 0, $iv ) );
        }
        else if( $action == 'd' ){
            $output = openssl_decrypt( base64_decode( $string ), $encrypt_method, $key, 0, $iv );
        }
    
        return $output;
    }


    protected function warmUpUrl($url){

        $ch = curl_init();
        $timeout = 10;

        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);
        curl_setopt($ch, CURLOPT_HEADER, TRUE);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, FALSE);
        curl_setopt($ch, CURLOPT_TIMEOUT,$timeout);
        $response = curl_exec($ch);

        curl_close($ch);

    }

}