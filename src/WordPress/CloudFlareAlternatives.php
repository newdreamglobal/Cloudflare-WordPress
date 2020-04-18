<?php

namespace CF\WordPress;

use CF\API\APIInterface;
use CF\Integration;

class CloudFlareAlternatives
{
    protected $config;
    protected $wordPressWrapper;
    protected $securityKey = 'the_secret_kingdom';
    const NDG_CF_SECRET_KEY = "newdream_secret_key_cf";
    const WP_HOOKS_LOG = true;
    const WP_HOOKS_LOGPATH = "/www/wwwroot/{dir-host}/wp-content/cf.log"; 

    public function __construct()
    {
        $this->config = new Integration\DefaultConfig(file_get_contents(CLOUDFLARE_PLUGIN_DIR.'config.js', true));    
        $this->wordPressWrapper = new WordPressWrapper();
        $this->securityKey = get_option(self::NDG_CF_SECRET_KEY, "empty");
        
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

      
        foreach($sites as $site){


            $this->cfLog("\nSite: ". $site["host"] . " ========================");

            
            $cacheCFUrl = $this->convertUrlsToCF($urls,$domainActive, $site["host"]);
            $fields = '{"files": [' . $cacheCFUrl . ']}';


            $this->cfLog("\n" . $fields);

            $purged = $this->clearSiteCacheUrls($site, $fields);
            
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

            $cf_zone = $this->tokenCrypt($config["zoneId"], "d");
            $cf_email = $this->tokenCrypt($config["email"], "d");
            $cf_apikey = $this->tokenCrypt($config["apiKey"], "d");

            $this->cfLog($cf_zone . " | " . $cf_email . " | " . $cf_apikey );

            //return;

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

}
