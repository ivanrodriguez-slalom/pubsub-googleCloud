
# (Publish) 
## In order to publish a message to PubSub we need to follow the steps on Google Cloud.
### (Config In Google Cloud)
    1. Create a project 
    2. Under the PubSub API create a Topic
        a. That topic's name will have the following structure projects/{project-name}/topics/{topic}
    3. Create a Service Account (Under IAM & Admin)
        a. That service account has an email associated that is needed for a setting in Salesforce
        b. Add the Pub/Sub Publisher and Pub/Sub Subscriber roles to the Service account so it can publish and Subscribe to topics
        c. In the "Keys" tab, create a new Key of .p12 format (This key will be later converted to JKS, which is the format used by salesforce) To convert the key we could use  Cloud Shell, or 'keytool' command from the JDK. See how to convert from .pk12 to .jks
### (Config in Salesforce)
    
    1. Enable Identity Providers
    2. In 'Certificate and Key Management', import the .jks file that was converted in previous steps 
    3. Create a new Custom metadata type to store the URLs needed to authenticate and to publish the message
        a. Five fields 
            i. Client Email --> it can be found in Service Account in GCP
            ii. Google Service Endpoint ('https://pubsub.googleapis.com/v1/{topic-name}:publish})
            iii. Token Endpoint ('https://www.googleapis.com/oauth2/v4/token')
            iv. Scope: (In this case is: https://www.googleapis.com/auth/pubsub)
            v. Certificate Name: (Name of the certificate created in Salesforce)
    4. Remote Site Settings
        a. One for https://accounts.google.com
        b. Second one for https://pubsub.googleapis.com
        c. Third one for https://www.googleapis.com
    5. Cache Partition
        a. The cache partition is to store the token retrieved from Google (The token provided by Google  is valid for an hour, so we can use the same token within that hour). In code, we need to set TTL parameter using the Org.put() method to 30 seconds before it expires so we never have an expired token.
        b. With a 1 MB cache's size is enough
    6. Platform Events whose fields are on the left side of the mapping field in the custom metadata record when sending messages, or on the right side of the mapping field when receiving messages
    7. Custom Metadata Type that stores the mapping definition, topic, platform event, direction of the message flow (in/out) and the name of the gcp_key that has the info to be used (only applicable when sending message use the checkpoints you specified ) 

# (Design)
## GoogleUtils class:
        /**
         * This class request the Auth Token needed to access the GCP's APIs 
         */
        public with sharing class GoogleUtils {
            //This is the name of the key to identify the token in the partition
            private String cacheAccessTokenKey = '';
            @TestVisible
            private String authToken = '';
            @TestVisible
            private String audience = '';
            private String scope = '';
            private String certificate = '';
            /******************************************************************************* */
            //Constructor
            public GoogleUtils(String cacheAccessTokenKey, String gcpKey){
                this.cacheAccessTokenKey = cacheAccessTokenKey;
                System.debug(cacheAccessTokenKey);
                System.debug('Value is GCP_Key field is: '+gcpKey);
                GCP_Key__mdt serviceAccount = getGCPServiceAccount(gcpKey);
                audience = serviceAccount.Pubsub_Endpoint__c;
                scope = serviceAccount.Scope__c;
                certificate = serviceAccount.Certificate_Name__c;
                authToken = getGCPAuthToken(serviceAccount);
            }
            /***********************GETTERS***************************** */
            /**
             * @return authToken received from GCP
             */
            public String getToken(){
                return authToken;
            }
            /**
             * @return audience that contains the URL of the topic that we need to post to
             */
            public String getAudience(){
                return audience;
            }
            /*************************SETTERS******************************************** */
            /**
             * @description This method sets the key in the partition
             */
            public void setCacheAccessTokenKey (String cacheAccessTokenKey){
                this.cacheAccessTokenKey = cacheAccessTokenKey;
            }
            /*************************HELPER METHODS*******************************************************************/
            /**
             * @description It stores the access token in the Cache with a TTL of 59 minutes and 30 seconds
             * @param accessToken received from GCP
             */
            @TestVisible
            private void cacheAccessToken(String accessToken){
                Cache.Org.put(cacheAccessTokenKey,accessToken, 3600 - 30);
            }
            
            /**
             * @description It removes the token in the cache, so a new token can be retrieved
             * @param accessToken that is stor
             */
            public static Boolean remove(String key){
                return Cache.Org.remove(key);
            }
        
            /**
            * @description it gets the metadata that contains all the information of the service account 
            * that is being used to publish messages
            *@param metadataName of the metadata that stores the Service'saccount info
            *@return the corresponding metadata record
            */
            @TestVisible
            private GCP_KEY__mdt getGCPServiceAccount(String metadataName){
                List<GCP_Key__mdt> gcpServiceAccount = [SELECT Client_Email__c,
                                                                Pubsub_Endpoint__c,
                                                                Token_Endpoint__c,
                                                                Scope__c,
                                                                Certificate_Name__c
                                                        FROM GCP_Key__mdt 
                                                        WHERE MasterLabel=:metadataName WITH SECURITY_ENFORCED];
                if(gcpServiceAccount.size() > 0){
                    return gcpServiceAccount[0];
                }else{
                    throw new GCPServiceAccountException ('None Service Account was found with the name specified');
                }
            }
            /**
             * @description It makes a callout to GCP to get the authorization token
             * @param serviceAccount metadata record with the info
             * @return authToken from the cache if available or from GCP
             */
            @TestVisible
            private String getGCPAuthToken(GCP_Key__mdt serviceAccount){
                String authToken = (String) Cache.Org.get(cacheAccessTokenKey);
                if(authToken != null){
                    return authToken;
                }
                //To store the received token
                String result = '';
                //Generate the JSON clam to request the token
                Auth.JWT jwt = new Auth.JWT();
                jwt.setAud(serviceAccount.Token_Endpoint__c);
                jwt.setIss(serviceAccount.Client_Email__c);
                //Setting additional Claims
                Map<String,Object> claims = new Map<String,Object>();
                claims.put('scope',scope);
                jwt.setAdditionalClaims(claims);
                //Creating the JWS object that signs the JWT bearer token
                Auth.JWS jws = new Auth.JWS(jwt,certificate);
                // In case it is needed to do some debugs, we can get the JWS  as a
                //concatenated string
                String jwsJSON = jws.getCompactSerialization();
                System.debug('JSON Web Signature is: '+jwsJSON);
                //Set the token endpoint that the bearer token will be posted to 
                String tokenEndpoint = serviceAccount.Token_Endpoint__c;
                //Post the JWT bearer token
                Auth.JWTBearerTokenExchange bearer = new Auth.JWTBearerTokenExchange(tokenEndpoint,jws);
                if(!Test.isRunningTest()){
                    result = bearer.getAccessToken();
                    System.debug('Token gotten from GCP: '+ result);
                }else{
                    result = 'IN TEST';
                }
                //Store the token in the cache
                cacheAccessToken(result);
                return result;
            }
            /******************************************HELPER CLASSES************************** */
            /**
             * Class to create exceptions when needed
             */
            public class GCPServiceAccountException extends Exception{}
        }
        
## Google Cloud Function

from simple_salesforce import Salesforce
from google.cloud import secretmanager
import base64
import requests
import json
import os
def postMessage(event, context):
    
    if 'data' in event:
        #Displaying some data that might be helpful to create the final message
        print(context.resource)
        print(context.event_id)
        print(context.timestamp)
        #getting credentials from Secret Manager
        username,password,token = getCredentials()
        #Getting the value stored in the 'domain_prefix' enviroment variable
        #to construct the custom domain url of the org. 
        #Salesforce() method in python appends that value to 'salesforce.com' sufix.
        domain_prefix = os.environ.get('domain_prefix');
        #getting connection with Salesforce using the User Integration's credentials
        sf = Salesforce(username=username,password=password,security_token=token,domain=domain_prefix)
        #******************CREATING JSON MESSAGE*****************************
        #Getting topic's short name stored in the environement variable
        topic = os.environ.get('topic')
        pubsub_message = {"data":event["data"],"topic":topic}
        #****************POST MESSAGE ****************************************
        #getting endpoint
        endpoint = os.environ.get('sfdc_endpoint')
        # POST message in Salesforce
        result = sf.apexecute(endpoint,method='POST', data=pubsub_message)
    else:
        raise ValueError('data Key is missing in PubSub message')

def getCredentials():
    # Create the Secret Manager client.
    client = secretmanager.SecretManagerServiceClient()
    # Organize the Secret Keys
    sf_user_dev = "SF_USER_HSBRIM"
    sf_pass_dev = "SF_PASS_HSBRIM"
    sf_token_dev = "SF_TOKEN_HSBRIM"
    
    # Get the project Id stored in the environment variable
    project_id = os.environ.get("project_id","The environment variable is not set yet")
    
    # Obtain the Secret Name Path
    sf_user_prod_name = f"projects/{project_id}/secrets/{sf_user_dev}/versions/latest"
    sf_pass_prod_name = f"projects/{project_id}/secrets/{sf_pass_dev}/versions/latest"
    sf_token_prod_name = f"projects/{project_id}/secrets/{sf_token_dev}/versions/latest"   
    
    # Obtain the Latest Secret Version
    sf_user_prod_response = client.access_secret_version(sf_user_prod_name)
    sf_pass_prod_response = client.access_secret_version(sf_pass_prod_name)
    sf_token_prod_response = client.access_secret_version(sf_token_prod_name)
    # get payload of each secret
    sf_username = sf_user_prod_response.payload.data.decode('UTF-8')  
    sf_password = sf_pass_prod_response.payload.data.decode('UTF-8') 
    sf_token = sf_token_prod_response.payload.data.decode('UTF-8')     
    return sf_username, sf_password, sf_token

Requirements.txt

#Function dependencies, for example:
#package>=version
requests>=2.20.0
simple-salesforce>=0.74.2
google-cloud-logging==1.11.0
google-cloud-secret-manager==0.2.0

## ENVIRONMENT VARIABLES IN GOOGLE

project_id 
topic
sfdc_endpoint
domain_prefix

## PubSubPublisher class
Class that publish the message (The class that publish the message to Google PubSub. The class
Should be similar to this one.

/**
 * This class makes the callout to Pub/Sub
 * @author: Ivan A. Rodriguez
 */
public class PubSubPublisher implements Queueable, Database.AllowsCallouts {
    private Object objEvent;
    /************************************************************************************** */
    //Constructor
    public PubSubPublisher(Object objEvent){
        this.objEvent = objEvent;
    }
    /***************************************************************************** */
    /**
     * @description Method that must to be defined from the Queueable interface
     * @param context 
     */
    public void execute (QueueableContext context){
       //generate the Pub Sub message
       Map<String,String> pubsubMessage = PubSubMapperHelper.GetMappingOut(objEvent);
       String cacheAccessTokenKey = 'local.GcpPartition.googleCloudAccessToken';
       String gcpKey = pubsubMessage.get('gcp_key');
       GoogleUtils utils = new GoogleUtils(cacheAccessTokenKey,gcpKey);
       //Setting the endpoint specifically for pubsub
       String pubSubEndpoint = utils.getAudience()+
                                pubsubMessage.get('topic')+
                                ':publish';
        // Publishing to PubSub
       if(utils.getToken() != null){
            pushDataToPubSub(utils.getToken(), pubSubEndpoint,pubSubMessage);
       }else{
           throw new GoogleUtils.GCPServiceAccountException('The token could not be retrieved with this Service Acocunt');
       }
       
    }
    /*********************HELPER METHODS**************************** */
    /**
     * @description method that publish the message to pubsub
     * @param authToken retrieved from GCP
     * @param pubSubEndpoint to where we need to publish the message
     * @param pubSubMessage contains the base64 message that needs to be sent
     */
    private void pushDataToPubSub(String authToken, String pubSubEndpoint, Map<String,String> pubSubMessage){
        String message = '{"messages":[{"data":'+'"'+pubSubMessage.get('json')+'"}]}';
        Http http = new Http();
       HttpRequest req = new HttpRequest();
       req.setHeader('Content-Type','application/json');
       req.setHeader('Authorization','Bearer '+authToken);
       req.setEndpoint(pubSubEndpoint);
       req.setMethod('POST');
       req.setBody(message);
       System.debug('POST request to: '+ pubSubEndpoint);
       HttpResponse response = http.send(req);
        //Analyze response
        if(response.getStatusCode() != 200){
            System.debug('Pub/Sub Message could not be published');
            System.debug(response.getStatusCode());
            //More Code here if needed
        }else{
            System.debug('Message Successfully Published');
            System.debug(response.getStatusCode());
            //More Code here if needed
        }
    }
}

## Generic Class to generates Mocks

/**
 * This class can be used to generate Pub/Sub Responses
 * @author: IVan A.Rodriguez
 */
@isTest
public class PubSubHttpMockGenerator implements HttpCalloutMock {
    private Integer code;
    private String status;
    private String body;
    private Map<String,String> header;
    //Constructor
    public PubSubHttpMockGenerator(Content content, Map<String,String> header) {
        this.code = content.code;
        this.status = content.status;
        this.body = content.body;
        this.header = header;
    }
    // Implementing interface method
    public HttpResponse respond (HttpRequest req){
        //Create a fake response
        HttpResponse response = new HttpResponse();
        //Set the Header
        for(String key: header.keySet()){
            response.setHeader(key,header.get(key));
        }
        //Set Content
        response.setBody(body);
        response.setStatusCode(code);
        response.setStatus(status);
        return response;
    }
    
    //---------WRAPER CLASSES----------
    public class Content {
        Integer code;
        String status;
        String body;
        public Content(Integer code, String status,String body){
            this.code = code;
            this.status = status;
            this.body = body;
        }
    }
}

## PubSubMappperHelper 
Class that performs the mapping between the platform event and the message received/sent from/to PubSub

public class PubSubMapperHelper {
    
    /*******************************************************************************************************
    * @description Returns the mapped json data from the SFDC Event to be sent to Google PubSub
    * @param objEvent the event object
    * @return Map<String, String> of the json, topic and GCP Key string from the mapped data
    */
    public static Map<String, String> GetMappingOut( Object objEvent) {
        Map<String, String> mappedJson = BuildJsonMap(objEvent, '', '');
        String messageBase64 = EncodingUtil.base64Encode(Blob.valueof(mappedJson.get('json')));
        mappedJson.put('json',messageBase64);
        return mappedJson;
    }
    
    /*******************************************************************************************************
    * @description Returns the mapped json of the SFDC Event from Google PubSub message 
    * @param topic the GCP pubsub topic
    * @param jsonData the json data sent in from GCP function
    * @return Map<String, String> of the json string from the mapped data
    */
    public static Map<String, String> GetMappingIn( String topic, String jsonData) {
        return BuildJsonMap(null, topic, jsonData);
    }
    private static Map<String, String> BuildJsonMap(Object objEvent, String topic, String jsonData){
        Map<String, String> result = new Map<String, String>();
        Map<String, Object> jsonMap = new Map<String, Object>();
        Map<String, Object> pubsubMap = new Map<String, Object>();
        Map<String, Object> eventMap = new Map<String, Object>();
        if(String.isEmpty(topic) && objEvent != null) {
            pubsubMap = GetMapDefinition( '', objEvent);            
            eventMap = (Map<String, Object>)JSON.deserializeUntyped(JSON.serialize(objEvent));
            result.put('gcp_key',(String)pubsubMap.get('gcp_key'));
            result.put('topic', (String)pubsubMap.get('topic'));
            
        } else if(!String.isEmpty(topic) && objEvent == null) {
            pubsubMap = GetMapDefinition( topic, null);
            eventMap = (Map<String, Object>)JSON.deserializeUntyped(jsonData);
            result.put('event', (String)pubsubMap.get('event'));
        }
        Map<String, String> configMap = (Map<String, String>)pubsubMap.get('mapdefinition');
      
        for(String fieldName: configMap.keySet()) {
            String externalName = configMap.get(fieldName);
            if(!externalName.contains('.')) {
                jsonMap.put(externalName, eventMap.get(fieldName));
            } else {
                Map<String, Object> childObjectMap = new Map<String, Object>();
                String childObjectName = externalName.substringBefore('.');
                if(jsonMap.containsKey(childObjectName)) {
                    childObjectMap = (Map<String, Object>)jsonMap.get(childObjectName);
                } else {
                    jsonMap.put(childObjectName, childObjectMap);
                }
                
                String childObjectFieldName = externalName.substringAfter('.');
                childObjectMap.put(childObjectFieldName, eventMap.get(fieldName));
            }
        }
        result.put('json', JSON.serialize(jsonMap));
        return result;
    }
    /*******************************************************************************************************
    * @description Returns the mapped json definition from metadata
    * @param topic the name of the topic used in pubsub
    * @param objEvent the event object
    * @return a Map<String, String> of the json config from metadata
    */
    private static Map<String, Object> GetMapDefinition( String topic, Object objEvent) {
        Map<String, Object> metaMap = new Map<String, Object>();
        Map<String, String> mapDefinition = new Map<String, String>();
        List<Pub_Sub_Mapping__mdt> savedMapping;
        String errSource = '';
        if(String.isEmpty(topic) && objEvent != null) {
            String apiName = ((SObject)objEvent).getSObjectType().getDescribe().getName();
            System.debug('Event apiName: '+apiName);
            errSource = 'Event ' + apiName;
            savedMapping = [SELECT Map_Definition__c, Event_Api_Name__c, Topic__c, GCP_Key__c FROM Pub_Sub_Mapping__mdt 
            WHERE Event_Api_Name__c =: apiName AND Direction__c = 'Out' Limit 1];
        } else if(!String.isEmpty(topic) && objEvent == null) {
            savedMapping = [SELECT Map_Definition__c, Event_Api_Name__c, Topic__c, GCP_Key__c FROM Pub_Sub_Mapping__mdt 
            WHERE  Topic__c =: topic AND Direction__c = 'In' Limit 1];
            System.debug('Topic: ' + topic);
            errSource = 'Topic ' + topic;
        }
        if(savedMapping.isEmpty()){
            throw new PubSubMappingException ('No mapping found for ' + errSource);
        }
        Map<String, Object> jsonMap = (Map<String, Object>)JSON.deserializeUntyped(savedMapping[0].Map_Definition__c);
        for(String strKey: jsonMap.keyset()) {
            mapDefinition.put(strKey, String.valueOf(jsonMap.get(strKey)));
        } 
        metaMap.put('event', savedMapping[0].Event_Api_Name__c);
        metaMap.put('topic', savedMapping[0].Topic__c);
        metaMap.put('mapdefinition', mapDefinition);
        metaMap.put('gcp_key',savedMapping[0].GCP_Key__c);
        return metaMap;
    }
    public class PubSubMappingException extends Exception{}
}

## PubSubListener 
Class the receives the message from pubsub generating the corresponding platform event

/**
 * This class contains the endpoint to which meesages from pub sub 
 * will be sent.
 */
@RestResource(urlMapping='/GCP_PubSub_Listener/*')
global with sharing class PubSubListener {
    
    /*******************************************************************************************************
    * @description Receives the posted data from the google PubSub function to be processed as platform events
    */
    @HttpPost
    global static void postMessage(){
        RestRequest req = RestContext.request;
        RestResponse res = RestContext.response;
        System.debug('Message from Google was received');
        String message = req.requestBody.toString();
        System.debug ('### Message: '+message);
        
        Map<String, Object> jsonMap = (Map<String, Object>)JSON.deserializeUntyped(message);
        
        String topic = String.valueOf(jsonMap.get('topic'));
        Blob b = EncodingUtil.base64Decode(String.valueOf(jsonMap.get('data')));
        String jsonData = b.toString();
        publishEvent(topic, jsonData);
        
        //res.statusCode = 200;
    }
    /*******************************************************************************************************
    * @description Publish the event generated from the mapping
    * @param topic the GCP pubsub topic
    * @param jsonData the json data sent in from GCP function
    */
    static void publishEvent(String topic, String jsonData){
        try{
            Map<String,String> metaInfo = PubSubMapperHelper.GetMappingIn(topic, jsonData);
            String typeName= metaInfo.get('event');
            String mappedJson = metaInfo.get('json');
            
            Map<String,Object> result = (Map<String, Object>)JSON.deserializeUntyped(mappedJson);
            SObject dynamicEvent = buildEvent(typeName, result);
            Database.SaveResult savedResult = Eventbus.publish(dynamicEvent);
            System.debug('@@@ ' + typeName + ' event processed = ' + savedResult.isSuccess());
        }
        catch(Exception ex){
            System.debug('Event Error:' + ex.getMessage());
        }
    }
    /*******************************************************************************************************
    * @description Returns the platform event from the mapping
    * @param typeName the type of event to be created
    * @param fields the fields and data for the event
    * @return SObject of the built platform event
    */
    static SObject buildEvent(String typeName, Map<String, Object> fields){
        Schema.SObjectType objToken = Schema.getGlobalDescribe().get(typeName);
            
        //Get the fields type information in case I need to cast the data
        Map<String, Schema.SObjectField> fieldMap = objToken.getDescribe().fields.getMap();
        sobject dynamicEvent = objToken.newSObject();
        
        for(String strKey: fields.keyset()) {
            if(fieldMap.containsKey(strKey)){
                dynamicEvent.put(strKey, String.valueOf(fields.get(strKey)));
            } else {
                System.debug('Event Error: ' + typeName + ' - Mapped field ' + strKey + ' does not exist');
            }
        }
        return dynamicEvent;
    }
}


## PubSubListenerTest class 
    
    @isTest
    private class PubSubListenerTest {
        @isTest
        private static void testPostMessage(){
            RestRequest req = new RestRequest();
            req.requestUri = System.URL.getSalesforceBaseUrl().toExternalForm()+'/apexrest/GCP_PubSub_Listener';
            req.httpMethod = 'POST';
            //Generating the message for the call
            String data = '{"Name": "Test Account","Street": "Collins Ave","City": "Miami Beach","HSID": "GF", "Nofield":"No Data"}';
            Blob blobData = Blob.valueOf(data);
            String encodedData = EncodingUtil.base64Encode(blobData);
            Map<String,String> message = new Map<String,String>();
            message.put('data',encodedData);
            message.put('topic','inbound');
            System.debug('### Message: '+message);
            String jsonMessage = JSON.serialize(message);
            // Seeting the message
            Blob blobMessage = Blob.valueOf(jsonMessage);
            req.requestBody = blobMessage;
            RestContext.request = req;
            //Calling the method to be tested
            PubSubListener.postMessage();
        }
    }

# Bibliography:
You can search for more information about integrating Salesforce and Google cloud by going to 
https://cloud.google.com/architecture/calling-protected-cloud-functions

## Notes: 
    • To put and to get data to/from cache, check  the following classes in the Apex Reference:
        ○ Chache.Org class in Apex Reference
    • For requesting token for the OAuth2.0 protocol, check the following classes in the Apex Reference:
        ○ Auth.JWT (JSON Web token )
        ○ Auth.JWS (JSON Web Signature)
        ○  Auth.JWTBearerTokenExchange
    • It is worth to read 'Using OAuth 2.0' to access Google APIs, which can be accessed via https://developers.google.com/identity/protocols/oauth2
