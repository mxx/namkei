(ns namkei.routes.services
  (:require [ring.util.http-response :refer :all]
            [compojure.api.sweet :refer :all]
            [namkei.funcs :as func]
            [schema.core :as s]))

(defapi service-routes
  {:swagger {:ui "/api-ui"
             :spec "/enigma.json"
             :data {:info {:version "1.0.0"
                           :title "ENIGMA API"
                           :description "ENIGMA Services"}}}}
  
  (context "/api/v1.0.0" []
           :tags ["lenamkei"]
           
           (GET "/kasnahu" []
                :return       String
                :query-params [cmene :- String, namcu :- String]
                :summary      "hash value for object"
                (ok (func/kasnahu cmene namcu)))
           
           (POST "/kasnahu" []
                 :return      String
                 :body-params [cmene :- String, namcu :- String]
                 :summary     "hash value for object"
                 (ok (func/kasnahu cmene namcu)))
           
           (GET "/kasnahu/:namcu/:cmene" []
                :return      String
                :path-params [cmene :- String, namcu :- String]
                :summary     "hash value for object"
                (ok (func/kasnahu cmene namcu)))
           
           (POST "/kasnahupamoi" []
                 :return      String
                 :form-params [cmene :- String, namcu :- String]
                 :summary     "hash value for object"
                 (ok (func/kasnahu cmene namcu)))
           
           ))
