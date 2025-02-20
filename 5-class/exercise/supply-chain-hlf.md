## Supply Chain Using HLF
Develop a supply chain using latest version of HLF. Network with four companies and a specific chaincode exposed as rest API.

> Refer to HLF [fabric samples](https://github.com/hyperledger/fabric-samples)

## API Specifications

**AddTuna**
----
  Add new Tuna to the blockchain network

* **URL**

  `/api/addTuna`

* **Method:**
  
	`POST` 

* **Data Params**

```
  "id":integer,
  "latitude":string,
  "longitude":string,
  "length":integer,
  "weight":integer
 ``` 

* **Success Response:**
  
``` 
{	
  "status":"OK - Transaction has been submitted",
  "txid":"7f485a8c3a3c7f982aed76e3b20a0ad0fb4cbf174fbeabc792969a30a3383499"
} 
```
 
* **Sample Call:**

 ``` 
 curl --request POST \
  --url http://localhost:3000/api/addTuna \
  --header 'content-type: application/json' \
  --data '{
			"id":10001,
			"latitude":"43.3623",
			"longitude":"8.4115",
			"length":34,
			"weight":50
		   }' 
 ```
            
**getTuna**
----
  Get Tuna from the blockchain with the actual status

* **URL**

  `/api/getTuna/:id`

* **Method:**
  
	`GET` 

* **URL Params**
    `"id":integer`

* **Success Response:**
  
 ``` 
 {
    "result": {
        "id": integer
        "latitude": string
        "longitude": string
        "length": integer
        "weight": integer
    } 
 }
 ```
 
* **Sample Call:**

``` 
curl --request GET \
  --url 'http://localhost:3000/api/getTuna/<TunaId>' \
  --header 'content-type: application/json' \ 
```


**setPosition**
----
  Sets the position (latitude and longitud) for the specified id, could be sushiId or TunaId

* **URL**

  `/api/getTuna/setPosition`

* **Method:**
  
	`POST` 

* **Data Params**
``` 
"id":10001,
"latitude":"43.3623",
"longitude":"8.4115"
``` 

* **Success Response:**
  
 ``` 
{	
	status":"OK - Transaction has been submitted",
	"txid":"7f485a8c3a3c7f982aed76e3b20a0ad0fb4cbf174fbeabc792969a30a3383499"
}
 ```
 
* **Sample Call:**

``` 
curl --request POST \
  --url http://localhost:3000/api/setPosition \
  --header 'content-type: application/json' \
  --data '{
            "id":10001,
            "latitude":"43.3623",
            "longitude":"8.4115"
			}'
```

**addSushi**
----
   Add new Sushi to the blockchain network with the related TunaId

* **URL**

  `/api/getTuna/addSushi`

* **Method:**
  
	`POST` 

* **Data Params**
 ```   
"id":integer,
"latitude":string,
"longitude":string,
"type":string,
"tunaId":integer
 ``` 
* **Success Response:**
  
 ``` 
{	
	status":"OK - Transaction has been submitted",
	"txid":"7f485a8c3a3c7f982aed76e3b20a0ad0fb4cbf174fbeabc792969a30a3383499"
}
 ```
 
* **Sample Call:**

``` 
curl --request POST \
  --url http://localhost:3000/api/addSushi \
  --header 'content-type: application/json' \
  --data '{
			"id":200001,
            "latitude":"42.5987",
            "longitude":"5.5671",
            "type":"sashimi",
            "tunaId":10001
			}'
```

**getSushi**
----
  Get sushi from the blockchain with the actual status

* **URL**

  `/api/getSushi/:id`

* **Method:**
  
	`GET` 

* **URL Params**
    `"id":integer`

* **Success Response:**
  
 ``` 
  {
    "result": {
            "id":"200001",
            "latitude":"42.5987",
            "longitude":"5.5671",
            "type":"sashimi",
            "tunaId":10001
			}'
}
 ```
 
* **Sample Call:**
 
``` 
curl --request GET \
  --url 'http://localhost:3000/api/getSushi/<SushiId>' \
  --header 'content-type: application/json' \
```



**getSushiHistory**
----
  Get sushi history, from the TunaId that started the supply-chain, getting all the history positions, until the sushi is delivered, with the sushi history too

* **URL**

  `/api/getHistorySushi/:id`

* **Method:**
  
	`GET` 

* **URL Params**
    `"id":integer`

* **Success Response:**
  
 ``` 
{
    "historySushi": [
        {
            "id": "200001",
            "latitude":"42.5987",
            "longitude":"5.5671",
            "type": "sashimi",
            "tunaId": 10004
        },
        {
            "id": "200001",
            "latitude":"43.3623",
            "longitude":"8.4115",
            "type": "sashimi",
            "tunaId": 10004
        }
    ],
    "historyTuna": [
        {
            "id": "10004",
            "latitude":"43.3623",
            "longitude":"8.4115",
            "length": 34,
            "weight": 50
        }
    ]
}
 ```
 
* **Sample Call:**
 
 ``` 
curl --request GET \
  --url 'http://localhost:3000/api/getHistorySushi/<SushiId>' \
  --header 'content-type: application/json' \
```

### Submission
* Create a private repository on GitHub and provide read access to `dhruvinparikh`
* Keep pushing commits to the repo
* In the class 5 discussion forum, only paste the GitHub repository link.
* Partial completion is accepted, efforts will be valued.
