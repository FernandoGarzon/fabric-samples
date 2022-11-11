package chaincode

import (
	"encoding/json"
	"fmt"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
	"github.com/xeipuuv/gojsonschema"

	"crypto/sha256"
	"encoding/hex"
	"log"
)

// SmartContract provides functions for managing an Asset
type SmartContract struct {
	contractapi.Contract
}

// Asset describes basic details of what makes up a simple asset
// Insert struct field in alphabetic order => to achieve determinism across languages
// golang keeps the order when marshal to json but doesn't order automatically

/*type Data struct {
	docType          string `json:"docType"`
	id               string `json:"id"`
	title            string `json:"title"`
	description      string `json:"description"`
	Type             string `json:"Type"`
	DOI              string `json:"DOI"`
	url              string `json:"url"`
	manifest         string `json:"manifest"`
	footprint        string `json:"footprint"`
	keywords         string `json:"keywords"`
	otherDataIdName  string `json:"otherDataIdName"`
	otherDataIdValue string `json:"otherDataIdValue"`
	fundingAgencies  string `json:"fundingAgencies"`
	acknowledgment   string `json:"acknowledgment"`
	noteForChange    string `json:"noteForChange"`
	contributor      string `json:"contributor"`
	contributor_id   string `json:"contributor_id"`
}*/

// Asset describes basic details of what makes up a simple asset
// Insert struct field in alphabetic order => to achieve determinism across languages
// golang keeps the order when marshal to json but doesn't order automatically

var lastSchemaHash string

type Data struct {
	Contributor     string `json:"Contributor"`
	ContributorId   string `json:"ContributorId"`
	ContentHash     string `json:"ContentHash"`
	Id              string `json:"Id"`
	Owner           string `json:"Owners"`
	JsonFileContent map[string]interface{}
}

type Schema struct {
	Version           int    `json:"Version"`
	Hash              string `json:"Hash"`
	JsonSchemaContent map[string]interface{}
}

// InitLedger adds a base set of Data entries to the ledger
func (s *SmartContract) InitLedger(ctx contractapi.TransactionContextInterface, InitSchema string, InitData string) error {

	// We use the function jsonReader in order to read the content of the shcema Json File. The schema Json file is composed by us and inserted into
	// the docker container of the commited chaincode (For now)
	schemaJsonFileContent, error_schema := s.JsonReader(ctx, InitSchema)
	firstJsonFileContent, error_file := s.JsonReader(ctx, InitData)

	if error_schema != nil {
		return fmt.Errorf("failed to read shcema.json file: %v", error_schema)
	} else if error_file != nil {
		return fmt.Errorf("failed to read 1st json files: %v", error_file)
	} else {

		firstJsonFileHash, initDataHashError := s.Hash(ctx, InitData)
		schemaJsonFileHash, schemaHashError := s.Hash(ctx, InitSchema)
		lastSchemaHash = schemaJsonFileHash
		if initDataHashError != nil {
			return fmt.Errorf("failed to calculate 1st json file hash: %v", initDataHashError)
		} else if schemaHashError != nil {
			return fmt.Errorf("failed to calculate schema hash: %v", schemaHashError)
		} else {
			data := Data{
				Contributor:     "pepitoperes@email.com",
				ContributorId:   "ABC123",
				ContentHash:     firstJsonFileHash,
				Id:              "00000",
				Owner:           "CIA",
				JsonFileContent: firstJsonFileContent,
			}

			assetJSON, err := json.Marshal(data)
			if err != nil {
				return err
			}

			err = ctx.GetStub().PutState(data.ContentHash, assetJSON)
			if err != nil {
				return fmt.Errorf("failed to put to world state. %v", err)
			} else {
				fmt.Print("A new Data Struct has been created with the hash %v", firstJsonFileHash)
			}

			//This is the definition of the Schema that we should use for validate all the JSON files from now on.

			initSchema := Schema{
				Version:           1,
				Hash:              schemaJsonFileHash,
				JsonSchemaContent: schemaJsonFileContent,
			}

			assetJSON, err = json.Marshal(initSchema)
			if err != nil {
				return err
			}

			err = ctx.GetStub().PutState(initSchema.Hash, assetJSON)
			if err != nil {
				return fmt.Errorf("failed to put to world state. %v", err)
			} else {
				fmt.Print("A new Schema has been created with the hash %v", schemaJsonFileHash)
			}
		}
	}
	return nil
}

func (s *SmartContract) LastSchemaHash(ctx contractapi.TransactionContextInterface) string {
	return lastSchemaHash
}

func (s *SmartContract) Hash(ctx contractapi.TransactionContextInterface, doc string) (string, error) {

	var v interface{}
	err := json.Unmarshal([]byte(doc), &v)
	if err != nil {
		return "HASH CRASH", fmt.Errorf("Unable to unmarshal Json String passed as parameter. No hash calculation can be completed: %v", err)
	} else {
		cdoc, err := json.Marshal(v)
		if err != nil {
			return "HASH CRASH", fmt.Errorf("Unable to re-marshal interface into json format. No hash calculation can be completed: %v", err)
		} else {
			sum := sha256.Sum256(cdoc)
			return hex.EncodeToString(sum[0:]), nil
		}
	}
}

func (s *SmartContract) JsonReader(ctx contractapi.TransactionContextInterface, content string) (map[string]interface{}, error) {

	var payload map[string]interface{}
	// Now let's unmarshall the data into `payload`
	err := json.Unmarshal([]byte(content), &payload)
	if err != nil {
		log.Fatal("Error during Unmarshal() of string into type Interface: ", err)
	}
	return payload, nil

}

// GetAllAssets returns all assets found in world state
/*func (s *SmartContract) GetAllAssets(ctx contractapi.TransactionContextInterface) ([]*Data, error) {
	// range query with empty string for startKey and endKey does an
	// open-ended query of all assets in the chaincode namespace.
	resultsIterator, err := ctx.GetStub().GetStateByRange("", "")
	if err != nil {
		return nil, err
	}
	defer resultsIterator.Close()

	var dataSamples []*Data
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, err
		}

		var data Data
		func PrintRandomDiv() {
			defer func() {
			  if panicInfo := recover(); panicInfo != nil {
				fmt.Printf("%v, %s", panicInfo, string(debug.Stack()))
			  }
			}()
			err = json.Unmarshal(queryResponse.Value, &data)
		  }

		if err != nil {
			log.Fatal("Error during Unmarshal() of string into type Data: ", err)
			return nil, err
		}
		dataSamples = append(dataSamples, &data)

	}

	return dataSamples, nil
}
*/

func (s *SmartContract) SchemaExists(ctx contractapi.TransactionContextInterface, Hash string) (bool, error) {
	assetJSON, err := ctx.GetStub().GetState(Hash)
	if err != nil {
		return false, fmt.Errorf("failed to read from world state: %v", err)
	}

	return assetJSON != nil, nil
}

func (s *SmartContract) CreateNewSchema(ctx contractapi.TransactionContextInterface,
	version int, newSchemaContent string) error {

	// We assume this new schema is different from what existed previously
	//exists, err := s.AssetExists(ctx, Id)
	//if err != nil {
	//	return err
	//}
	//if exists {
	//	return fmt.Errorf("the asset %s already exists", Id)
	//}

	jsonFileContent, err := s.JsonReader(ctx, newSchemaContent)
	if err != nil {
		return err
	} else {
		// Verify that an schema with exact same structure doesn't exist yet.
		hashContent, _ := s.Hash(ctx, newSchemaContent)
		exists, err := s.SchemaExists(ctx, hashContent)
		if exists {
			return fmt.Errorf("Schema already exists: %v", err)
		} else {
			lastSchemaHash = hashContent
			newSchema := Schema{
				Version:           version,
				Hash:              hashContent,
				JsonSchemaContent: jsonFileContent,
			}

			assetJSON, err := json.Marshal(newSchema)
			if err != nil {
				return err
			}

			err = ctx.GetStub().PutState(newSchema.Hash, assetJSON)
			if err != nil {
				return fmt.Errorf("failed to put to world state. %v", err)
			}
		}

		return nil
	}
}

// GetAllSchemas returns all schemas found in world state

//func (s *SmartContract) GetAllSchemas(ctx contractapi.TransactionContextInterface) ([]Schema, error) {
// range query with empty string for startKey and endKey does an
// open-ended query of all schemas in the chaincode namespace.
//resultsIterator, err := ctx.GetStub().GetStateByRange("", "")
//if err != nil {
//	return nil, err
//}
//defer resultsIterator.Close()

//var schemaSamples []*Schema
//for resultsIterator.HasNext() {
//	queryResponse, err := resultsIterator.Next()
//	if err != nil {
//		return nil, err
//	}

//	var schm Schema
//	err = json.Unmarshal(queryResponse.Value, &schm)
//	if err != nil {
//		return nil, err
//	}
//	schemaSamples = append(schemaSamples, &schm)
//}

//return schemas, nil
//}

// AssetExists returns true when asset with given ID exists in world state
func (s *SmartContract) AssetExists(ctx contractapi.TransactionContextInterface, Id string) (bool, error) {
	assetJSON, err := ctx.GetStub().GetState(Id)
	if err != nil {
		return false, fmt.Errorf("failed to read from world state: %v", err)
	}

	return assetJSON != nil, nil
}

// JSON Validation

func (s *SmartContract) ValidJson(ctx contractapi.TransactionContextInterface, JsonContent string) (bool, error) {

	//schemaLoader := gojsonschema.NewReferenceLoader("file:///Users/fernando/Projects/OSC-IS/fabric-samples/test-network/JsonSchemaValidationTests/Schema.json")
	//documentLoader := gojsonschema.NewReferenceLoader("file:////Users/fernando/Projects/OSC-IS/fabric-samples/test-network/JsonSchemaValidationTests/testFile.json")

	//schemaLoader := gojsonschema.NewReferenceLoader("file:///home/chaincode/Schema.json")
	//documentLoader := gojsonschema.NewReferenceLoader("file:////home/chaincode/testFile.json")

	// PATH Needs to be absolute path (From root '/'). Add something that takes care of that.

	//m := schemas[len(schemas) - 1].JsonFileContent

	CurrentSchemaHash := s.LastSchemaHash(ctx)
	schema, _ := s.ReadSchema(ctx, CurrentSchemaHash)

	schemaLoader := gojsonschema.NewGoLoader(schema.JsonSchemaContent)
	documentLoader := gojsonschema.NewStringLoader(JsonContent)

	result, err := gojsonschema.Validate(schemaLoader, documentLoader)

	if err != nil {
		panic(err.Error())
	}

	if result.Valid() {
		fmt.Printf("The document is valid\n")
	} else {
		fmt.Printf("The document is not valid. see errors :\n")
		for _, desc := range result.Errors() {
			fmt.Printf("- %s\n", desc)
		}
	}
	return result.Valid(), nil
}

// CreateDataSample issues a new Data Sample to the world state with given details.
func (s *SmartContract) CreateDataSample(ctx contractapi.TransactionContextInterface,
	Contributor string, ContributorId string, Id string, Owner string, JsonFileContent string) error {

	ContentHash, err := s.Hash(ctx, JsonFileContent)
	exists, err := s.AssetExists(ctx, ContentHash)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("the asset %s already exists", ContentHash)
	}

	valid, err := s.ValidJson(ctx, JsonFileContent)
	if err != nil {
		return err
	}
	if !valid {
		return fmt.Errorf("the json file provided is not valid")
	} else {
		jsonFileContent, err := s.JsonReader(ctx, JsonFileContent)
		if err != nil {
			return err
		} else {
			data := Data{
				Contributor:     Contributor,
				ContributorId:   ContributorId,
				ContentHash:     ContentHash,
				Id:              Id,
				Owner:           Owner,
				JsonFileContent: jsonFileContent,
			}

			assetJSON, err := json.Marshal(data)
			if err != nil {
				return err

			}
			return ctx.GetStub().PutState(ContentHash, assetJSON)
		}
	}

}

// UpdateAsset updates an existing asset in the world state with provided parameters.
func (s *SmartContract) UpdateAsset(ctx contractapi.TransactionContextInterface,
	Contributor string, ContributorId string, ContentHash string, Id string) error {
	exists, err := s.AssetExists(ctx, Id)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("the asset %s does not exist", Id)
	}

	// overwriting original asset with new asset

	data := Data{
		Contributor:   Contributor,
		ContributorId: ContributorId,
		ContentHash:   ContentHash,
		Id:            Id,
		Owners:        []string{"DOE", "DOS", "DOJ"},
	}

	assetJSON, err := json.Marshal(data)
	if err != nil {
		return err
	}

	return ctx.GetStub().PutState(Id, assetJSON)
}

func (s *SmartContract) DeleteAsset(ctx contractapi.TransactionContextInterface, Id string) error {
	exists, err := s.AssetExists(ctx, Id)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("the asset %s does not exist", Id)
	}

	return ctx.GetStub().DelState(Id)
}

func (s *SmartContract) ReadAsset(ctx contractapi.TransactionContextInterface, Id string) (*Data, error) {
	assetJSON, err := ctx.GetStub().GetState(Id)
	if err != nil {
		return nil, fmt.Errorf("failed to read from world state: %v", err)
	}
	if assetJSON == nil {
		return nil, fmt.Errorf("the asset %s does not exist", Id)
	}

	var data Data
	err = json.Unmarshal(assetJSON, &data)
	if err != nil {
		return nil, err
	}

	return &data, nil
}

func (s *SmartContract) ReadSchema(ctx contractapi.TransactionContextInterface, hash string) (*Schema, error) {
	assetJSON, err := ctx.GetStub().GetState(hash)
	if err != nil {
		return nil, fmt.Errorf("failed to read from world state: %v", err)
	}
	if assetJSON == nil {
		return nil, fmt.Errorf("the schema with hash %s does not exist", hash)
	}

	var schema Schema
	err = json.Unmarshal(assetJSON, &schema)
	if err != nil {
		return nil, err
	}

	return &schema, nil
}

// TransferAsset updates the owner field of asset with given id in world state, and returns the old owner.
func (s *SmartContract) TransferAsset(ctx contractapi.TransactionContextInterface, Id string, newOwners []string) ([]string, error) {
	data, err := s.ReadAsset(ctx, Id)
	if err != nil {
		return []string{}, err
	}

	data.Owners = newOwners

	assetJSON, err := json.Marshal(data)
	if err != nil {
		return []string{}, err
	}

	err = ctx.GetStub().PutState(Id, assetJSON)
	if err != nil {
		return []string{}, err
	}

	return data.Owners, nil
}

/*


// ReadAsset returns the asset stored in the world state with given id.
func (s *SmartContract) ReadAsset(ctx contractapi.TransactionContextInterface, id string) (*Asset, error) {
	assetJSON, err := ctx.GetStub().GetState(id)
	if err != nil {
		return nil, fmt.Errorf("failed to read from world state: %v", err)
	}
	if assetJSON == nil {
		return nil, fmt.Errorf("the asset %s does not exist", id)
	}

	var asset Asset
	err = json.Unmarshal(assetJSON, &asset)
	if err != nil {
		return nil, err
	}

	return &asset, nil
}



// TransferAsset updates the owner field of asset with given id in world state, and returns the old owner.
func (s *SmartContract) TransferAsset(ctx contractapi.TransactionContextInterface, id string, newOwner string) (string, error) {
	asset, err := s.ReadAsset(ctx, id)
	if err != nil {
		return "", err
	}

	oldOwner := asset.Owner
	asset.Owner = newOwner

	assetJSON, err := json.Marshal(asset)
	if err != nil {
		return "", err
	}

	err = ctx.GetStub().PutState(id, assetJSON)
	if err != nil {
		return "", err
	}

	return oldOwner, nil
}

// GetAllAssets returns all assets found in world state
func (s *SmartContract) GetAllAssets(ctx contractapi.TransactionContextInterface) ([]*Asset, error) {
	// range query with empty string for startKey and endKey does an
	// open-ended query of all assets in the chaincode namespace.
	resultsIterator, err := ctx.GetStub().GetStateByRange("", "")
	if err != nil {
		return nil, err
	}
	defer resultsIterator.Close()

	var assets []*Asset
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, err
		}

		var asset Asset
		err = json.Unmarshal(queryResponse.Value, &asset)
		if err != nil {
			return nil, err
		}
		assets = append(assets, &asset)
	}

	return assets, nil
}
*/
