package chaincode

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
	"github.com/xeipuuv/gojsonschema"

	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"log"
)

// SmartContract provides functions for managing an Asset
type SmartContract struct {
	contractapi.Contract
}

// Asset describes basic details of what makes up a simple asset

// Asset describes basic details of what makes up a simple asset
// Insert struct field in alphabetic order => to achieve determinism across languages
// golang keeps the order when marshal to json but doesn't order automatically

var lastSchemaHash string
var APIUserIds []string

const PDC1 = "PDC1"
const PDC2 = "PDC2"

type Data struct {
	OrgName     string `json:"OrgName"`
	ProjectName string `json:"ProjectName"`
	ContentHash string `json:"ContentHash"`
	Comment     string `json:"Comment"`
	APIUserID   string `json:"APIUserID"`
	Date        string `json:"Date"`
	JsonContent map[string]interface{}
}

type PrivateSchemaContent struct {
	JsonSchemaContent map[string]interface{} `json:"JsonSchemaContent"`
	SchemaId          string                 `json:"SchemaId"`
	Project           string                 `json:"Project`
}

// Not being persisted
type Schema struct {
	JsonSchemaContent map[string]interface{} `json:"JsonSchemaContent"`
	SchemaId          string                 `json:"SchemaId"`
	Project           string                 `json:"Project`
}

type User struct {
	UUID      string   `json:"UUID"` // UUID := Hash(OrgName + assetInput.APIUserId)
	APIUserId string   `json:"APIUserId"`
	Groups    []string `json:"Groups"`   // Array of GIDs the User is part of
	Projects  []string `json:"Projects"` // Array of PIDs the User is part of
	Org       string   `json:"Org"`
}

type Group struct {
	GID       string `json:"GID"`       // GID := OrgName + ProjectName + GroupName
	GroupName string `json:"GroupName"` //Admin or Users
	Project   string `json:"Project"`
	Org       string `json:"Org"`
	Users     []User `json:"Users"` // Array of Users belonging to Group
}

type Project struct {
	PID         string  `json:"PID"` // PID = OrgName + ProjectName
	ProjectName string  `json:"ProjectName"`
	Org         string  `json:"Org"`
	Groups      []Group `json:"Groups"` // Array of Groups belonging to Project
}

// Main function
func main() {
	aChaincode, err := contractapi.NewChaincode(&SmartContract{})
	if err != nil {
		log.Panicf("Error creating artifact chaincode: %v", err)
	}

	if err := aChaincode.Start(); err != nil {
		log.Panicf("Error starting artifact chaincode: %v", err)
	}
}

// ProjectName should be the only argument passed in transient dictionary.

func (s *SmartContract) Init(ctx contractapi.TransactionContextInterface) error {

	transientAssetJSON, err := s.getTransientMap(ctx)
	if err != nil {
		return fmt.Errorf("error getting transient: %v", err)
	}

	type transientInput struct {
		GID         string `json:"GID"`
		GroupName   string `json:"GroupName"`
		ProjectName string `json:"ProjectName"`
		Org         string `json:"Org"`
	}

	var assetInput transientInput
	err = json.Unmarshal(transientAssetJSON, &assetInput)
	if err != nil {
		return fmt.Errorf("failed to unmarshal JSON: %v", err)
	}

	MSP, err := shim.GetMSPID()
	if err != nil {
		return fmt.Errorf("failed to get MSPID: %v", err)
	}

	Org := MSP
	PDC := "_implicit_org_" + MSP
	PID := Org + "." + assetInput.ProjectName
	GIDAdmin := Org + "." + assetInput.ProjectName + ".Admin"
	GIDUsers := Org + "." + assetInput.ProjectName + ".Users"

	assetAsBytes, err := ctx.GetStub().GetPrivateData(PDC, PID)

	if err != nil {
		return fmt.Errorf("failed to get Project: %v", err)
	} else if assetAsBytes != nil {
		fmt.Println("Project already exists: " + PID)
		return fmt.Errorf("this Project already exists: " + PID + ". Initialization stopped.")
	}

	assetAsBytes, err = ctx.GetStub().GetPrivateData(PDC, GIDAdmin)

	if err != nil {
		return fmt.Errorf("failed to get Grpup: %v", err)
	} else if assetAsBytes != nil {
		fmt.Println("Group already exists: " + PID)
		return fmt.Errorf("this Group already exists: " + GIDAdmin + ". Initialization stopped.")
	}

	assetAsBytes, err = ctx.GetStub().GetPrivateData(PDC, GIDUsers)

	if err != nil {
		return fmt.Errorf("failed to get Grpup: %v", err)
	} else if assetAsBytes != nil {
		fmt.Println("Group already exists: " + GIDUsers)
		return fmt.Errorf("this Group already exists: " + GIDUsers + ". Initialization stopped.")
	}

	clientID, err := submittingClientIdentity(ctx)
	if err != nil {
		return err
	}

	APIUserId := clientID

	//Has User been created?

	userID := MSP + "." + APIUserId

	h := sha1.New()
	h.Write([]byte(userID))
	hash := hex.EncodeToString(h.Sum(nil))

	UUID := hash

	assetAsBytes, err = ctx.GetStub().GetPrivateData(PDC, UUID)

	if err != nil {
		return fmt.Errorf("failed to get User: %v", err)
	} else if assetAsBytes != nil {
		fmt.Println("User already exists: " + UUID)
		return fmt.Errorf("this User already exists: " + UUID)
	}

	//Initial User
	PI := User{
		UUID:      UUID,
		APIUserId: APIUserId,
		Groups:    []string{"Admin", "Users"},
		Projects:  []string{assetInput.ProjectName},
		Org:       MSP,
	}

	// Initial Admin Group
	Admin := Group{
		GID:       GIDAdmin,
		GroupName: "Admin",
		Project:   assetInput.ProjectName,
		Org:       MSP,
		Users:     []User{PI},
	}

	// Initial Users Group
	Users := Group{
		GID:       GIDUsers,
		GroupName: "Users",
		Project:   assetInput.ProjectName,
		Org:       MSP,
		Users:     []User{PI},
	}

	//Initial Project
	Project_ := Project{

		PID:         PID,
		ProjectName: assetInput.ProjectName,
		Org:         MSP,
		Groups:      []Group{Admin, Users},
	}

	assetJSONasBytes, err := json.Marshal(Project_)
	if err != nil {
		return fmt.Errorf("failed to marshal Project into JSON: %v", err)
	}

	log.Printf("WriteProjectToPDC Put: collection %v, ID %v, owner %v", PDC, PID, clientID)

	err = ctx.GetStub().PutPrivateData(PDC, PID, assetJSONasBytes)
	if err != nil {
		return fmt.Errorf("failed to put Project into private data collection: %v", err)
	}

	assetJSONasBytes, err = json.Marshal(Admin)
	if err != nil {
		return fmt.Errorf("failed to marshal Group Admin into JSON: %v", err)
	}

	log.Printf("Write Admin Group Put: collection %v, ID %v, owner %v", PDC, GIDAdmin, clientID)

	err = ctx.GetStub().PutPrivateData(PDC, GIDAdmin, assetJSONasBytes)
	if err != nil {
		return fmt.Errorf("failed to put Admin Group into private data collection: %v", err)
	}

	assetJSONasBytes, err = json.Marshal(Users)
	if err != nil {
		return fmt.Errorf("failed to marshal Group Users into JSON: %v", err)
	}

	log.Printf("Write Users Group Put: collection %v, ID %v, owner %v", PDC, GIDUsers, clientID)

	err = ctx.GetStub().PutPrivateData(PDC, GIDUsers, assetJSONasBytes)
	if err != nil {
		return fmt.Errorf("failed to put Users Group into private data collection: %v", err)
	}

	assetJSONasBytes, err = json.Marshal(PI)
	if err != nil {
		return fmt.Errorf("failed to marshal User PI into JSON: %v", err)
	}

	log.Printf("Write User PI Put: collection %v, ID %v, owner %v", PDC, UUID, clientID)

	err = ctx.GetStub().PutPrivateData(PDC, UUID, assetJSONasBytes)
	if err != nil {
		return fmt.Errorf("failed to put PI User into private data collection: %v", err)
	}

	return nil

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

func (s *SmartContract) GetAllAssets(ctx contractapi.TransactionContextInterface) ([]*Data, error) {
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

		var data map[string]interface{}
		err = json.Unmarshal(queryResponse.Value, &data)
		if err != nil {
			return nil, err
		} else {
			var dataSruct Data
			err = json.Unmarshal(queryResponse.Value, &dataSruct)
			if err != nil {
				return nil, err
			} else {
				dataSamples = append(dataSamples, &dataSruct)
			}
		}
	}

	return dataSamples, nil
}

func (s *SmartContract) SchemaExists(ctx contractapi.TransactionContextInterface, SchemaID string) (bool, error) {

	assetJSON, err := s.ReadSchemaFromPDC(ctx, SchemaID)

	if assetJSON == nil {
		return false, fmt.Errorf("failed to read from world state. Schema doesn't exist: %v", err)
	} else if err != nil {
		return false, fmt.Errorf("failed to read from world state. Schema doesn't exist: %v", err)
	} else {
		return true, nil
	}
}

// AssetExists returns true when asset with given ID exists in world state
func (s *SmartContract) AssetExists(ctx contractapi.TransactionContextInterface, Hash string) (bool, error) {
	assetJSON, err := ctx.GetStub().GetState(Hash)
	if err != nil {
		return false, fmt.Errorf("failed to read from world state. Asset dosen't exist: %v", err)
	} else if assetJSON != nil {
		var data map[string]interface{}
		err2 := json.Unmarshal(assetJSON, &data)
		if err2 != nil {
			return false, fmt.Errorf("failed to read from world state: %v", err2)
		} else if err3, ok := data["ContentHash"]; ok {
			return assetJSON != nil, nil
		} else {
			return false, fmt.Errorf("failed to read from world state. Hash passed as parameter may correspond to a Schema struct rather than to a Data Struct: %v", err3)
		}
	} else {
		return assetJSON != nil, nil
	}
}

// JSON Validation

func (s *SmartContract) ValidJson(ctx contractapi.TransactionContextInterface, JsonContent string, SchemaID string) (bool, error) {

	schema, err := s.ReadSchemaFromPDC(ctx, SchemaID)

	if err != nil {
		panic(err.Error())
	}

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
	OrgName string, ProjectName string, Comment string, Date string, APIUserID string, JsonFileContent string, SchemaID string) error {

	SchemaExists, err := s.SchemaExists(ctx, SchemaID)

	if err != nil {
		return err
	}
	if !SchemaExists {
		return fmt.Errorf("the Schema with Id %s doesn't exists", SchemaID)
	}
	ContentHash, err := s.Hash(ctx, JsonFileContent)
	if err != nil {
		return err
	}
	exists, err := s.AssetExists(ctx, ContentHash)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("the asset %s already exists", ContentHash)
	}

	valid, err := s.ValidJson(ctx, JsonFileContent, SchemaID)
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
				OrgName:     OrgName,
				ProjectName: ProjectName,
				ContentHash: ContentHash,
				Comment:     Comment,
				Date:        Date,
				APIUserID:   APIUserID,
				JsonContent: jsonFileContent,
			}

			assetJSON, err := json.Marshal(data)
			if err != nil {
				return err
			}
			return ctx.GetStub().PutState(ContentHash, assetJSON)
		}
	}

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

// TransferAsset updates the owner field of asset with given id in world state, and returns the old owner.

func (s *SmartContract) contains(ctx contractapi.TransactionContextInterface, st []string, str string) bool {
	for _, v := range st {
		if v == str {
			return true
		}
	}
	return false
}

func (s *SmartContract) GetUser(ctx contractapi.TransactionContextInterface, APIUserId string) (*User, error) {

	MSP, err := shim.GetMSPID()
	if err != nil {
		return nil, fmt.Errorf("failed to get MSPID: %v", err)
	}

	userID := MSP + "." + APIUserId

	h := sha1.New()
	h.Write([]byte(userID))
	hash := hex.EncodeToString(h.Sum(nil))

	UUID := hash
	PDC := "_implicit_org_" + MSP

	assetAsBytes, err := ctx.GetStub().GetPrivateData(PDC, UUID)

	if err != nil {
		return nil, fmt.Errorf("failed to get User: %v", err)
	}

	if assetAsBytes == nil {
		fmt.Println("User doesn't exist: " + UUID)
		return nil, fmt.Errorf("failed to get User. User doesn't exist or can't be found in PDC. Verify Hash: %v", err)
	}

	var user User

	err = json.Unmarshal(assetAsBytes, &user)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %v", err)
	}

	return &user, nil

}

// Pass APIUserID as argument in transient map
func (s *SmartContract) ReadUser(ctx contractapi.TransactionContextInterface) (*User, error) {

	transientAssetJSON, err := s.getTransientMap(ctx)
	if err != nil {
		return nil, fmt.Errorf("error getting transient: %v", err)
	}

	type transientInput struct {
		APIUserID string `json:"APIUserID"`
	}

	var assetInput transientInput
	err = json.Unmarshal(transientAssetJSON, &assetInput)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %v", err)
	}

	MSP, err := shim.GetMSPID()
	if err != nil {
		return nil, fmt.Errorf("failed to get MSPID: %v", err)
	}

	userID := MSP + "." + assetInput.APIUserID

	h := sha1.New()
	h.Write([]byte(userID))
	hash := hex.EncodeToString(h.Sum(nil))

	UUID := hash
	PDC := "_implicit_org_" + MSP

	assetAsBytes, err := ctx.GetStub().GetPrivateData(PDC, UUID)

	if err != nil {
		return nil, fmt.Errorf("failed to get User: %v", err)
	}

	if assetAsBytes == nil {
		fmt.Println("User doesn't exist: " + assetInput.APIUserID)
		return nil, nil
	}

	var user User

	err = json.Unmarshal(assetAsBytes, &user)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %v", err)
	}

	return &user, nil

}

// Subscribe a new user to the Implicit PDC. APIUserId ProjectName and GroupName need to be passed as parameters in transient map

func (s *SmartContract) NewUser(ctx contractapi.TransactionContextInterface) error {

	transientAssetJSON, err := s.getTransientMap(ctx)
	if err != nil {
		return fmt.Errorf("error getting transient: %v", err)
	}

	type transientInput struct {
		UUID        string `json:"UUID"`
		APIUserId   string `json:"APIUserId"`
		GroupName   string `json:"GroupName"`
		ProjectName string `json:"ProjectName"`
		Org         string `json:"Org"`
	}

	var assetInput transientInput
	err = json.Unmarshal(transientAssetJSON, &assetInput)
	if err != nil {
		return fmt.Errorf("failed to unmarshal JSON: %v", err)
	}

	MSP, err := shim.GetMSPID()
	if err != nil {
		return fmt.Errorf("failed to get MSPID: %v", err)
	}
	PDC := "_implicit_org_" + MSP
	assetInput.Org = MSP

	AdminGID := assetInput.Org + "." + assetInput.ProjectName + ".Admin"
	isAdmin, err := s.VerifyUserIsAdmin(ctx, AdminGID)

	if err != nil {
		return fmt.Errorf("verification of Submitting Identity cannot be performed: Error %v", err)
	}

	if !isAdmin {
		return fmt.Errorf("submitting Identity is not admin of respective Project %v. Can't create user %v. Error %v", assetInput.ProjectName, assetInput.APIUserId, err)
	}

	//Has User been created?

	userID := MSP + "." + assetInput.APIUserId

	h := sha1.New()
	h.Write([]byte(userID))
	hash := hex.EncodeToString(h.Sum(nil))

	assetInput.UUID = hash

	assetAsBytes, err := ctx.GetStub().GetPrivateData(PDC, assetInput.UUID)

	if err != nil {
		return fmt.Errorf("failed to get User: %v", err)
	} else if assetAsBytes != nil {
		fmt.Println("User already exists: " + assetInput.UUID)
		return fmt.Errorf("this User already exists: " + assetInput.UUID)
	}

	// Get ID of submitting client identity

	// Verify that the client is submitting request to peer in their organization
	// This is to ensure that a client from another org doesn't attempt to read or
	// write private data from this peer.
	err = verifyClientOrgMatchesPeerOrg(ctx)

	if err != nil {
		return fmt.Errorf("Creation of a New User cannot be performed: Error %v", err)
	}

	PID := MSP + "." + assetInput.ProjectName
	GID := PID + "." + assetInput.GroupName

	NewUser := User{
		UUID:      assetInput.UUID,
		APIUserId: assetInput.APIUserId,
		Groups:    []string{GID},
		Projects:  []string{PID},
		Org:       MSP,
	}
	assetJSONasBytes, err := json.Marshal(NewUser)
	if err != nil {
		return fmt.Errorf("failed to marshal Schema into JSON: %v", err)
	}

	GroupAsBytes, err := ctx.GetStub().GetPrivateData(PDC, GID)

	if GroupAsBytes == nil {
		return fmt.Errorf("Error Getting the Group %v from the Implicit PDC: Error %v. User can't be created if no Group is specified. Err: %v", err)
	}

	if err != nil {
		return fmt.Errorf("Error Getting the Group %v from the Implicit PDC: Error %v. User can't be created if no Group is specified. Err: %v", err)
	}

	err = ctx.GetStub().PutPrivateData(PDC, assetInput.UUID, assetJSONasBytes)
	if err != nil {
		return fmt.Errorf("failed to put asset into private data collection: %v", err)
	}

	//Update of Users Group

	var group Group

	err = json.Unmarshal(GroupAsBytes, &group)
	if err != nil {
		fmt.Errorf("failed to unmarshal JSON: %v", err)
	}

	group.Users = append(group.Users, NewUser)

	assetJSONasBytes, err = json.Marshal(group)
	if err != nil {
		return fmt.Errorf("failed to marshal Group into JSON: %v", err)
	}

	err = ctx.GetStub().PutPrivateData(PDC, GID, assetJSONasBytes)
	if err != nil {
		return fmt.Errorf("failed to Update Group into private data collection: %v", err)
	}

	return nil

}

// GroupName and ProjectName Arguments needed in transient map. GID = Org.ProjectName.GroupName. Org = MSP. GroupName is either Admin or Users. Project Object is obtain with ProjectName, and then added to the Group Struct.

func (s *SmartContract) NewGroup(ctx contractapi.TransactionContextInterface) error {

	transientAssetJSON, err := s.getTransientMap(ctx)
	if err != nil {
		return fmt.Errorf("error getting transient: %v", err)
	}

	type transientInput struct {
		GID         string `json:"GID"`
		GroupName   string `json:"GroupName"`
		ProjectName string `json:"ProjectName"`
		Org         string `json:"Org"`
		Users       []User `json:"Users"`
	}

	var assetInput transientInput
	err = json.Unmarshal(transientAssetJSON, &assetInput)
	if err != nil {
		return fmt.Errorf("failed to unmarshal JSON: %v", err)
	}

	MSP, err := shim.GetMSPID()
	if err != nil {
		return fmt.Errorf("failed to get MSPID: %v", err)
	}

	PDC := "_implicit_org_" + MSP
	assetInput.Org = MSP
	assetInput.GID = MSP + "." + assetInput.ProjectName + "." + assetInput.GroupName

	AdminGID := assetInput.Org + "." + assetInput.ProjectName + ".Admin"
	isAdmin, err := s.VerifyUserIsAdmin(ctx, AdminGID)

	if err != nil {
		return fmt.Errorf("verification of Submitting Identity cannot be performed: Error %v", err)
	}

	if !isAdmin {
		return fmt.Errorf("submitting Identity is not admin of respective Project %v. Can't create Group %v. Error %v", assetInput.ProjectName, assetInput.GID, err)
	}

	assetAsBytes, err := ctx.GetStub().GetPrivateData(PDC, assetInput.GID)

	if err != nil {
		return fmt.Errorf("failed to get Group: %v", err)
	} else if assetAsBytes != nil {
		fmt.Println("Group already exists: " + assetInput.GID)
		return fmt.Errorf("this Group already exists: " + assetInput.GID)
	}

	// Get ID of submitting client identity
	clientID, err := submittingClientIdentity(ctx)
	if err != nil {
		return err
	}

	// Verify that the client is submitting request to peer in their organization
	// This is to ensure that a client from another org doesn't attempt to read or
	// write private data from this peer.
	err = verifyClientOrgMatchesPeerOrg(ctx)
	if err != nil {
		return fmt.Errorf("CreateGroup cannot be performed: Error %v", err)
	}

	// We get the Project Object

	PID := MSP + "." + assetInput.ProjectName
	ProjectAsBytes, err := ctx.GetStub().GetPrivateData(PDC, PID)

	if err != nil {
		return fmt.Errorf("Error Getting the Project %v from the Implicit PDC: Error %v. Group can't be created if no Project is specified.", ProjectAsBytes, err)
	}

	if ProjectAsBytes == nil {
		return fmt.Errorf("Error Getting the Project %v from the Implicit PDC: Error %v. Group can't be created if no Group is specified. Err: %v", err)
	}

	NewGroup := Group{
		GID:       assetInput.GID,
		GroupName: assetInput.GroupName,
		Project:   PID,
		Users:     []User{},
		Org:       MSP,
	}
	assetJSONasBytes, err := json.Marshal(NewGroup)
	if err != nil {
		return fmt.Errorf("failed to marshal Schema into JSON: %v", err)
	}

	var project Project

	err = json.Unmarshal(ProjectAsBytes, &project)
	if err != nil {
		fmt.Errorf("failed to unmarshal JSON: %v", err)
	}

	project.Groups = append(project.Groups, NewGroup)

	assetJSONasBytes, err = json.Marshal(project)
	if err != nil {
		return fmt.Errorf("failed to marshal Project into JSON: %v", err)
	}

	err = ctx.GetStub().PutPrivateData(PDC, PID, assetJSONasBytes)
	if err != nil {
		return fmt.Errorf("failed to Update Project into private data collection: %v", err)
	}

	// Save asset to private data collection
	// Typical logger, logs to stdout/file in the fabric managed docker container, running this chaincode
	// Look for container name like dev-peer0.org1.example.com-{chaincodename_version}-xyz
	log.Printf("WriteGroupToPDC Put: collection %v, ID %v, owner %v", PDC, assetInput.GID, clientID)

	err = ctx.GetStub().PutPrivateData(PDC, assetInput.GID, assetJSONasBytes)
	if err != nil {
		return fmt.Errorf("failed to put asset into private data collection: %v", err)
	}

	return nil

}

// ProjectName Should be the only argument passed in transient dictionary. PID = OrgName.ProjectName.

func (s *SmartContract) NewProject(ctx contractapi.TransactionContextInterface) error {

	transientAssetJSON, err := s.getTransientMap(ctx)
	if err != nil {
		return fmt.Errorf("error getting transient: %v", err)
	}

	type transientInput struct {
		PID         string  `json:"PID"`
		ProjectName string  `json:"ProjectName"`
		Org         string  `json:"Org"`
		Groups      []Group `json:"Groups"`
	}

	var assetInput transientInput
	err = json.Unmarshal(transientAssetJSON, &assetInput)
	if err != nil {
		return fmt.Errorf("failed to unmarshal JSON: %v", err)
	}

	MSP, err := shim.GetMSPID()
	if err != nil {
		return fmt.Errorf("failed to get MSPID: %v", err)
	}
	PDC := "_implicit_org_" + MSP
	assetInput.Org = MSP
	assetInput.PID = MSP + "." + assetInput.ProjectName
	assetAsBytes, err := ctx.GetStub().GetPrivateData(PDC, assetInput.PID)

	if err != nil {
		return fmt.Errorf("failed to get Project: %v", err)
	} else if assetAsBytes != nil {
		fmt.Println("Project already exists: " + assetInput.PID)
		return fmt.Errorf("this Project already exists: " + assetInput.PID)
	}

	// Get ID of submitting client identity
	clientID, err := submittingClientIdentity(ctx)
	if err != nil {
		return err
	}

	// Verify that the client is submitting request to peer in their organization
	// This is to ensure that a client from another org doesn't attempt to read or
	// write private data from this peer.
	err = verifyClientOrgMatchesPeerOrg(ctx)
	if err != nil {
		return fmt.Errorf("CreateProject cannot be performed: Error %v", err)
	}

	NewProject := Project{
		PID:         assetInput.PID,
		ProjectName: assetInput.ProjectName,
		Groups:      []Group{},
		Org:         MSP,
	}
	assetJSONasBytes, err := json.Marshal(NewProject)
	if err != nil {
		return fmt.Errorf("failed to marshal Schema into JSON: %v", err)
	}

	// Save asset to private data collection
	// Typical logger, logs to stdout/file in the fabric managed docker container, running this chaincode
	// Look for container name like dev-peer0.org1.example.com-{chaincodename_version}-xyz
	log.Printf("WriteProjectToPDC Put: collection %v, ID %v, owner %v", PDC, assetInput.PID, clientID)

	err = ctx.GetStub().PutPrivateData(PDC, assetInput.PID, assetJSONasBytes)
	if err != nil {
		return fmt.Errorf("failed to put asset into private data collection: %v", err)
	}

	return nil

}

/**func (s *SmartContract) AssociateUserWithUUID(ctx contractapi.TransactionContextInterface, UUID string, APIId string) (string, error) {
	user, err := s.ReadUser(ctx, UUID)
	if err != nil {
		return "Error", fmt.Errorf("read User function failed excecution: %v", err)
	}
	if s.contains(ctx, user.APIUserId, APIId) {
		return "APIId provided is already associated with user " + UUID, nil
	}
	user.APIUserId = append(user.APIUserId, APIId)

	assetJSON, err := json.Marshal(user)
	if err != nil {
		return "Marshal of Data not done", err
	}

	err = ctx.GetStub().PutState(UUID, assetJSON)
	if err != nil {
		return "Unable to update asset", err
	}

	return "APIId added to map for user " + UUID, nil
}

func (s *SmartContract) GetAllUsers(ctx contractapi.TransactionContextInterface) ([]*User, error) {
	// range query with empty string for startKey and endKey does an
	// open-ended query of all schemas in the chaincode namespace.
	resultsIterator, err := ctx.GetStub().GetStateByRange("", "")
	if err != nil {
		return nil, err
	}
	defer resultsIterator.Close()

	var UserSamples []*User
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, err
		}

		var user map[string]interface{}
		err = json.Unmarshal(queryResponse.Value, &user)
		if err != nil {
			return nil, err
		} else if _, ok := user["UUID"]; ok {
			var userStruct User
			err = json.Unmarshal(queryResponse.Value, &userStruct)
			if err != nil {
				return nil, err
			} else {
				UserSamples = append(UserSamples, &userStruct)
			}
		}
	}

	return UserSamples, nil
}

func (s *SmartContract) GroupExists(ctx contractapi.TransactionContextInterface, GroupId string) (bool, error) {
	assetJSON, err := ctx.GetStub().GetState(GroupId)
	if err != nil {
		return false, fmt.Errorf("failed to read from world state: %v", err)
	}

	if assetJSON != nil {
		var data map[string]interface{}
		err2 := json.Unmarshal(assetJSON, &data)
		if err2 != nil {
			return false, fmt.Errorf("failed to read from world state: %v", err2)
		}
		if err3, ok := data["GroupName"]; ok {
			return assetJSON != nil, nil
		} else {
			return false, fmt.Errorf("failed to read from world state. Hash passed as parameter may correspond to a Schema struct or Data Struc rather than to a Group Struct: %v", err3)
		}
	} else {
		return assetJSON != nil, nil
	}
}

func (s *SmartContract) CreateGroup(ctx contractapi.TransactionContextInterface, GroupName string, Project string, Org string) error {
	//Create a function that checks that a group already exists. Maybe combining GroupName, Group Name and project, and turn that into a Hash? Use the Hash to determine if the group exists.
	GroupId := GroupName + "." + Project + "." + Org

	groupExists, err := s.GroupExists(ctx, GroupId)
	if err != nil {
		return fmt.Errorf("unable to check whether Group exists or not: %v", err)
	}

	if groupExists {
		return fmt.Errorf("the group with name %s already exists", GroupName)
	}

	group := Group{
		GroupName: GroupName,
		UUIDs:     []string{},
		Project:   Project,
		Org:       Org,
		GroupId:   GroupId,
	}

	assetJSON, err := json.Marshal(group)
	if err != nil {
		return err
	}

	err = ctx.GetStub().PutState(group.GroupId, assetJSON)
	if err != nil {
		return fmt.Errorf("failed to create new Group. %v", err)
	}

	fmt.Printf("The Group %v has been created ", group.GroupName)

	return nil
}

func (s *SmartContract) ReadGroup(ctx contractapi.TransactionContextInterface, GroupId string) (*Group, error) {
	exists, err := s.GroupExists(ctx, GroupId)
	if (err != nil) || (!exists) {
		return nil, fmt.Errorf("failed to read Group: % v", err)
	}
	assetJSON, err := ctx.GetStub().GetState(GroupId)
	if err != nil {
		return nil, fmt.Errorf("failed to read from world state: %v", err)
	}
	if assetJSON == nil {
		return nil, fmt.Errorf("the Group with Hash %s does not exist", GroupId)
	}

	var group Group
	err = json.Unmarshal(assetJSON, &group)
	if err != nil {
		return nil, err
	}

	return &group, nil
}

func (s *SmartContract) AddUserIDToGroup(ctx contractapi.TransactionContextInterface, UUID string, GroupId string) ([]string, error) {
	group, err := s.ReadGroup(ctx, GroupId)
	if err != nil {
		return nil, fmt.Errorf("read Group function failed excecution: %v", err)
	}

	contained := s.contains(ctx, group.UUIDs, UUID)
	if contained {
		return nil, fmt.Errorf("user %v already contained in Group %v", UUID, GroupId)
	}

	group.UUIDs = append(group.UUIDs, UUID)

	assetJSON, err := json.Marshal(group)
	if err != nil {
		return nil, fmt.Errorf("marshal of Group Struct not done: %v", err)
	}

	err = ctx.GetStub().PutState(GroupId, assetJSON)

	if err != nil {
		return nil, fmt.Errorf("unable to update asset: %v", err)
	}

	return group.UUIDs, nil
}
**/

func (s *SmartContract) LinearSearch(ctx contractapi.TransactionContextInterface, list []string, element string) int {
	for i, n := range list {
		if n == element {
			return i
		}
	}
	return -1
}

func (s *SmartContract) RemoveElement(ctx contractapi.TransactionContextInterface, list []string, element string) []string {
	index := s.LinearSearch(ctx, list, element)
	if index != -1 {
		return append(list[:index])
	} else {
		return list
	}
}

/**func (s *SmartContract) DelUserIDFromGroup(ctx contractapi.TransactionContextInterface, UUID string, Hash string) ([]string, error) {
	group, err := s.ReadGroup(ctx, Hash)
	if err != nil {
		return nil, fmt.Errorf("read Group function failed excecution: %v", err)
	}

	contained := s.contains(ctx, group.UUIDs, UUID)
	if !contained {
		return nil, fmt.Errorf("User %v already removed from Group or unexisting", UUID)
	}

	uuids := group.UUIDs
	uuids = s.RemoveElement(ctx, uuids, UUID)
	group.UUIDs = uuids

	assetJSON, err := json.Marshal(group)
	if err != nil {
		return nil, fmt.Errorf("marshal of Group Struct not done: %v", err)
	}

	err = ctx.GetStub().PutState(Hash, assetJSON)

	if err != nil {
		return nil, fmt.Errorf("unable to update asset: %v", err)
	}

	return group.UUIDs, nil
}

func (s *SmartContract) GetAPIUserByUUID(ctx contractapi.TransactionContextInterface, UUID string) ([]string, error) {
	user, err := s.ReadUser(ctx, UUID)
	if err != nil {
		return nil, fmt.Errorf("failed to read User %v from Wrold State", UUID)
	}
	return user.APIUserId, nil

}
**/

func submittingClientIdentity(ctx contractapi.TransactionContextInterface) (string, error) {
	b64ID, err := ctx.GetClientIdentity().GetID()
	if err != nil {
		return "", fmt.Errorf("Failed to read clientID: %v", err)
	}
	decodeID, err := base64.StdEncoding.DecodeString(b64ID)
	if err != nil {
		return "", fmt.Errorf("failed to base64 decode clientID: %v", err)
	}
	return string(decodeID), nil
}

func verifyClientOrgMatchesPeerOrg(ctx contractapi.TransactionContextInterface) error {
	clientMSPID, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return fmt.Errorf("failed getting the client's MSPID: %v", err)
	}
	peerMSPID, err := shim.GetMSPID()
	if err != nil {
		return fmt.Errorf("failed getting the peer's MSPID: %v", err)
	}

	if clientMSPID != peerMSPID {
		return fmt.Errorf("client from org %v is not authorized to read or write private data from an org %v peer", clientMSPID, peerMSPID)
	}

	return nil
}

// WriteSchemaToPDC submits a schema to an Org's priva data collection so validations of incoming data can be done.

func (s *SmartContract) WriteSchemaToPDC(ctx contractapi.TransactionContextInterface) error {

	transientAssetJSON, err := s.getTransientMap(ctx)
	if err != nil {
		return fmt.Errorf("error getting transient: %v", err)
	}

	type transientInput struct {
		JsonSchemaContent map[string]interface{} `json:"JsonSchemaContent"`
		SchemaId          string                 `json:"SchemaId"`
		Project           string                 `json:"Project`
	}

	// So far, we've taken what's on the transient dictionary and unmarshal it into the transientInput Struct
	var assetInput transientInput
	err = json.Unmarshal(transientAssetJSON, &assetInput)
	if err != nil {
		return fmt.Errorf("failed to unmarshal JSON: %v", err)
	}
	jsonFileContent := assetInput.JsonSchemaContent

	MSP, err := shim.GetMSPID()
	if err != nil {
		return fmt.Errorf("failed to get MSPID: %v", err)
	}
	PDC := "_implicit_org_" + MSP
	assetAsBytes, err := ctx.GetStub().GetPrivateData(PDC, assetInput.SchemaId)
	if err != nil {
		return fmt.Errorf("failed to get Schema: %v", err)
	} else if assetAsBytes != nil {
		fmt.Println("Schema already exists: " + assetInput.SchemaId)
		return fmt.Errorf("this Schema already exists: " + assetInput.SchemaId)
	}

	// Get ID of submitting client identity
	clientID, err := submittingClientIdentity(ctx)
	if err != nil {
		return err
	}

	// Verify that the client is submitting request to peer in their organization
	// This is to ensure that a client from another org doesn't attempt to read or
	// write private data from this peer.
	err = verifyClientOrgMatchesPeerOrg(ctx)
	if err != nil {
		return fmt.Errorf("CreateSchema cannot be performed: Error %v", err)
	}

	Schema := PrivateSchemaContent{
		JsonSchemaContent: jsonFileContent,
		SchemaId:          assetInput.SchemaId,
		Project:           assetInput.Project,
	}
	assetJSONasBytes, err := json.Marshal(Schema)
	if err != nil {
		return fmt.Errorf("failed to marshal Schema into JSON: %v", err)
	}

	// Save asset to private data collection
	// Typical logger, logs to stdout/file in the fabric managed docker container, running this chaincode
	// Look for container name like dev-peer0.org1.example.com-{chaincodename_version}-xyz
	log.Printf("WriteSchemaToPDC Put: collection %v, ID %v, owner %v", PDC, assetInput.SchemaId, clientID)

	err = ctx.GetStub().PutPrivateData(PDC, assetInput.SchemaId, assetJSONasBytes)
	if err != nil {
		return fmt.Errorf("failed to put asset into private data collection: %v", err)
	}

	return nil
}

// ReadAsset reads the information from collection
func (s *SmartContract) ReadSchemaFromPDC(ctx contractapi.TransactionContextInterface, SchemaID string) (*Schema, error) {
	MSP, err := shim.GetMSPID()
	if err != nil {
		return nil, fmt.Errorf("failed to get MSPID: %v", err)
	}

	err = verifyClientOrgMatchesPeerOrg(ctx)
	if err != nil {
		return nil, fmt.Errorf("CreateSchema cannot be performed: Error %v", err)
	}

	PDC := "_implicit_org_" + MSP
	log.Printf("ReadSchemaFromPDC: collection %v, ID %v", PDC, SchemaID)
	assetJSON, err := ctx.GetStub().GetPrivateData(PDC, SchemaID) //get the asset from chaincode state
	if err != nil {
		return nil, fmt.Errorf("failed to read Schema: %v", err)
	}

	//No Asset found, return empty response
	if assetJSON == nil {
		log.Printf("%v does not exist in collection %v", SchemaID, PDC)
		return nil, fmt.Errorf("%v does not exist in collection %v", SchemaID, PDC)
	}

	var schema *Schema
	err = json.Unmarshal(assetJSON, &schema)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %v", err)
	}

	return schema, nil

}

func (s *SmartContract) GetAllPDCSchemas(ctx contractapi.TransactionContextInterface) ([]*Schema, error) {

	MSP, err := shim.GetMSPID()
	if err != nil {
		return nil, fmt.Errorf("failed to get MSPID: %v", err)
	}

	err = verifyClientOrgMatchesPeerOrg(ctx)
	if err != nil {
		return nil, fmt.Errorf("Reading of Users cannot be performed: Error %v", err)
	}

	PDC := "_implicit_org_" + MSP
	log.Printf("GetAllPDCSchemas: collection %v ", PDC)

	resultsIterator, err := ctx.GetStub().GetPrivateDataByRange(PDC, "", "")

	if err != nil {
		return nil, err
	}
	defer resultsIterator.Close()

	if err != nil {
		return nil, fmt.Errorf("failed to read Schemas: %v", err)
	}

	var schemas []*Schema
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, err
		}

		var schema map[string]interface{}
		err = json.Unmarshal(queryResponse.Value, &schema)
		if err != nil {
			return nil, err
		} else if _, ok := schema["SchemaId"]; ok {
			var schemaStruct Schema
			err = json.Unmarshal(queryResponse.Value, &schemaStruct)
			if err != nil {
				return nil, err
			} else {
				schemas = append(schemas, &schemaStruct)
			}
		}

	}

	return schemas, nil
}

func (s *SmartContract) getTransientMap(ctx contractapi.TransactionContextInterface) ([]byte, error) {
	// Get new asset from transient map
	transientMap, err := ctx.GetStub().GetTransient()
	if err != nil {
		return nil, fmt.Errorf("error getting transient: %v", err)
	}
	// Project properties are private, therefore they get passed in transient field, instead of func args
	transientAssetJSON, ok := transientMap["asset_properties"]
	if !ok {
		//log error to stdout
		return nil, fmt.Errorf("asset not found in the transient map input")
	}
	return transientAssetJSON, nil
}

func (s *SmartContract) GiveProject(ctx contractapi.TransactionContextInterface, PID string) (*Project, error) {
	MSP, err := shim.GetMSPID()
	if err != nil {
		return nil, fmt.Errorf("failed to get MSPID: %v", err)
	}

	err = verifyClientOrgMatchesPeerOrg(ctx)
	if err != nil {
		return nil, fmt.Errorf("CreateSchema cannot be performed: Error %v", err)
	}

	PDC := "_implicit_org_" + MSP
	log.Printf("GiveProject: collection %v, ID %v", PDC, PID)
	assetJSON, err := ctx.GetStub().GetPrivateData(PDC, PID) //get the asset from chaincode state
	if err != nil {
		return nil, fmt.Errorf("failed to read Project: %v", err)
	}

	//No Project found, return empty response
	if assetJSON == nil {
		log.Printf("%v does not exist in collection %v", PID, PDC)
		return nil, fmt.Errorf("%v does not exist in collection %v", PID, PDC)
	}

	var project *Project
	err = json.Unmarshal(assetJSON, &project)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %v", err)
	}

	return project, nil

}

func (s *SmartContract) GiveGroup(ctx contractapi.TransactionContextInterface, GID string) (*Group, error) {
	MSP, err := shim.GetMSPID()
	if err != nil {
		return nil, fmt.Errorf("failed to get MSPID: %v", err)
	}

	err = verifyClientOrgMatchesPeerOrg(ctx)
	if err != nil {
		return nil, fmt.Errorf("CreateSchema cannot be performed: Error %v", err)
	}

	PDC := "_implicit_org_" + MSP
	log.Printf("GiveGroup: collection %v, ID %v", PDC, GID)
	assetJSON, err := ctx.GetStub().GetPrivateData(PDC, GID) //get the asset from chaincode state
	if err != nil {
		return nil, fmt.Errorf("failed to read Group: %v", err)
	}

	//No Project found, return empty response
	if assetJSON == nil {
		log.Printf("%v does not exist in collection %v", GID, PDC)
		return nil, fmt.Errorf("%v does not exist in collection %v", GID, PDC)
	}

	var group *Group
	err = json.Unmarshal(assetJSON, &group)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %v", err)
	}

	return group, nil

}

func (s *SmartContract) GetAllPDCUsers(ctx contractapi.TransactionContextInterface) ([]*User, error) {

	MSP, err := shim.GetMSPID()
	if err != nil {
		return nil, fmt.Errorf("failed to get MSPID: %v", err)
	}

	err = verifyClientOrgMatchesPeerOrg(ctx)
	if err != nil {
		return nil, fmt.Errorf("Reading of Users cannot be performed: Error %v", err)
	}

	PDC := "_implicit_org_" + MSP

	log.Printf("GetAllUsers: collection %v ", PDC)

	resultsIterator, err := ctx.GetStub().GetPrivateDataByRange(PDC, "", "") //get all the Users from PDC State

	if err != nil {
		return nil, err
	}
	defer resultsIterator.Close()

	if err != nil {
		return nil, fmt.Errorf("failed to read Users: %v", err)
	}

	var users []*User

	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, err
		}

		var user map[string]interface{}
		err = json.Unmarshal(queryResponse.Value, &user)
		if err != nil {
			return nil, err
		} else if _, ok := user["UUID"]; ok {
			var userStruct User
			err = json.Unmarshal(queryResponse.Value, &userStruct)
			if err != nil {
				return nil, err
			} else {
				users = append(users, &userStruct)
			}
		}
	}

	return users, nil

}

func (s *SmartContract) VerifyUserIsAdmin(ctx contractapi.TransactionContextInterface, GID string) (bool, error) {
	MSP, err := shim.GetMSPID()
	if err != nil {
		return false, fmt.Errorf("failed to get MSPID: %v", err)
	}

	clientID, err := submittingClientIdentity(ctx)
	if err != nil {
		return false, err
	}

	err = verifyClientOrgMatchesPeerOrg(ctx)
	if err != nil {
		return false, fmt.Errorf("Reading of Users cannot be performed: Error %v", err)
	}

	PDC := "_implicit_org_" + MSP

	// Get Group Struct frpom PDC

	GroupBytes, err := ctx.GetStub().GetPrivateData(PDC, GID) //get the asset from chaincode state
	if err != nil {
		return false, fmt.Errorf("failed to read Group: %v", err)
	}

	var Group_ Group

	err = json.Unmarshal(GroupBytes, &Group_)
	if err != nil {
		return false, fmt.Errorf("failed to unmarshal JSON: %v", err)
	}

	users := Group_.Users

	for _, user := range users {
		APIUserId := user.APIUserId
		if APIUserId == clientID {
			return true, nil
		}
	}
	return false, nil
}

// Pass GID and APIUserID as argument in transient dictionary
func (s *SmartContract) AddUserToGroup(ctx contractapi.TransactionContextInterface) error {

	transientAssetJSON, err := s.getTransientMap(ctx)
	if err != nil {
		return fmt.Errorf("error getting transient: %v", err)
	}

	type transientInput struct {
		GID       string `json:"GID"`
		APIUserID string `json:"APIUserID"`
	}

	var assetInput transientInput
	err = json.Unmarshal(transientAssetJSON, &assetInput)
	if err != nil {
		return fmt.Errorf("failed to unmarshal JSON: %v", err)
	}

	GID := assetInput.GID
	MSP, err := shim.GetMSPID()
	if err != nil {
		return fmt.Errorf("failed to get MSPID: %v", err)
	}

	err = verifyClientOrgMatchesPeerOrg(ctx)
	if err != nil {
		return fmt.Errorf("Verification of Identity cannot be performed: Error %v", err)
	}

	GroupSplit := strings.Split(GID, ".")
	GIDAdmin := GroupSplit[0] + "." + GroupSplit[1] + ".Admin"
	isAdmin, err := s.VerifyUserIsAdmin(ctx, GIDAdmin)

	if err != nil {
		return fmt.Errorf("Verification of Identity cannot be performed. Can't verify if submitting user is admin or not: Error %v", err)
	}

	if !isAdmin {
		return fmt.Errorf("Submitting Identity is not admin. Can't add user to Group: Error %v", err)
	}

	User_, err := s.GetUser(ctx, assetInput.APIUserID)

	if err != nil {
		return fmt.Errorf("Verification of Existence of user %v cannot be performed: Error %v", assetInput.APIUserID, err)
	}

	if User_ == nil {
		return fmt.Errorf("User doesn't exist yet. Please use function NewUser() to create a new User: Error %v", err)
	}

	userInGroup := s.contains(ctx, User_.Groups, assetInput.GID)

	if userInGroup {
		return fmt.Errorf("User already belongs to group", err)
	}

	PDC := "_implicit_org_" + MSP

	assetAsBytes, err := ctx.GetStub().GetPrivateData(PDC, GID)

	if err != nil {
		return fmt.Errorf("failed to get Group from PDC: %v", err)
	}

	var Group Group

	err = json.Unmarshal(assetAsBytes, &Group)
	if err != nil {
		return fmt.Errorf("failed to unmarshal JSON: %v", err)
	}

	NewUser := User{
		UUID:      User_.UUID,
		APIUserId: User_.APIUserId,
		Groups:    User_.Groups,
		Projects:  User_.Projects,
		Org:       MSP,
	}
	Group.Users = append(Group.Users, NewUser)

	assetJSONasBytes, err := json.Marshal(Group)
	if err != nil {
		return fmt.Errorf("failed to marshal Group into JSON: %v", err)
	}

	err = ctx.GetStub().PutPrivateData(PDC, GID, assetJSONasBytes)
	if err != nil {
		return fmt.Errorf("failed to put Group into private data collection: %v", err)
	}

	//Update User

	User_.Groups = append(User_.Groups, assetInput.GID)

	assetJSONasBytes, err = json.Marshal(User_)
	if err != nil {
		return fmt.Errorf("failed to marshal User into JSON: %v", err)
	}

	userID := MSP + "." + assetInput.APIUserID

	h := sha1.New()
	h.Write([]byte(userID))
	hash := hex.EncodeToString(h.Sum(nil))

	err = ctx.GetStub().PutPrivateData(PDC, hash, assetJSONasBytes)
	if err != nil {
		return fmt.Errorf("failed to put User into private data collection: %v", err)
	}

	return nil
}

// Pass GID and APIUserID as argument in transient dictionary
func (s *SmartContract) RemoveUserFromGroup(ctx contractapi.TransactionContextInterface) error {

	transientAssetJSON, err := s.getTransientMap(ctx)
	if err != nil {
		return fmt.Errorf("error getting transient: %v", err)
	}

	type transientInput struct {
		GID       string `json:"GID"`
		APIUserID string `json:"APIUserID"`
	}

	var assetInput transientInput
	err = json.Unmarshal(transientAssetJSON, &assetInput)
	if err != nil {
		return fmt.Errorf("failed to unmarshal JSON: %v", err)
	}

	GID := assetInput.GID
	MSP, err := shim.GetMSPID()
	if err != nil {
		return fmt.Errorf("failed to get MSPID: %v", err)
	}

	err = verifyClientOrgMatchesPeerOrg(ctx)
	if err != nil {
		return fmt.Errorf("Verification of Identity cannot be performed: Error %v", err)
	}

	GroupSplit := strings.Split(GID, ".")
	GIDAdmin := GroupSplit[0] + "." + GroupSplit[1] + ".Admin"
	isAdmin, err := s.VerifyUserIsAdmin(ctx, GIDAdmin)

	if err != nil {
		return fmt.Errorf("Verification of Identity cannot be performed: Error %v", err)
	}

	if !isAdmin {
		return fmt.Errorf("Submitting Identity is not admin. Can't remove user from Group: Error %v", err)
	}

	User, err := s.GetUser(ctx, assetInput.APIUserID)

	if err != nil {
		return fmt.Errorf("Verification of Existence of user cannot be performed: Error %v", err)
	}

	if User == nil {
		return fmt.Errorf("User doesn't exist. %v", err)
	}

	userInGroup := s.contains(ctx, User.Groups, GID)

	if err != nil {
		return fmt.Errorf("Verification of Existence of user in Group cannot be performed: Error %v", err)
	}

	if userInGroup == false {
		fmt.Printf("User already removed from group or Group GID is not correct", err)
	}

	PDC := "_implicit_org_" + MSP

	assetAsBytes, err := ctx.GetStub().GetPrivateData(PDC, GID)

	if err != nil {
		return fmt.Errorf("failed to get Group from PDC: %v", err)
	}

	var Group Group

	err = json.Unmarshal(assetAsBytes, &Group)
	if err != nil {
		return fmt.Errorf("failed to unmarshal JSON: %v", err)
	}

	index := -1

	for i, n := range Group.Users {
		if n.APIUserId == assetInput.APIUserID {
			index = i
			break
		}
	}
	if index != -1 {
		Group.Users = append(Group.Users[:index])
	} else {
		fmt.Printf("User already removed from group", err)
	}

	assetJSONasBytes, err := json.Marshal(Group)
	if err != nil {
		return fmt.Errorf("failed to marshal Group into JSON: %v", err)
	}

	err = ctx.GetStub().PutPrivateData(PDC, GID, assetJSONasBytes)
	if err != nil {
		return fmt.Errorf("failed to put Group into private data collection: %v", err)
	}

	//Update User

	index = -1
	for i, g := range User.Groups {
		if g == assetInput.GID {
			index = i
			break
		}
	}
	if index != -1 {
		User.Groups = append(User.Groups[:index])
	}

	assetJSONasBytes, err = json.Marshal(User)
	if err != nil {
		return fmt.Errorf("failed to marshal User into JSON: %v", err)
	}

	userID := MSP + "." + assetInput.APIUserID

	h := sha1.New()
	h.Write([]byte(userID))
	hash := hex.EncodeToString(h.Sum(nil))

	err = ctx.GetStub().PutPrivateData(PDC, hash, assetJSONasBytes)
	if err != nil {
		return fmt.Errorf("failed to put User into private data collection: %v", err)
	}

	return nil
}
