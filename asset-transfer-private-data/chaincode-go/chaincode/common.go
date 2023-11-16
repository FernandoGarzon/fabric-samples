package chaincode

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"crypto/sha256"

	"github.com/hyperledger/fabric-chaincode-go/pkg/cid"
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"

	"log" // this might not be the right thing to use, does it kill the chaincode?
)

// SmartContract is the API we use to introduce chaincode functions.
// This is the receiver for all functions that can be called from HLF.
// Don't put functions in here that shouldn't be called by HLF clients.

// Hash() function calculates the sha256.Sum256 of a string. doc argument is the content of the Json file that users use to submit data into the ledger. This content is treated as a simple string.
func Hash(ctx contractapi.TransactionContextInterface, doc string) (string, error) {
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

func stringArrayContains(st []string, str string) bool {
	for _, v := range st {
		if v == str {
			return true
		}
	}
	return false
}

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
	result, err := SubmittingIdentityHasOU(ctx, "")
	if err != nil {
		return err
	}
	if !result {
		return fmt.Errorf("Function submittingIdentityHasOU() returned false with no reason.")
	}

	return nil
}

// Check that the submitting identity (HLF client) has a specific OU.
// Also check that the MSP of the submitting identity and this peer's MSP are the same.
// If the requiredOU is the empy string, just perform the MSP check.
// Note that requiredOU SHALL NOT include "OU=".
func SubmittingIdentityHasOU(ctx contractapi.TransactionContextInterface, requiredOU string) (bool, error) {
	// Check the MSPs match
	clientMSPID, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return false, fmt.Errorf("Failed getting the submitting client's MSPID: %v.", err)
	}
	peerMSPID, err := shim.GetMSPID()
	if err != nil {
		return false, fmt.Errorf("Failed getting the peer's (our) MSPID: %v.", err)
	}

	if clientMSPID != peerMSPID {
		return false, fmt.Errorf("Client from org %v is not authorized to read or write private data from this org (%v).", clientMSPID, peerMSPID)
	}

	// Maybe the caller just wanted to check that the MSPs match.
	if requiredOU == "" {
		return true, nil
	}

	// Let's try using cid for OU assertions
	stub := ctx.GetStub()
	// OU=admin satisfies all
	found, err := cid.HasOUValue(stub, "admin")
	if err != nil {
		return false, err
	}
	if found {
		return true, nil
	}
	// Actually check for the OU
	found, err = cid.HasOUValue(stub, requiredOU)
	if err != nil {
		return false, err
	}
	if found {
		return true, nil
	}

	clientID, err := submittingClientIdentity(ctx)
	return false, fmt.Errorf("Submitting client does not have OU=%v, got '%v'", requiredOU, clientID)
}

func VerifyUserHasPrivilege(ctx contractapi.TransactionContextInterface) (bool, error) {
	return SubmittingIdentityHasOU(ctx, "admin")
}

// JsonReader() unmarshals a string passed as parameter into a map or interface. It is used to read and manipulate content of files.
func JsonReader(content string) (map[string]interface{}, error) {
	var payload map[string]interface{}
	// Now let's unmarshall the data into `payload`
	err := json.Unmarshal([]byte(content), &payload)
	if err != nil {
		log.Fatal("Error during Unmarshal() of string into type Interface: ", err)
	}
	return payload, nil
}

func GetTransientMap(ctx contractapi.TransactionContextInterface) ([]byte, error) {
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

// Some operations take a {group, user, schema} name and will need to convert to a UUID or
// do some other lookup.
// This is the first step in that process, which will return a key in the specified namespace
// for the given name.
//
// We use a single function to do this so that it's easy to change the format of the key later.
func ObjectNameToKey(objectType string, msp string, objectName string) (string, error) {
	// Note: we case-squash since most input (e.g. email address) will be case-agnostic.
	mspLower := strings.ToLower(msp)
	objectNameLower := strings.ToLower(objectName)

	// We only allow certain types of objects.
	if objectType != "user" && objectType != "group" && objectType != "schema" &&
		objectType != "useruuid" && objectType != "groupuuid" {
		return "", fmt.Errorf("Object Type is not 'user', 'group', 'schema', 'useruuid', or 'groupuuid'")
	}

	// Check input for weird characters
	matched, err := regexp.MatchString("[^-.a-z0-9]", mspLower)
	if matched || err != nil {
		return "", fmt.Errorf("'MSP' contains characters besides [-.a-z0-9]")
	}

	matched, err = regexp.MatchString("[^-.a-z0-9]", objectNameLower)
	if matched || err != nil {
		return "", fmt.Errorf("'%d name' contains characters besides [-.a-z0-9]", objectType)
	}

	// apiuser to key
	if objectType == "user" {
		return "iam.user_to_uuid." + mspLower + "." + objectNameLower, nil
	}

	// group to key
	if objectType == "group" {
		return "iam.group_to_uuid." + mspLower + "." + objectNameLower, nil
	}

	// apiuseruuid to key
	if objectType == "useruuid" {
		return "iam.uuid_to_user." + mspLower + "." + objectNameLower, nil
	}

	// groupuuid to key
	if objectType == "groupuuid" {
		return "iam.uuid_to_group." + mspLower + "." + objectNameLower, nil
	}

	// schema to key
	// Note: caller must set objectName to <group UUID>$<schema name>
	if objectType == "schema" {
		return "schema." + mspLower + "." + objectNameLower, nil
	}

	return "", fmt.Errorf("Unknown object type: %d", objectType)
}

// Wrapper around ObjectNameToKey for apiUserId
func apiUserToKey(msp string, apiuser string) (string, error) {
	return ObjectNameToKey("user", msp, apiuser)
}

// Wrapper around ObjectNameToKey for useruuid
func userUuidToKey(msp string, uuid string) (string, error) {
	return ObjectNameToKey("useruuid", msp, uuid)
}

// Wrapper around ObjectNameToKey for group
func groupNameToKey(msp string, groupName string) (string, error) {
	return ObjectNameToKey("group", msp, groupName)
}

// Wrapper around ObjectNameToKey for groupuuid
func groupUuidToKey(msp string, uuid string) (string, error) {
	return ObjectNameToKey("groupuuid", msp, uuid)
}

// Wrapper around ObjectNameToKey for schema
// Remember, we key the schema using the group's UUID so the artifacts follow
// the group if the group is ever renamed.
// Actually, let's handle this in schema.go since it's getting complex.
