package chaincode

// schema.go - JSON schema related functions
// Since we allow customizable fields, the artifact's JSON document needs
// to be validated without hard-coding the fields in chaincode.
// JSON schemas are the way to do that.

import (
	"encoding/json"
	"fmt"

	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
	"github.com/xeipuuv/gojsonschema"
)

// Type Schema describes the data struct used to validate the content of Json Files when a user tries to submit new data to the ledger.
// Note that the schema must contain certain fields, and other data is
// encoded in its key.
type Schema struct {
	SchemaText      string
	SubmittedByUuid string
	Version         int
}

// When a client deals with a schema, we'll resolve the submitter's UUID to an APIUserId to keep UUIDs opaque.
// Make a separate struct to avoid confusion.
type SchemaExternal struct {
	SchemaText  string
	SubmittedBy string
	Version     int
}

// A bit about schemas:
// We do want to make sure the schema's history is tracked, and
// an artifact can be independently verified against the correct schema.
//
// The PDC currently does not have an implementation to get history
// so we probably shouldn't use that. On the bright side, a schema
// isn't a secret, so it can be stored on the public ledger.
//
// An artifact submission will always be validated against the current
// schema at the specified name, so we only need to record something, like
// the hash of the current schema in the artifact.

// Naming a schema:
//
// A schema needs a key, and it needs a namespace to avoid collisions with
// other objects.
// Following iam, we use the following construct for keys:
// schema.<msp>.<group uuid>.<schema name>
// All keys are case-squashed.

// Produce a suitable key for a given schema name.
// Note that we use the group uuid in the key instead of group name.
// This is so the schema and artifacts will follow the group if it is ever renamed.
func SchemaNameToKey(ctx contractapi.TransactionContextInterface, groupName string, schemaName string) (string, error) {
	// We need the MSP, but can derive it here to save on calling complexity.
	MSP, err := shim.GetMSPID()
	if err != nil {
		return "", fmt.Errorf("Failed to get MSPID: %v.", err)
	}

	// Resolve the group to a uuid
	groupUuid, err := GroupNameToUUID(ctx, MSP, groupName)
	if err != nil {
		return "", err
	}

	return ObjectNameToKey("schema", MSP, groupUuid+"."+schemaName)
}

// Retrieve the current version of a schema struct.
func GetSchema(ctx contractapi.TransactionContextInterface, groupName string, schemaName string) (Schema, error) {
	var schemaRecord Schema

	// Permissons check!
	// Turns out this is public, so everyone can view.

	// We'll need to refer to this schema with a key. Derive that.
	schemaKey, err := SchemaNameToKey(ctx, groupName, schemaName)
	if err != nil {
		return schemaRecord, err
	}

	schemaBytesFromState, err := ctx.GetStub().GetState(schemaKey)
	if err != nil {
		return schemaRecord, err
	}

	err = json.Unmarshal(schemaBytesFromState, &schemaRecord)

	if err != nil {
		return schemaRecord, err
	}

	return schemaRecord, nil
}

// Get historical values for a given schema, not just the latest.
func (s *SmartContract) GetSchemaHistory(ctx contractapi.TransactionContextInterface, groupName string, schemaName string) ([]SchemaExternal, error) {
	var schemaExternalRecords []SchemaExternal
	var schemaExternalRecord SchemaExternal
	var schemaRecord Schema

	// We don't want to expose submitter unless it's a read-write identity.
	hasOU, _ := SubmittingIdentityHasOU(ctx, "Read-Write")

	// We'll need to refer to this schema with a key. Derive that.
	schemaKey, err := SchemaNameToKey(ctx, groupName, schemaName)
	if err != nil {
		return schemaExternalRecords, err
	}

	// Get the history for the key
	schemaHistory, err := ctx.GetStub().GetHistoryForKey(schemaKey)
	if err != nil {
		return schemaExternalRecords, err
	}

	// Unmarshal each version and add it to the output
	for schemaHistory.HasNext() {
		rec, err := schemaHistory.Next()
		if err != nil {
			return nil, err
		}

		err = json.Unmarshal(rec.Value, &schemaRecord)
		if err != nil {
			return nil, fmt.Errorf("Unable to unmarshal historical schema record: %v", err)
		}

		// Use a slightly different struct to avoid exposing internal fields.
		schemaExternalRecord = SchemaExternal{}

		// Mask out submitter if read-only client
		if hasOU {
			submittedBy, _ := UUIDToAPIUserId(ctx, schemaRecord.SubmittedByUuid)
			schemaExternalRecord.SubmittedBy = submittedBy
		}
		schemaExternalRecord.SchemaText = schemaRecord.SchemaText
		schemaExternalRecord.Version = schemaRecord.Version
		schemaExternalRecords = append(schemaExternalRecords, schemaExternalRecord)
	}

	return schemaExternalRecords, nil
}

// Create a new schema.
func (s *SmartContract) NewSchema(ctx contractapi.TransactionContextInterface, groupName string, schemaName string, schemaText string) error {
	return StoreSchema(ctx, true, groupName, schemaName, schemaText)
}

// Update an existing schema.
// This is almost the same as creating a new one.
func (s *SmartContract) UpdateSchema(ctx contractapi.TransactionContextInterface, groupName string, schemaName string, schemaText string) error {
	return StoreSchema(ctx, false, groupName, schemaName, schemaText)
}

// Store (new, update) a schema.
// We accept everything but the APIUserID as normal arguments since aside from that,
// there are no secrets here.
// Since new and update are almost the same operations except checking preconditions, we
// do that in a single function to keep repeated code to a minimum.
func StoreSchema(ctx contractapi.TransactionContextInterface, createNew bool, groupName string, schemaName string, schemaText string) error {

	// Stores the current version schema, if needed.
	var schemaCurrent Schema

	// Permissons check!
	hasOU, errOU := SubmittingIdentityHasOU(ctx, "Read-Write")
	if !hasOU {
		return errOU
	}

	res, err := IsAPIUserIdAnAdminOfGroup(ctx, groupName)
	if err != nil {
		return err
	}
	if !res {
		return fmt.Errorf("APIUserId is not a member of group %s.ADMINS", groupName)
	}

	// We'll need to refer to this schema with a key. Derive that.
	schemaKey, err := SchemaNameToKey(ctx, groupName, schemaName)
	if err != nil {
		return fmt.Errorf("Failed to create a lookup key for schema: %v", err)
	}

	// Depending on whether we're creating a new schema or updating it, there's a check to be made.
	schemaBytesFromState, err := ctx.GetStub().GetState(schemaKey)
	if err != nil {
		return fmt.Errorf("Failed to look up key: %s, %v", schemaKey, err)
	}

	if createNew && schemaBytesFromState != nil {
		return fmt.Errorf("Schema %s for group %s already exists.", schemaName, groupName)
	}

	if !createNew && schemaBytesFromState == nil {
		return fmt.Errorf("Schema %s for group %s does not already exist.", schemaName, groupName)
	}

	// An update has a few more checks...
	if !createNew {
		err = json.Unmarshal(schemaBytesFromState, &schemaCurrent)
		if err != nil {
			return fmt.Errorf("Failed to unmarshal current schema from ledger: %v", err)
		}

		// New and old schema text must be different.
		if schemaCurrent.SchemaText == schemaText {
			return fmt.Errorf("Schema and current schema are the same, nothing to update.")
		}
	}

	// Schema must validate against meta-schema
	metaSchema := gojsonschema.NewStringLoader(metaschemaText)
	thisSchema := gojsonschema.NewStringLoader(schemaText)
	result, err := gojsonschema.Validate(metaSchema, thisSchema)
	if err != nil {
		return err
	}
	if !result.Valid() {
		errmsg := ""
		for _, desc := range result.Errors() {
			errmsg = errmsg + "- " + desc.String() + "\n"
		}
		return fmt.Errorf("Schema is not valid: %v", errmsg)
	}

	// We want to know who submitted this schema, so resolve that.
	APIUserUuid, err := getAPIUserUuidFromTransient(ctx)
	if err != nil {
		return err
	}

	// Good to insert?
	var schemaRecord Schema
	schemaRecord.SchemaText = schemaText
	schemaRecord.SubmittedByUuid = APIUserUuid
	schemaRecord.Version = 1

	if !createNew {
		// The current schema was populated during the check to see if an update is actually needed.
		// We need to increment the version number if updating, so artifacts can be re-validated independently after the schema is updated.
		schemaRecord.Version = schemaCurrent.Version + 1
	}

	schemaRecordBytes, err := json.Marshal(schemaRecord)
	if err != nil {
		return fmt.Errorf("Failed to convert schema to JSON: %v", err)
	}
	return ctx.GetStub().PutState(schemaKey, schemaRecordBytes)
}

// Validates the json content of a new Data struct being submitted to the public Ledger.
// jsonText: JSON document (string, not struct) to validate.
// groupName: Name of the group to retrieve the schema from.
// schemaName: Name of the schema to retrieve.
func ValidJson(ctx contractapi.TransactionContextInterface, groupName string, schemaName string, jsonDocument map[string]interface{}) (bool, int, error) {

	// Retrieve the current schema
	schemaRecord, err := GetSchema(ctx, groupName, schemaName)
	if err != nil {
		return false, -1, err
	}

	schemaLoader := gojsonschema.NewStringLoader(schemaRecord.SchemaText)
	documentLoader := gojsonschema.NewGoLoader(jsonDocument)

	result, err := gojsonschema.Validate(schemaLoader, documentLoader)
	if err != nil {
		return false, -1, err
	}

	if result.Valid() {
		return true, schemaRecord.Version, nil
	}

	errmsg := ""
	for _, desc := range result.Errors() {
		errmsg = errmsg + "- " + desc.String() + "\n"
	}
	return false, -1, fmt.Errorf("Schema is not valid: %v", errmsg)
}

/*

// Not needed yet, but we'll need it eventually
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


*/
