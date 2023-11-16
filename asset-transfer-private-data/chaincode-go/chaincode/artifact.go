package chaincode

// artifact.go - Functions related to artifacts.

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// Type Artifact, describes basic details of what makes up an Artifact. This is persisted permanently in the ledger.
// Some attributes will be stored in a composite key, but only for facilitating lookups.
//   - OrgName, GroupUUID, SchemaName
//
// The composite key cannot be the only source of these data, as the reverse-lookup (find key given ArtifactId)
// is expensive when the number of Artifacts is large.
type SmartContract struct {
	contractapi.Contract
}

type Artifact struct {
	Title                   string                 // Title of the artifact.
	Description             string                 // More details about the artifact.
	SubmissionComment       string                 // A comment about this submission.
	ContributorUUID         string                 // UUID of the owner (not the APIUserID)
	EditorUUID              string                 // UUID of the last editor (not the APIUserId)
	GroupUUID               string                 // UUID of the group that this Artifact belongs to. (not the GroupName)
	SchemaName              string                 // The name of the schema used to validate this Artifact.
	SchemaVersion           string                 // The version of the schema used to validate this submission.
	OrgName                 string                 // The organization (MSP) this Artifact belongs to.
	PrivateCustomFieldsHash string                 // Hash of private data if any (stored with same composite key)
	PublicCustomFields      map[string]interface{} // Public custom fields, copied from submission.
}

// A chaincode function can only return two values.
// We need one for err, so this is a composite value in the form of a struct.
type ArtifactListPage struct {
	ArtifactList []*ArtifactListItem
	NextBookmark string
}

// An Artifact output in a list needs its extra details.
type ArtifactListItem struct {
	Artifact
	ArtifactId          string
	ContributorName     string
	EditorName          string
	GroupName           string
	PrivateCustomFields map[string]interface{}
}

/*****************************************************
 * Content Digest - How to find duplicate Artifacts. *
 *****************************************************/
// We want to avoid having duplicate content, generally speaking,
// however duplicates in other groups, or even other schemas is
// okay, as the data in the Artifact's fields means something
// completely different in the context of any given schema.
//
// In order to faclitate checking for duplicates, we need to define
// what constitutes a duplicate, and find a way to check without
// having to compare each existing Artifact to the candidate.
// The check needs to run quickly, as there may be hundreds of
// thousands of Artifacts.
//
// Obviously retrieving every Artifact is out, so we have two
// clear choices: 1) store a digest in the Artifact, use
// a rich query to find it. 2) store a digest in a composite key or
// composite key + value.
//
// (1) can be slow if there are a lot of Artifacts, and requires
// a CouchDB state database.
//
// (2) can be fast, depending on how we implement it. Note that
// we want to keep the range of returned results small (preferably 0 or 1)
// so that verification at commit time doesn't fail if there are a lot of
// submissions.
//
// In any case, we need a hash...

// Generate a digest of an Artifact, suitable for duplicate detection.
func ArtifactHash(artifact Artifact) (string, error) {
	hasher := sha256.New()

	// We'll keep updating the hash state with various parts of the
	// Artifact.

	// Mandatory public fields:
	hasher.Write([]byte("_Title:"))
	hasher.Write([]byte(artifact.Title))
	hasher.Write([]byte("_Description:"))
	hasher.Write([]byte(artifact.Description))
	hasher.Write([]byte("_SubmissionComment:"))
	hasher.Write([]byte(artifact.SubmissionComment))
	hasher.Write([]byte("_PrivateCustomFieldsHash:"))
	hasher.Write([]byte(artifact.PrivateCustomFieldsHash))
	// We skip the schema version because the schema might be updated.
	// We also skip ownership attributes as the owner isn't relevant to the meaning of the data.

	// Public custom fields are an object sub-tree, so we should
	// json-ify that, as they're not directly serializable.
	hasher.Write([]byte("_PublicCustomFields:"))
	o, err := json.Marshal(artifact.PublicCustomFields)
	if err != nil {
		return "", err
	}
	hasher.Write(o)

	// And the end, so nobody can add junk to make a collision.
	hasher.Write([]byte("_END_"))
	sum := hasher.Sum(nil)
	return fmt.Sprintf("%x", sum), nil
}

// Generate a digest of the private fields, producing the same output as
// GetPrivateDataHash(), just hex-ified.
// We use this since GetPrivateDataHash() can't return a hash of private data that
// hasn't been committed yet.
func ArtifactPrivateHash(private_fields map[string]interface{}) (string, error) {
	hasher := sha256.New()
	o, err := json.Marshal(private_fields)
	if err != nil {
		return "", err
	}
	hasher.Write(o)
	sum := hasher.Sum(nil)
	return fmt.Sprintf("%x", sum), nil
}

/*****************************************************
 * Keys - Artifacts are stored using composite keys. *
 *****************************************************/
// We'll likely need to retrieve keys by several criteria,
// possibly frequently enough that a rich query is undesirable.
// The composite key feature of HLF makes it possible to
// encode values in the key in specific positions,
// making searching for all keys with a certain property
// a simple range query.
//
// We use the following properties:
//  OrgName, GroupUUID, SchemaName
// NOTE: SchemaVersion was omitted and stored in Artifact -- it adds too much granularity
// forcing the creation of a new Artifact when the schema version is bumped and an artifact
// receives an update.
//
// We still need a handle to uniquely identify the Artifact in the HLF channel, so
// we'll use a version 4 UUID provided by the client. We considered using a counter, but
// found that it limits the number of submissions to one per block. A chaincode-generated
// UUID is also not practical as it is non-deterministic and needs to be deterministic.
//
// As a composite key query is inherently a range query, it can be slow and cause
// unnecessary processing when we know the Artifact's exact id. We'll store TWO things
// in the ledger: one composite key with a filler value to speed up finding Artifacts, and
// an entry with the actual id as a key and Artifact as value.
//
// Thus, we end up with the following:
// An Artifact has a unique id: osc-is-artifact-<v4 uuid> (osc-is-artifact-id)
// We store it at:
//   osc-is-artifact-id = Artifact
// And create a composite key:
//   osc-is-artifact-map, {OrgName, GroupUUID, SchemaName, osc-is-artifact-id, sha256-hash} = []byte{'1'}
//   NOTE: Don't use nil, as that DELETES the key.

// Returns a composite key for an Artifact
// Assumes caller has confirmed that client and peer MSP match!
func artifactToMapKey(ctx contractapi.TransactionContextInterface, orgName string, groupName string, schemaName string, artifactId string, hash string) string {
	stub := ctx.GetStub()
	// convert groupName to UUID
	MSP, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return ""
	}
	groupUuid, err := GroupNameToUUID(ctx, MSP, groupName)
	if err != nil || groupUuid == "" {
		return ""
	}

	key, _ := stub.CreateCompositeKey("osc-is-artifact-map", []string{orgName, groupUuid, schemaName, artifactId, strings.ToLower(hash)})
	return key
}

// Create a composite key to keep track of unique artifacts
func (s *SmartContract) ArtifactHashToMapKey(ctx contractapi.TransactionContextInterface, orgName, groupName, schemaName, hash string) string {
	stub := ctx.GetStub()
	// convert groupName to UUID
	MSP, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return ""
	}
	groupUuid, err := GroupNameToUUID(ctx, MSP, groupName)
	if err != nil || groupUuid == "" {
		return ""
	}

	key, _ := stub.CreateCompositeKey("osc-is-artifact-hash-map", []string{orgName, groupUuid, schemaName, strings.ToLower(hash)})
	return key
}

// Undoes artifactToKey, setting the fields
// Also assume caller has confirmed that client and peer MSP match!
func mapkeyToArtifact(ctx contractapi.TransactionContextInterface, key string, orgName *string, groupName *string, schemaName *string, artifactId *string) error {
	stub := ctx.GetStub()
	objType, subkeys, err := stub.SplitCompositeKey(key)
	if objType != "osc-is-artifact-map" {
		return fmt.Errorf("Key is not of type 'osc-is-artifact-map'")
	}

	if err == nil {
		// convert uuid to groupName
		MSP, err := ctx.GetClientIdentity().GetMSPID()
		gn, err := UUIDToGroupName(ctx, MSP, subkeys[1])
		if err != nil {
			return err
		}

		*orgName = subkeys[0]
		*groupName = gn
		*schemaName = subkeys[2]
		*artifactId = subkeys[3]
	}

	return err
}

// Resolve and clean up UUIDs for external use.
// First, this is only possible for Artifacts owned by the same org as this peer, as the
// mapping is in a PDC.
// Second, that's okay, because the general public doesn't have to know the actual identities.
// Third, we only want to map when it's relevant, to the client, and that's when they signal with using a read-write identity.
func cleanArtifactListItemForExternal(ctx contractapi.TransactionContextInterface, o *ArtifactListItem) error {
	orgName, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return err
	}
	o.ContributorName = ""
	o.EditorName = ""
	o.GroupName = ""

	// The rest of this is meaningless (and will fail) if the Artifact isn't in this peer's org.
	if o.OrgName != orgName {
		return nil
	}

	// The client hasn't used its read-write identity, so it might be operating in a guest context.
	// Guests don't need to know these details.
	hasOU, err := SubmittingIdentityHasOU(ctx, "Read-Write")
	if !hasOU {
		// We're done, nothing more to do.
		return nil
	}

	// group name
	o.GroupName, err = UUIDToGroupName(ctx, orgName, o.GroupUUID)
	if err != nil {
		return err
	}

	// contributor
	o.ContributorName, err = UUIDToAPIUserId(ctx, o.ContributorUUID)
	if err != nil {
		return err
	}

	// editor
	o.EditorName = ""
	if o.EditorUUID != "" {
		o.EditorName, err = UUIDToAPIUserId(ctx, o.EditorUUID)
		if err != nil {
			return err
		}
	}

	return nil
}

// Populate the private data element of the ArtifactListItem, but only if
// the prerequisites are met.
func populatePrivateData(ctx contractapi.TransactionContextInterface, o *ArtifactListItem) error {
	// We require the more trusted read-write identity because it's allowed to act on behalf of
	// an apiuser.
	hasOU, err := SubmittingIdentityHasOU(ctx, "Read-Write")
	if !hasOU {
		// We're done, nothing more to do.
		return nil
	}

	// At this point, the submitting HLF identity has RW privs and is in the same org as this peer.
	// We need to make sure this peer is also in the org owning the Artifact...
	orgName, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return err
	}
	if o.OrgName != orgName {
		return nil
	}

	// ... finally, only group members or group admins can create/update Artifacts
	artifactGroupName, err := UUIDToGroupName(ctx, orgName, o.GroupUUID)
	if err != nil {
		return err
	}
	isMember, _ := IsAPIUserIdMemberOfGroup(ctx, artifactGroupName)
	isGroupAdmin, _ := IsAPIUserIdAnAdminOfGroup(ctx, artifactGroupName)
	if !isMember && !isGroupAdmin {
		return nil
	}

	// Wow, still here, that means we need to get the private data.
	privateDataKey := o.ArtifactId + "-" + o.PrivateCustomFieldsHash
	privateDataBytes, err := ctx.GetStub().GetPrivateData("_implicit_org_"+orgName, privateDataKey)
	if err != nil {
		return err
	}
	if len(privateDataBytes) == 0 {
		return fmt.Errorf("populatePrivateData error: Artifact contains a reference to private data, but no private data found.")
	}
	err = json.Unmarshal(privateDataBytes, &o.PrivateCustomFields)
	if err != nil {
		return err
	}

	// Check the expected and actual hash, just in case something happened
	privateDataHash, err := ctx.GetStub().GetPrivateDataHash("_implicit_org_"+orgName, privateDataKey)
	if err != nil {
		return err
	}
	if fmt.Sprintf("%x", privateDataHash) != o.PrivateCustomFieldsHash {
		return fmt.Errorf("populatePrivateData error: Artifact contains a reference to private data, but the private data has the wrong hash, indicating corruption or tampering.")
	}

	return nil
}

// Returns a paginated list of all Artifacts in the public ledger.
//
// Note: this is a completely public function, so no private data will be returned here.
// The intent of this function is to produce a catalog for browsing, not for retrieving Artifact details.
// The more-detailed GetArtifactById must be used for details, including private data.
func GetAllArtifacts(ctx contractapi.TransactionContextInterface, pageSize int32, bookmark string) (*ArtifactListPage, error) {

	// We could set some defaults, but requring explicit values produces less surprises.
	if pageSize < 1 {
		return nil, fmt.Errorf("pageSize must be > 1")
	}

	startKey := "osc-is-artifact-"
	endKey := "osc-is-artifact." // byte('-') + 1
	resultsIterator, queryResponse, err := ctx.GetStub().GetStateByRangeWithPagination(startKey, endKey, pageSize, bookmark)
	if err != nil {
		return nil, err
	}
	defer resultsIterator.Close()

	var ArtifactsOut []*ArtifactListItem
	for resultsIterator.HasNext() {
		result, err := resultsIterator.Next()
		if err != nil {
			return nil, err
		}

		var t ArtifactListItem
		err = json.Unmarshal(result.Value, &t.Artifact)
		if err != nil {
			return nil, err
		}
		t.ArtifactId = result.Key
		t.PrivateCustomFields = make(map[string]interface{})
		cleanArtifactListItemForExternal(ctx, &t)

		ArtifactsOut = append(ArtifactsOut, &t)
	}

	return &ArtifactListPage{ArtifactsOut, queryResponse.Bookmark}, nil
}

// Get the previous versions of an Artifact
func GetArtifactHistoryById(ctx contractapi.TransactionContextInterface, artifactId string) ([]*ArtifactListItem, error) {
	var t ArtifactListItem
	var ArtifactsOut []*ArtifactListItem
	artifactIdLower := strings.ToLower(artifactId)

	// Check format of artifactId
	matched, err := regexp.MatchString("^osc-is-artifact-[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[a-f0-9]{4}-[a-f0-9]{12}$", artifactIdLower)
	if !matched || err != nil {
		return nil, fmt.Errorf("The supplied OSC-IS Artifact ID has an incorrect format. Expecting osc-is-artifact-<v4 uuid>")
	}

	// Get the history/versions
	artifactHistory, err := ctx.GetStub().GetHistoryForKey(artifactIdLower)
	if err != nil {
		return nil, err
	}

	for artifactHistory.HasNext() {
		rec, err := artifactHistory.Next()
		if err != nil {
			return nil, err
		}

		err = json.Unmarshal(rec.Value, &t.Artifact)
		if err != nil {
			return nil, fmt.Errorf("GetArtifactHistoryById error: %v", err)
		}
		t.ArtifactId = artifactIdLower
		t.PrivateCustomFields = make(map[string]interface{})

		populatePrivateData(ctx, &t)
		cleanArtifactListItemForExternal(ctx, &t)
		ArtifactsOut = append(ArtifactsOut, &t)
	}

	return ArtifactsOut, nil
}

// The user-accessible version of GetArtifactById below.
// Unlike the internal implementation, this function will perform additional checks against the
// apiUserId and retrieve private data if allowed by group membership semantics.
func (s *SmartContract) GetArtifactById(ctx contractapi.TransactionContextInterface, artifactId string) (*ArtifactListItem, error) {
	// Everyone can retrieve the public part of an artifact, so let's just do that now.
	var ao *Artifact
	ao, err := GetArtifactById(ctx, artifactId)
	if err != nil {
		return nil, fmt.Errorf("GetArtifactById error: %v", err)
	}
	if ao == nil {
		return nil, fmt.Errorf("GetArtifactById error: artifactId not found.")
	}

	var o ArtifactListItem
	o.Artifact = *ao
	o.PrivateCustomFields = make(map[string]interface{})
	o.ArtifactId = artifactId

	// Check if we should populate the private data.
	// Normally this is a public function, but private data has some extra requirements.

	// First, don't even bother if there's no private data.
	if o.PrivateCustomFieldsHash == "" {
		cleanArtifactListItemForExternal(ctx, &o)
		return &o, nil
	}

	err = populatePrivateData(ctx, &o)
	if err != nil {
		return nil, fmt.Errorf("GetArtifactById error: %v", err)
	}
	cleanArtifactListItemForExternal(ctx, &o)
	return &o, nil
}

// Return an Artifact with the given id.
// An artifact starts with "osc-is-artifact-[v4 uuid]", not a number.
func GetArtifactById(ctx contractapi.TransactionContextInterface, artifactId string) (*Artifact, error) {
	var t Artifact
	artifactIdLower := strings.ToLower(artifactId)

	// Check format of artifactId
	matched, err := regexp.MatchString("^osc-is-artifact-[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[a-f0-9]{4}-[a-f0-9]{12}$", artifactIdLower)
	if !matched || err != nil {
		return nil, fmt.Errorf("The supplied OSC-IS Artifact ID has an incorrect format. Expecting osc-is-artifact-<v4 uuid>")
	}

	// Attempt to retrieve the record.
	artifactBytes, err := ctx.GetStub().GetState(artifactIdLower)
	if err != nil {
		return nil, err
	}

	if artifactBytes == nil {
		// This is arguably not an error.
		//return nil, fmt.Errorf("No Artifact found with supplied OSC-IS Artifact ID")
		return nil, nil
	}

	err = json.Unmarshal(artifactBytes, &t)
	if err != nil {
		return nil, err
	}

	return &t, nil
}

func (s *SmartContract) NewArtifact(ctx contractapi.TransactionContextInterface, groupName string, schemaName string, artifactId string) (string, error) {
	return s.storeArtifact(ctx, true, groupName, schemaName, artifactId)
}

func (s *SmartContract) UpdateArtifact(ctx contractapi.TransactionContextInterface, groupName string, schemaName string, artifactId string) (string, error) {
	return s.storeArtifact(ctx, false, groupName, schemaName, artifactId)
}

// Store an Artifact, either a new one or an updated one.
// Set createNew to true when creating a new Artifact.
// Note: we do not expose this to the chaincode, it's meant to be called from a wrapper.
func (s *SmartContract) storeArtifact(ctx contractapi.TransactionContextInterface,
	createNew bool, groupName string, schemaName string, artifactId string) (string, error) {

	// I guess we need to do a permission check here anyway.
	// It's the same for create/update.
	hasOU, errOU := SubmittingIdentityHasOU(ctx, "Read-Write")
	if !hasOU {
		return "", errOU
	}

	// Only group members or group admins can create/update Artifacts
	isMember, _ := IsAPIUserIdMemberOfGroup(ctx, groupName)
	isGroupAdmin, _ := IsAPIUserIdAnAdminOfGroup(ctx, groupName)
	if !isMember {
		if !isGroupAdmin {
			return "", fmt.Errorf("APIUserId Is not a member or admin of group")
		}
	}

	// We'll need an MSP / org name.
	// it shouldn't be possible to clobber an artifact using a different org.
	orgName, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return "", err
	}

	// Resolve APIUserId from transient to uuid.
	apiUserUUID, err := getAPIUserUuidFromTransient(ctx)
	if err != nil {
		return "", err
	}

	// artifactId must fit a certain format
	artifactIdLower := strings.ToLower(artifactId)
	matched, err := regexp.MatchString("^osc-is-artifact-[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[a-f0-9]{4}-[a-f0-9]{12}$", artifactIdLower)
	if !matched || err != nil {
		return "", fmt.Errorf("The supplied OSC-IS Artifact ID has an incorrect format. Expecting osc-is-artifact-<v4 uuid>")
	}

	// Validate submission against schema.
	// The Artifact properties are passed in via the transient map.
	// Build an object from them.
	type transientJsonTemplate struct {
		APIUserId        string
		ArtifactJsonBody string
	}
	transientBytes, err := GetTransientMap(ctx)
	if err != nil {
		return "", fmt.Errorf("Error retrieving transient map: %v.", err)
	}

	var transientJson transientJsonTemplate
	err = json.Unmarshal([]byte(transientBytes), &transientJson)
	if err != nil {
		return "", fmt.Errorf("Error unmarshalling transient map: %v.\nIn: %s", err, string(transientBytes))
	}

	var artifactFields map[string]interface{}
	err = json.Unmarshal([]byte(transientJson.ArtifactJsonBody), &artifactFields)
	if err != nil {
		return "", fmt.Errorf("Error unmarshalling ArtifactJsonBody: %v\n", err)
	}

	// Now validate it
	validJson, schemaVersion, err := ValidJson(ctx, groupName, schemaName, artifactFields)
	if err != nil || !validJson {
		return "", fmt.Errorf("Invalid Asset JSON: %v.", err)
	}

	// Here's the new/update candidate.
	// Rather than gather all these fields from args and other parts of transient store,
	// we'll roll them up in a single json document, which makes validation a single schema check.

	var newArtifact Artifact

	// yank bits from the mandatory public fields
	mandatoryFields := artifactFields["mandatory_public_fields"].(map[string]interface{})
	newArtifact.Title = mandatoryFields["title"].(string)
	newArtifact.Description = mandatoryFields["description"].(string)
	newArtifact.SubmissionComment = mandatoryFields["submission_comment"].(string)
	newArtifact.SchemaName = schemaName
	newArtifact.SchemaVersion = string(schemaVersion)
	newArtifact.ContributorUUID = apiUserUUID
	newArtifact.EditorUUID = ""
	newArtifact.OrgName = orgName
	// set GroupUUID later, when we resolve groupName to a UUID.

	// public custom fields
	newArtifact.PublicCustomFields = artifactFields["public_fields"].(map[string]interface{})

	// private custom fields
	// let's try dropping the JSON subtree into the PDC and let HLF rollback if the transaction doesn't complete.
	// as it turns out, there's no history for PDCs, so we need to do something else, otherwise
	// the previous private data for older entries cannot be preserved.
	newArtifact.PrivateCustomFieldsHash = ""
	if len(artifactFields["private_fields"].(map[string]interface{})) > 0 {
		newPrivateHash, err := ArtifactPrivateHash(artifactFields["private_fields"].(map[string]interface{}))
		if err != nil {
			return "", fmt.Errorf("Error retrieving hash of saved Artifact private_fields: %v.", err)
		}
		newArtifact.PrivateCustomFieldsHash = newPrivateHash

		newPrivateBytes, err := json.Marshal(artifactFields["private_fields"].(map[string]interface{}))
		if err != nil {
			return "", fmt.Errorf("Error marshalling Artifact private_fields to JSON: %v.", err)
		}
		privateDataKey := artifactIdLower + "-" + newPrivateHash

		err = ctx.GetStub().PutPrivateData("_implicit_org_"+orgName, privateDataKey, newPrivateBytes)
		if err != nil {
			return "", fmt.Errorf("Error saving Artifact private_fields to PDC: %v.", err)
		}
	}

	// When submitting an update, we'll need to reference the existing Artifact.
	// This is especially important when an update is performed by a different person than the contributor.
	var existingArtifact *Artifact
	if !createNew {
		// Record the editor, who isn't always the contributor.
		// In any case, this is an indicator that the Artifact was modified.
		newArtifact.EditorUUID = apiUserUUID

		existingArtifact, err = GetArtifactById(ctx, artifactIdLower)
		if err != nil {
			return "", fmt.Errorf("Unable to search for Artifact to update: %s: %v.", artifactIdLower, err)
		}
		if existingArtifact == nil {
			return "", fmt.Errorf("Updating non-existent Artifact ID: %s.", artifactIdLower)
		}

		// Check if the current and previous org match.
		// It's unlikely, but possible for two orgs to end up with
		// a collision of apiUserUUIDs and/or groupUUIDs.
		if existingArtifact.OrgName != newArtifact.OrgName {
			return "", fmt.Errorf("The org name of the existing artifact does not match that of the updated version.")
		}

		// Check if the current and previous contributor match. Only
		// the "owner" and group admins can update an Artifact.
		// Do this check here before things get really serious.
		if existingArtifact.ContributorUUID != apiUserUUID {
			if !isGroupAdmin {
				return "", fmt.Errorf("The apiUserId is not the contibutor of the artifact being updated, nor is it a group admin.")
			}
			// Preserve the original contributor. We record that this Artifact was edited above.
			newArtifact.ContributorUUID = existingArtifact.ContributorUUID
		}
	}

	// Uniqueness check 1: Submitting identical content for the same (org, group, schema) is not allowed.
	newArtifactHash, err := ArtifactHash(newArtifact)
	if err != nil {
		return "", fmt.Errorf("Error creating sha256 digest of artifact: %v.", err)
	}

	// Use this weird approach to resolve the group name to uuid, and to keep key format consistent.
	// i.e. don't try to build a composite key here.
	newArtifactSearchKey := artifactToMapKey(ctx, orgName, groupName, schemaName, "", newArtifactHash)
	_, newArtifactSearchKeySubkeys, err := ctx.GetStub().SplitCompositeKey(newArtifactSearchKey)
	if err != nil {
		return "", fmt.Errorf("Error splitting composite key for new Artifact: %v.", err)
	}

	// duplicate check using atrifact hash composite key
	artifactHashKey := s.ArtifactHashToMapKey(ctx, orgName, groupName, schemaName, newArtifactHash)
	artifactHashValue, err := ctx.GetStub().GetState(artifactHashKey)
	if err != nil {
		return "", fmt.Errorf("Error retrieving aritfact hash value ledger.")
	}
	if artifactHashValue != nil {
		return "", fmt.Errorf("Duplicate submission detected.")
	}

	// Now that the groupName has been resolved, copy it here.
	newArtifact.GroupUUID = newArtifactSearchKeySubkeys[1]

	// Artifact needs to be JSON-encoded
	newArtifactBytes, err := json.Marshal(newArtifact)
	if err != nil {
		return "", fmt.Errorf("Error marshalling new Artifact to JSON: %v.", err)
	}

	// New and update are almost the same, except for some housekeeping and checks.

	////   NEW
	if createNew {
		// Artifact ID cannot exist when creating new.
		existingArtifact, err = GetArtifactById(ctx, artifactIdLower)
		if err != nil {
			return "", fmt.Errorf("Unable to determine if new Artifact ID is in use: %s: %v.", artifactIdLower, err)
		}
		if existingArtifact != nil {
			return "", fmt.Errorf("Creating new Artifact with Artifact ID that is in use: %s.", artifactIdLower)
		}
	} else {
		////   UPDATE
		// Artifact ID must exist when creating new. (check performed above)

		// Remove exising map / search composite key
		existingArtifactHash, err := ArtifactHash(*existingArtifact)
		if err != nil {
			return "", fmt.Errorf("Unable to create hash for exising artifact: %s: %v.", artifactIdLower, err)
		}
		existingArtifactSearchKey := artifactToMapKey(ctx, orgName, groupName, schemaName, artifactIdLower, existingArtifactHash)
		ctx.GetStub().DelState(existingArtifactSearchKey)
	}

	// Store the map / search composite key
	newArtifactSearchKey = artifactToMapKey(ctx, orgName, groupName, schemaName, artifactIdLower, newArtifactHash)
	ctx.GetStub().PutState(newArtifactSearchKey, []byte("1"))
	// Store the actual Artifact
	ctx.GetStub().PutState(artifactIdLower, newArtifactBytes)
	// Store atrifact hassh composite key
	ctx.GetStub().PutState(artifactHashKey, []byte("1"))
	return artifactIdLower, nil
}

/*


func (s *SmartContract) UpdateDataSample(ctx contractapi.TransactionContextInterface, Hash string, Comment string, Date string, APIUserID string, JsonFileContent string, SchemaID string) error {

	data, err := s.ReadAsset(ctx, Hash)
	if err != nil {
		return fmt.Errorf("the asset with Hash %s doesn't exist in world state. Please, verify the hash value", Hash)
	}

	SchemaExists, err := s.SchemaExists(ctx, SchemaID)

	if err != nil {
		return err
	}
	if !SchemaExists {
		return fmt.Errorf("the Schema with Id %s doesn't exists", SchemaID)
	}

	user, err := s.GetUser(ctx, APIUserID)
	if err != nil {
		return err
	}

	if user == nil {
		return fmt.Errorf("the submitting User is empty or doesn't exist")
	}

	if user.UUID != data.UUID {
		groups := user.Groups
		GIDAdmin := user.Projects[0] + "." + "Admin"
		if !stringArrayContains(groups, GIDAdmin) {
			return fmt.Errorf("the Updating User identity doesn't match submitting user's identity or User isn't admin")
		}
	}

	valid, err := ValidJson(ctx, JsonFileContent, SchemaID)
	if err != nil {
		return err
	}
	if !valid {
		return fmt.Errorf("the json file provided is not valid")
	} else {
		jsonFileContent, err := JsonReader(JsonFileContent)
		if err != nil {
			return err
		} else {
			updatedData := Data{
				OrgName:     data.OrgName,
				ProjectName: data.ProjectName,
				ContentHash: data.ContentHash,
				Comment:     Comment,
				Date:        Date,
				APIUserID:   data.APIUserID,
				UUID:        user.UUID,
				JsonContent: jsonFileContent,
			}

			assetJSON, err := json.Marshal(updatedData)
			if err != nil {
				return err
			}
			return ctx.GetStub().PutState(Hash, assetJSON)
		}
	}

}

func (s *SmartContract) ReadAsset(ctx contractapi.TransactionContextInterface, Hash string) (*Data, error) {
	assetJSON, err := ctx.GetStub().GetState(Hash)
	if err != nil {
		return nil, fmt.Errorf("failed to read from world state: %v", err)
	}
	if assetJSON == nil {
		return nil, fmt.Errorf("the asset %s does not exist", Hash)
	}

	var data Data
	err = json.Unmarshal(assetJSON, &data)
	if err != nil {
		return nil, err
	}

	return &data, nil
}


*/
