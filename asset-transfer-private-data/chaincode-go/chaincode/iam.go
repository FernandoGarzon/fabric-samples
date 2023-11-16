// iam.go - Identity and Access Management (IAM) related functions.
// These include groups and users.
//
// A user can be a member of one or more groups.
//
// A group is an arbitrary string [a-z90-9].  Extra permissions
// in a group (e.g. edit anyone's artifacts) are denoted by membership
// in another group with the same name, ending in ".<ROLE>", where
// <ROLE> is one of ADMINS. More to be added when needed.
//
// A group ties together a set of users and artifacts.
//
// As groups and users may need to be renamed while preserving their
// semantics, we map each user and group to a persistent ID, and use that ID
// internally when referencing.
package chaincode

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// Type User describes the attributes of a person using the HLfabric to perform transactions.
// This is NOT the HLF client, but rather the people multiplexed behind the HLF client. (e.g. portal accounts)
// Note: these are stored keyed by UUID, so we don't need to store the UUID in the value.
// Note 2: the "org" is an MSP, and  that's in the key too.

type User struct {
	APIUserId string         `json:"APIUserId"` // An email address would be the most common form if this attribute. Generally, it's provided by the Orgs portal or OSC-IS portal.
	Groups    map[string]int `json:"Groups"`    // A MAP of group UUIDs the User is part of. See Group struct for more info.
	// The value doesn't matter, only the key.
}

// Note that in effect, users list the groups they are in, rather than groups listing their users.
// This is in part due to the fact that we'll be handling a request with a specific user
// more often than trying to enumerate all users in a group.
//
// There are situations where additional permissions are needed in a group, for that we use another
// group ending in ".<ROLE>", e.g. G.ADMINS.
type Group struct {
	GroupName string `json:"GroupName"` // A human-friendly name for this group.
}

// Returned by ListUsers, to HLF chaincode client.
type UserGroupInfo struct {
	APIUserId string
	Groups    []string
}

/**************************************
 * User methods                       *
 **************************************/

// Pass an APIUserId, get back a UUID
// This actually looks at the PDC, so don't call it until after the mapping has been
// added.
func APIUserIdToUUID(ctx contractapi.TransactionContextInterface, MSP string, APIUserId string) (string, error) {
	// Derive the key to pull from PDC
	apiuserkey, err := apiUserToKey(MSP, APIUserId)
	if err != nil {
		return "", fmt.Errorf("Failed to derive apiuserkey: %v.", err)
	}

	// Do the lookup
	uuidbytes, err := ctx.GetStub().GetPrivateData("_implicit_org_"+MSP, apiuserkey)
	if err != nil {
		return "", fmt.Errorf("Failed to look up APIUserId: %v.", err)
	}

	// Done?
	return string(uuidbytes), nil
}

// Pass a UUID, get back an APIUserId
// This actually looks at the PDC, so don't call it until after the mapping has been
// added.
func UUIDToAPIUserId(ctx contractapi.TransactionContextInterface, uuid string) (string, error) {
	// Most callers won't already have gotten the MSP, so just do it here.
	MSP, err := shim.GetMSPID()
	if err != nil {
		return "", err
	}
	PDC := "_implicit_org_" + MSP

	useruuidkey, err := userUuidToKey(MSP, uuid)
	if err != nil {
		return "", fmt.Errorf("Failed to convert UUID to key: %v.", err)
	}
	res, err := ctx.GetStub().GetPrivateData(PDC, useruuidkey)
	if err != nil {
		return "", fmt.Errorf("Failed to search for UUID: %v.", err)
	}

	var userInfo User

	err = json.Unmarshal(res, &userInfo)
	if err != nil {
		return "", fmt.Errorf("Failed to unmarshal userInfo JSON: %v.", err)
	}

	return userInfo.APIUserId, nil
}

// Return a User info object given an APIUserId.
// Internal use only, not to be called by HLF clients.
func getUser(ctx contractapi.TransactionContextInterface, MSP string, APIUserId string) (*User, error) {
	PDC := "_implicit_org_" + MSP

	// User info is keyed by UUID, but we have APIUserId.
	// Query the APIUserId to UUID mapping first.
	apiuserUUID, err := APIUserIdToUUID(ctx, MSP, APIUserId)
	if err != nil {
		return nil, err
	}

	// Now we can get the User info object
	apiuserUUIDKey, err := userUuidToKey(MSP, apiuserUUID)
	if err != nil {
		return nil, fmt.Errorf("Failed to convert User UUID to key: %v.", err)
	}
	res, err := ctx.GetStub().GetPrivateData(PDC, apiuserUUIDKey)
	if err != nil {
		return nil, fmt.Errorf("Failed to search for User UUID: %v.", err)
	}
	if res == nil {
		return nil, fmt.Errorf("Failed to retrieve User info: %v for %s.", err, APIUserId)
	}

	// Prepare the struct to be filled and returned
	var userInfo User
	err = json.Unmarshal(res, &userInfo)
	if err != nil {
		return nil, fmt.Errorf("Failed to unmarshal User info: %v.", err)
	}

	return &userInfo, nil
}

// Store a User info object given an APIUserId.
// Internal user only, not to be called by HLF clients.
func putUser(ctx contractapi.TransactionContextInterface, MSP string, APIUserId string, UserInfo *User) error {
	PDC := "_implicit_org_" + MSP

	// User info is keyed by UUID, but we have APIUserId.
	// Query the APIUserId to UUID mapping first.
	apiuserUUID, err := APIUserIdToUUID(ctx, MSP, APIUserId)
	if err != nil {
		return err
	}

	apiuserUUIDKey, err := userUuidToKey(MSP, apiuserUUID)
	if err != nil {
		return fmt.Errorf("Failed to convert User UUID to key: %v.", err)
	}

	// Store in PDC
	userInfoBytes, err := json.Marshal(UserInfo)
	if err != nil {
		return fmt.Errorf("Failed to marshal user into JSON: %v", err)
	}
	err = ctx.GetStub().PutPrivateData(PDC, apiuserUUIDKey, userInfoBytes)
	if err != nil {
		return fmt.Errorf("Failed to put user into private data collection: %v", err)
	}

	return nil
}

// We try to pass APIUserId in the transient map as it may be secret.
// e.g. An email address.
// This happens enough that we should make it in a function.
func getAPIUserIdFromTransient(ctx contractapi.TransactionContextInterface) (string, error) {
	transientBytes, err := GetTransientMap(ctx)
	if err != nil {
		return "", fmt.Errorf("Error getting transient: %v.", err)
	}

	type transientJsonTemplate struct {
		APIUserId string
	}
	var transientJson transientJsonTemplate
	err = json.Unmarshal(transientBytes, &transientJson)
	if err != nil {
		return "", fmt.Errorf("Failed to unmarshal JSON: %v.", err)
	}

	return transientJson.APIUserId, nil
}

// Sometimes we need the UUID instead, such as when creating records.
// Don't use the APIUserID in records as that may change over time.
func getAPIUserUuidFromTransient(ctx contractapi.TransactionContextInterface) (string, error) {
	MSP, err := shim.GetMSPID()
	if err != nil {
		return "", err
	}

	// Get the apiuserid from transient
	APIUserId, err := getAPIUserIdFromTransient(ctx)
	if err != nil {
		return "", err
	}

	// Map to UUID
	APIUserUuid, err := APIUserIdToUUID(ctx, MSP, APIUserId)
	if err != nil {
		return "", err
	}

	return APIUserUuid, nil
}

// Pass APIUserID as argument in transient map
// Subscribe a new user to the Implicit PDC. APIUserId, ProjectName and GroupName need to be passed as parameters in transient map
// Create a new user.
// This requires a uuid and the apiuserid. As we might want to keep apiuserid private, it is
// provided via the transient map. We want to keep uuid on the ledger so its history can be retrieved.
func (s *SmartContract) NewUser(ctx contractapi.TransactionContextInterface, uuid string) error {
	// This operation requires an HLF identity with "OU=IAM Admin".
	hasOU, errOU := SubmittingIdentityHasOU(ctx, "IAM Admin")
	if !hasOU {
		return errOU
	}

	apiuserid, err := getAPIUserIdFromTransient(ctx)
	if err != nil {
		return err
	}

	// We'll need the MSP a lot.
	MSP, err := shim.GetMSPID()
	if err != nil {
		return fmt.Errorf("Failed to get MSPID: %v.", err)
	}
	PDC := "_implicit_org_" + MSP

	// Check 1: UUID doesn't already exist.
	useruuidkey, err := userUuidToKey(MSP, uuid)
	if err != nil {
		return fmt.Errorf("Failed to convert UUID to key: %v.", err)
	}
	res, err := ctx.GetStub().GetPrivateData(PDC, useruuidkey)
	if err != nil {
		return fmt.Errorf("Failed to search for existing UUID: %v.", err)
	}
	if res != nil {
		return fmt.Errorf("UUID is already in use.")
	}

	// Check 2: apiuserid doesn't already exist.
	apiuserkey, err := apiUserToKey(MSP, apiuserid)
	if err != nil {
		return fmt.Errorf("Failed to convert apiuserid to key: %v.", err)
	}
	res, err = ctx.GetStub().GetPrivateData(PDC, apiuserkey)
	if err != nil {
		return fmt.Errorf("Failed to search for existing apiuserid: %v.", err)
	}
	if res != nil {
		return fmt.Errorf("APIUserId is already in use.")
	}

	// So.. how do we store mapping? It's in PDC, however a
	// transaction that does a range/partial composite query and a put
	// will throw an error. (see https://hyperledger-fabric.readthedocs.io/en/latest/private-data-arch.html querying private data, limitations)

	var newUser User
	newUser.Groups = make(map[string]int)
	newUser.APIUserId = apiuserid

	// We save TWO entries without using a composite key or map to prevent transaction failure due to contention.
	// Also as noted above, a range or partial composite key query cannot be used in the same transaction as a "put".
	// Note: it's up to the caller to not reuse UUIDs.

	// Save apiuser -> uuid to PDC.
	err = ctx.GetStub().PutPrivateData(PDC, apiuserkey, []byte(uuid))
	if err != nil {
		return fmt.Errorf("Failed to put new user into private data collection: %v", err)
	}

	// Save the new user to PDC.
	// It turns out that a PutPrivateData call doesn't actually take effect until after
	// the transaction is committed. It's not like an SQL transaction where you can see
	// the proposed changes... so, we can't use putUser() here.
	userInfoBytes, err := json.Marshal(newUser)
	if err != nil {
		return fmt.Errorf("Failed to marshal user into JSON: %v", err)
	}
	err = ctx.GetStub().PutPrivateData(PDC, useruuidkey, userInfoBytes)
	if err != nil {
		return fmt.Errorf("Failed to put user into private data collection: %v", err)
	}

	return nil
}

// Return a list of users, including their group memberships.
// Note: This function uses a range query, so do not call it in the same transaction as one that
// changes the ledger or PDC.
func (s *SmartContract) ListUsers(ctx contractapi.TransactionContextInterface) ([]UserGroupInfo, error) {
	// This operation requires an HLF identity with "OU=IAM Admin".
	hasOU, errOU := SubmittingIdentityHasOU(ctx, "IAM Admin")
	if !hasOU {
		return nil, errOU
	}

	// We'll need the MSP a lot.
	MSP, err := shim.GetMSPID()
	if err != nil {
		return nil, fmt.Errorf("Failed to get MSPID: %v.", err)
	}
	PDC := "_implicit_org_" + MSP

	// Range query start and end is by lexicographical sort
	// see common.go, userUuidToKey() to see where this string came from
	// The "/" is "." + 1
	keyStart := "iam.uuid_to_user." + strings.ToLower(MSP) + "."
	keyEnd := "iam.uuid_to_user." + strings.ToLower(MSP) + "/"
	resultsIterator, err := ctx.GetStub().GetPrivateDataByRange(PDC, keyStart, keyEnd)
	if err != nil {
		return nil, err
	}
	defer resultsIterator.Close()

	var output []UserGroupInfo
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, err
		}

		var iterItem User
		err = json.Unmarshal(queryResponse.Value, &iterItem)
		if err != nil {
			return nil, fmt.Errorf("Unable to unmarshal uuid_to_user: %v", err)
		}

		var outItem UserGroupInfo
		outItem.APIUserId = iterItem.APIUserId

		outItem.Groups = []string{}
		if len(iterItem.Groups) > 0 {
			for groupuuid, _ := range iterItem.Groups {
				groupName, err := UUIDToGroupName(ctx, MSP, groupuuid)
				if err != nil {
					return nil, err
				}
				outItem.Groups = append(outItem.Groups, groupName)
			}
		}
		output = append(output, outItem)
	}

	return output, nil
}

/**************************************
 * Group methods                      *
 **************************************/

// Pass a GroupName, get back a UUID
// This actually looks at the PDC, so don't call it until after the mapping has been
// added.
func GroupNameToUUID(ctx contractapi.TransactionContextInterface, MSP string, GroupName string) (string, error) {
	// Derive the key to pull from PDC
	groupNameKey, err := groupNameToKey(MSP, GroupName)
	if err != nil {
		return "", fmt.Errorf("Failed to derive GroupName key: %v.", err)
	}

	// Do the lookup
	uuidbytes, err := ctx.GetStub().GetPrivateData("_implicit_org_"+MSP, groupNameKey)
	if err != nil {
		return "", fmt.Errorf("Failed to look up GroupName: %v.", err)
	}

	// Done?
	return string(uuidbytes), nil
}

// Pass a UUID, get back a GroupName
// This actually looks at the PDC, so don't call it until after the mapping has been
// added.
func UUIDToGroupName(ctx contractapi.TransactionContextInterface, MSP string, UUID string) (string, error) {
	// Derive the key to pull from PDC
	groupUUIDKey, err := groupUuidToKey(MSP, UUID)

	if err != nil {
		return "", fmt.Errorf("Failed to derive GroupUUID key: %v.", err)
	}

	// Do the lookup
	groupInfoBytes, err := ctx.GetStub().GetPrivateData("_implicit_org_"+MSP, groupUUIDKey)
	if err != nil {
		return "", fmt.Errorf("Failed to look up GroupUUID: %v.", err)
	}

	var groupInfo Group

	err = json.Unmarshal(groupInfoBytes, &groupInfo)
	if err != nil {
		return "", fmt.Errorf("Failed to unmarshal GroupInfo JSON: %v.", err)
	}

	return groupInfo.GroupName, nil
}

// Create a new group.
// Pass in a uuid and the name of the group.
// Neither of these are secrets, so we don't need the transient map.
func (s *SmartContract) NewGroup(ctx contractapi.TransactionContextInterface, UUID string, GroupName string) error {

	// This operation requires an HLF identity with "OU=IAM Admin".
	hasOU, errOU := SubmittingIdentityHasOU(ctx, "IAM Admin")
	if !hasOU {
		return errOU
	}

	// We'll need the MSP a lot.
	MSP, err := shim.GetMSPID()
	if err != nil {
		return fmt.Errorf("Failed to get MSPID: %v.", err)
	}
	PDC := "_implicit_org_" + MSP

	// Check 1: UUID doesn't already exist.
	groupuuidkey, err := groupUuidToKey(MSP, UUID)
	if err != nil {
		return fmt.Errorf("Failed to convert UUID to key: %v.", err)
	}
	res, err := ctx.GetStub().GetPrivateData(PDC, groupuuidkey)
	if err != nil {
		return fmt.Errorf("Failed to search for existing UUID: %v.", err)
	}
	if res != nil {
		return fmt.Errorf("UUID is already in use.")
	}

	// Check 2: GroupName doesn't already exist.
	groupnamekey, err := groupNameToKey(MSP, GroupName)
	if err != nil {
		return fmt.Errorf("Failed to convert GroupName to key: %v.", err)
	}
	res, err = ctx.GetStub().GetPrivateData(PDC, groupnamekey)
	if err != nil {
		return fmt.Errorf("Failed to search for existing GroupName: %v.", err)
	}
	if res != nil {
		return fmt.Errorf("GroupName is already in use.")
	}

	// The same constraints for users apply here.
	// We'll have to save TWO entries, the UUID-> group data, and group name -> UUID.
	var newGroup Group
	newGroup.GroupName = GroupName

	// Save the new group to PDC
	newGroupBytes, err := json.Marshal(newGroup)
	if err != nil {
		return fmt.Errorf("failed to marshal new group into JSON: %v", err)
	}
	err = ctx.GetStub().PutPrivateData(PDC, groupuuidkey, newGroupBytes)
	if err != nil {
		return fmt.Errorf("failed to put new group into private data collection: %v", err)
	}
	// Save GroupName -> uuid to PDC.
	err = ctx.GetStub().PutPrivateData(PDC, groupnamekey, []byte(UUID))
	if err != nil {
		return fmt.Errorf("failed to put new group into private data collection: %v", err)
	}

	return nil
}

// Assign a groupname to a given apiuser.
// The apiuser might be considered private, so pass that in on the transient map.
func (s *SmartContract) AssignGroup(ctx contractapi.TransactionContextInterface, GroupName string) error {
	// This operation requires an HLF identity with "OU=IAM Admin".
	hasOU, errOU := SubmittingIdentityHasOU(ctx, "IAM Admin")
	if !hasOU {
		return errOU
	}

	apiuserid, err := getAPIUserIdFromTransient(ctx)
	if err != nil {
		return err
	}

	// We'll need the MSP a lot.
	MSP, err := shim.GetMSPID()
	if err != nil {
		return fmt.Errorf("Failed to get MSPID: %v.", err)
	}
	PDC := "_implicit_org_" + MSP

	// Retrieve the group UUID so we can set it on the user
	groupnameKey, err := groupNameToKey(MSP, GroupName)
	if err != nil {
		return fmt.Errorf("Failed to convert GroupName to key: %v.", err)
	}
	res, err := ctx.GetStub().GetPrivateData(PDC, groupnameKey)
	if err != nil {
		return fmt.Errorf("Failed to search for GroupName: %v.", err)
	}
	if res == nil {
		return fmt.Errorf("GroupName does not exist.")
	}
	groupUUID := string(res)

	// Retrieve the User info to edit
	userInfo, err := getUser(ctx, MSP, apiuserid)
	if err != nil {
		return fmt.Errorf("Failed to retrieve user info: %v.", err)
	}

	// Make the requested changes
	userInfo.Groups[groupUUID] = 1

	// Write it back out.
	err = putUser(ctx, MSP, apiuserid, userInfo)
	if err != nil {
		return fmt.Errorf("Failed to store user info: %v.", err)
	}

	return nil
}

// Unassign a groupname to a given apiuser.
// The apiuser might be considered private, so pass that in on the transient map.
func (s *SmartContract) UnassignGroup(ctx contractapi.TransactionContextInterface, GroupName string) error {
	// This operation requires an HLF identity with "OU=IAM Admin".
	hasOU, errOU := SubmittingIdentityHasOU(ctx, "IAM Admin")
	if !hasOU {
		return errOU
	}

	apiuserid, err := getAPIUserIdFromTransient(ctx)
	if err != nil {
		return err
	}

	// We'll need the MSP a lot.
	MSP, err := shim.GetMSPID()
	if err != nil {
		return fmt.Errorf("Failed to get MSPID: %v.", err)
	}
	PDC := "_implicit_org_" + MSP

	// Retrieve the group UUID so we can set it on the user
	groupnameKey, err := groupNameToKey(MSP, GroupName)
	if err != nil {
		return fmt.Errorf("Failed to convert GroupName to key: %v.", err)
	}
	res, err := ctx.GetStub().GetPrivateData(PDC, groupnameKey)
	if err != nil {
		return fmt.Errorf("Failed to search for GroupName: %v.", err)
	}
	if res == nil {
		return fmt.Errorf("GroupName does not exist.")
	}
	groupUUID := string(res)

	// Retrieve the User info to edit
	userInfo, err := getUser(ctx, MSP, apiuserid)
	if err != nil {
		return fmt.Errorf("Failed to retrieve user info: %v.", err)
	}

	// Make the requested changes
	delete(userInfo.Groups, groupUUID)

	// Write it back out.
	err = putUser(ctx, MSP, apiuserid, userInfo)
	if err != nil {
		return fmt.Errorf("Failed to store user info: %v.", err)
	}

	return nil
}

// Return a JSON array of all groups
// Note: as this uses a range query, do not call this function from another one
// that will make changes to the ledger or PDC.
func (s *SmartContract) ListGroups(ctx contractapi.TransactionContextInterface) ([]string, error) {
	// This operation requires an HLF identity with "OU=IAM Admin".
	hasOU, errOU := SubmittingIdentityHasOU(ctx, "IAM Admin")
	if !hasOU {
		return nil, errOU
	}

	// We'll need the MSP a lot.
	MSP, err := shim.GetMSPID()
	if err != nil {
		return nil, fmt.Errorf("Failed to get MSPID: %v.", err)
	}
	PDC := "_implicit_org_" + MSP

	// Range query start and end is by lexicographical sort
	// see common.go, groupUuidToKey() to see where this string came from
	// The "/" is "." + 1
	keyStart := "iam.uuid_to_group." + strings.ToLower(MSP) + "."
	keyEnd := "iam.uuid_to_group." + strings.ToLower(MSP) + "/"
	resultsIterator, err := ctx.GetStub().GetPrivateDataByRange(PDC, keyStart, keyEnd)
	if err != nil {
		return nil, err
	}
	defer resultsIterator.Close()

	var output []string
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, err
		}

		var iterItem map[string]interface{}
		err = json.Unmarshal(queryResponse.Value, &iterItem)
		if err != nil {
			return nil, err
		}

		// Every result must have a GroupName, because that's what NewGroup did.
		_, ok := iterItem["GroupName"]
		if !ok {
			return nil, fmt.Errorf("Group info struct is missing a group name. Possible corruption.")
		}

		output = append(output, iterItem["GroupName"].(string))
	}

	return output, nil
}

/**************************************
 * Authz methods                      *
 **************************************/

// Some operations require "group.ADMINS" membership. We check it enough that
// it should be its own function.
// Note: APIUserIds are sort-of private, so we always pass those in via transient.
// Returns a bool, true if admin of groupName; and error with more detail if any
func IsAPIUserIdAnAdminOfGroup(ctx contractapi.TransactionContextInterface, groupName string) (bool, error) {
	return IsAPIUserIdMemberOfGroup(ctx, groupName+".ADMINS")
}

func IsAPIUserIdMemberOfGroup(ctx contractapi.TransactionContextInterface, groupName string) (bool, error) {
	MSP, err := shim.GetMSPID()
	if err != nil {
		return false, err
	}

	// Get the apiuserid from transient
	APIUserId, err := getAPIUserIdFromTransient(ctx)
	if err != nil {
		return false, err
	}

	// Get the group UUID
	PDC := "_implicit_org_" + MSP
	groupnameKey, err := groupNameToKey(MSP, groupName)
	if err != nil {
		return false, fmt.Errorf("Failed to convert groupName to key: %v.", err)
	}
	res, err := ctx.GetStub().GetPrivateData(PDC, groupnameKey)
	if err != nil {
		return false, fmt.Errorf("Failed to search for groupName: %v.", err)
	}
	if res == nil {
		return false, fmt.Errorf("GroupName %s does not exist.", groupName)
	}
	groupUUID := string(res)

	// Now get the user info
	userInfo, err := getUser(ctx, MSP, APIUserId)
	if err != nil {
		return false, err
	}

	// Hopefully the group UUID is present in userinfo...
	if userInfo.Groups[groupUUID] == 1 {
		return true, nil
	}

	return false, nil
}
